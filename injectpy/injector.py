import os
import logging
import ctypes
import ctypes.wintypes as wintypes
from .results import InjectionResult
from .winapi import WinAPI, kernel32, PROCESS_ALL_ACCESS, MEM_COMMIT, PAGE_READWRITE
from .process_utils import ProcessUtils



class Injector:
    def __init__(self, verbose: bool = False, logger_instance: logging.Logger | None = None):
        self.verbose = verbose
        if logger_instance:
            self.logger = logger_instance
        else:
            self.logger = logging.getLogger("injectpy")
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter("[%(levelname)s] %(message)s")
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)


    def _log(self, msg: str):
        if self.verbose:
            self.logger.info(msg)


    def _error(self, msg: str):
        err = ctypes.get_last_error()
        if err != 0:
            error_msg = ctypes.FormatError(err)
            self.logger.error(f"{msg} (WinError {err}: {error_msg})")
        else:
            self.logger.error(msg)


    def _check_architecture(self, h_process) -> tuple[bool, str, str]:
        is_wow64_self = wintypes.BOOL()
        is_wow64_target = wintypes.BOOL()
        WinAPI.IsWow64Process(kernel32._handle, ctypes.byref(is_wow64_self))
        WinAPI.IsWow64Process(h_process, ctypes.byref(is_wow64_target))
        injector_arch = "x64" if ctypes.sizeof(ctypes.c_void_p) == 8 else "x86"
        target_arch = "x64" if not is_wow64_target.value else "x86"
        match = is_wow64_self.value == is_wow64_target.value
        return match, injector_arch, target_arch


    def inject(self, target: int | str, file_path: str, index: int = 0, timeout: int = 5000) -> InjectionResult:
        """
        Inject into a process by PID or process name.

        :param target: PID (int) or process name (str)
        :param file_path: Path to file
        :param index: Which process to use if multiple match names
        :param timeout: Wait time in ms (default 5000) - 0xFFFFFFFF for INFINITE
        """
        file_path = os.path.abspath(file_path)

        if not os.path.isfile(file_path):
            self.logger.error(f"File not found: {file_path}")
            return InjectionResult.FILE_NOT_FOUND

        pid = self._resolve_pid(target, index)
        if not pid:
            return InjectionResult.PROCESS_NOT_FOUND

        file_bytes = file_path.encode("ascii") + b"\x00"
        self._log(f"Injecting {file_path} into PID {pid}")

        h_process = WinAPI.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            self._error("Could not open process")
            return InjectionResult.ACCESS_DENIED

        arch_match, injector_arch, target_arch = self._check_architecture(h_process)
        if not arch_match:
            self.logger.error(f"Architecture mismatch: Injector is {injector_arch}, target process is {target_arch}")
            WinAPI.CloseHandle(h_process)
            return InjectionResult.ARCH_MISMATCH

        mem_addr = WinAPI.VirtualAllocEx(h_process, None, len(file_bytes), MEM_COMMIT, PAGE_READWRITE)
        if not mem_addr:
            self._error("Could not allocate memory in target process")
            WinAPI.CloseHandle(h_process)
            return InjectionResult.MEMORY_ALLOC_FAILED

        written = ctypes.c_size_t(0)
        if not WinAPI.WriteProcessMemory(h_process, mem_addr, file_bytes, len(file_bytes), ctypes.byref(written)):
            self._error("Could not write file to process memory")
            WinAPI.CloseHandle(h_process)
            return InjectionResult.WRITE_FAILED

        h_kernel32 = WinAPI.GetModuleHandleA(b"kernel32.dll")
        loadlib_addr = WinAPI.GetProcAddress(h_kernel32, b"LoadLibraryA")
        if not loadlib_addr:
            self._error("Could not resolve LoadLibraryA")
            WinAPI.CloseHandle(h_process)
            return InjectionResult.LOADLIBRARY_NOT_FOUND

        thread_id = wintypes.DWORD(0)
        h_thread = WinAPI.CreateRemoteThread(h_process, None, 0, loadlib_addr, mem_addr, 0, ctypes.byref(thread_id))
        if not h_thread:
            self._error("Could not create remote thread")
            WinAPI.CloseHandle(h_process)
            return InjectionResult.THREAD_CREATION_FAILED

        # Wait for completion
        wait_result = WinAPI.WaitForSingleObject(h_thread, timeout)
        if wait_result == 0x102:  # WAIT_TIMEOUT
            self.logger.error("Injection thread timed out")
            WinAPI.CloseHandle(h_thread)
            WinAPI.CloseHandle(h_process)
            return InjectionResult.TIMEOUT

        WinAPI.CloseHandle(h_thread)
        WinAPI.CloseHandle(h_process)
        return InjectionResult.SUCCESS


    def _resolve_pid(self, target: int | str, index: int = 0) -> int | None:
        if isinstance(target, int):
            return target
        elif isinstance(target, str):
            pids = ProcessUtils.get_pids_by_name(target)
            if not pids:
                self.logger.error(f"Process '{target}' not found")
                return None
            if index >= len(pids):
                self.logger.error(f"Process '{target}' found {len(pids)} matches, but index {index} was requested")
                return None
            if len(pids) > 1:
                self.logger.warning(f"Multiple processes found for '{target}', using index {index} (PID {pids[index]})")
            return pids[index]
        else:
            self.logger.error("Target must be PID (int) or process name (str)")
            return None