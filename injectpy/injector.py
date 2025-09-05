import os
import logging
import ctypes
import ctypes.wintypes as wintypes
from injectpy.results import InjectionResult
from injectpy.winapi import WinAPI, kernel32, PROCESS_MINIMAL_ACCESS, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE
from injectpy.process_utils import ProcessUtils



class Injector:
    def __init__(self, verbose: bool = False, logger_instance: logging.Logger | None = None):
        self.verbose = verbose
        self.logger = logger_instance or self._setup_logger()


    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("injectpy")
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger


    def _log(self, msg: str):
        if self.verbose:
            self.logger.info(msg)


    def _warning(self, msg: str):
        if self.verbose:
            self.logger.warning(msg)


    def _error(self, msg: str):
        if self.verbose:
            err = ctypes.get_last_error()
            if err != 0:
                error_msg = ctypes.FormatError(err)
                self.logger.error(f"{msg} (Last WinError {err}: {error_msg})")
            else:
                self.logger.error(msg)


    def _create_and_wait_for_remote_thread(self, h_process: int, function_addr: int, parameter: int, timeout: int) -> tuple[InjectionResult, int]:
        thread_id = wintypes.DWORD(0)
        h_thread = WinAPI.CreateRemoteThread(h_process, None, 0, function_addr, parameter, 0, ctypes.byref(thread_id))
        if not h_thread:
            self._error("Could not create remote thread")
            return InjectionResult.THREAD_CREATION_FAILED, 0

        try:
            wait_result = WinAPI.WaitForSingleObject(h_thread, timeout)
            if wait_result == 0x102:
                self._error("Thread timed out")
                return InjectionResult.TIMEOUT, 0

            exit_code = wintypes.DWORD(0)
            if not WinAPI.GetExitCodeThread(h_thread, ctypes.byref(exit_code)):
                self._error("Could not get thread exit code")
                return InjectionResult.THREAD_EXIT_FAILED, 0

            return InjectionResult.SUCCESS, exit_code.value
        finally:
            WinAPI.CloseHandle(h_thread)


    def inject(self, target: int | str, file_path: str, index: int = 0, timeout: int = 5000, force: bool = False) -> InjectionResult:
        """
        Inject into a process by PID or process name.

        :param target: PID (int) or process name (str)
        :param file_path: Path to file
        :param index: Which process to use if multiple match names
        :param timeout: Wait time in ms (default 5000) - 0xFFFFFFFF for INFINITE
        :param force: Force injection by ejecting the module if it already lives in the process and injecting it again after
        """
        if not os.path.isfile(file_path):
            self._error(f"File not found: {file_path}")
            return InjectionResult.FILE_NOT_FOUND

        pid = self._resolve_pid(target, index)
        if not pid:
            return InjectionResult.PROCESS_NOT_FOUND

        already_loaded = ProcessUtils.get_module_base(pid, file_path)
        if already_loaded:
            if not force:
                self._error(f"Module already loaded in PID {pid}. Consider ejecting first.")
                return InjectionResult.ALREADY_LOADED
            self._log(f"Force enabled: ejecting module before reinjecting.")
            eject_result = self.eject(pid, file_path, timeout=timeout)
            if eject_result != InjectionResult.SUCCESS:
                self._error(f"Force eject failed: {eject_result.name}")
                return eject_result

        wide_bytes = (file_path + "\x00").encode("utf-16le")
        self._log(f"Injecting {file_path} into PID {pid}")

        h_process = WinAPI.OpenProcess(PROCESS_MINIMAL_ACCESS, False, pid)
        if not h_process:
            self._error("Could not open process")
            return InjectionResult.ACCESS_DENIED

        try:
            mem_addr = WinAPI.VirtualAllocEx(h_process, None, len(wide_bytes), MEM_COMMIT, PAGE_READWRITE)
            if not mem_addr:
                self._error("Could not allocate memory in target process")
                return InjectionResult.MEMORY_ALLOC_FAILED

            try:
                written = ctypes.c_size_t(0)
                if not WinAPI.WriteProcessMemory(h_process, mem_addr, wide_bytes, len(wide_bytes), ctypes.byref(written)):
                    self._error("Could not write file to process memory")
                    return InjectionResult.WRITE_FAILED

                if written.value != len(wide_bytes):
                    self._error(f"Partial write: {written.value}/{len(wide_bytes)} bytes written")
                    return InjectionResult.WRITE_FAILED

                h_kernel32 = WinAPI.GetModuleHandleW("kernel32.dll")
                loadlibw_addr = WinAPI.GetProcAddress(h_kernel32, b"LoadLibraryW")
                if not loadlibw_addr:
                    self._error("Could not resolve LoadLibraryW")
                    return InjectionResult.LOADLIBRARY_NOT_FOUND

                result, exit_code = self._create_and_wait_for_remote_thread(h_process, loadlibw_addr, mem_addr, timeout)
                if result != InjectionResult.SUCCESS:
                    return result

                if exit_code == 0:
                    self._error("Remote LoadLibraryW returned NULL")
                    return InjectionResult.REMOTE_LOAD_FAILED

                if not ProcessUtils.get_module_base(pid, file_path):
                    self._error("Module verification failed after LoadLibraryW")
                    return InjectionResult.VERIFY_FAILED

                return InjectionResult.SUCCESS

            finally:
                WinAPI.VirtualFreeEx(h_process, mem_addr, 0, MEM_RELEASE)
        finally:
            WinAPI.CloseHandle(h_process)


    def eject(self, target: int | str, module: str, index: int = 0, timeout: int = 5000) -> InjectionResult:
        """
        Ejects module from given process via PID or process name.

        :param target: PID (int) or process name (str)
        :param module: Either path to module or module name
        :param index: Which process to use if multiple match names
        :param timeout: Wait time in ms (default 5000) - 0xFFFFFFFF for INFINITE
        """
        dll_name = os.path.basename(module)
        pid = self._resolve_pid(target, index)
        if not pid:
            return InjectionResult.PROCESS_NOT_FOUND

        h_process = WinAPI.OpenProcess(PROCESS_MINIMAL_ACCESS, False, pid)
        if not h_process:
            self._error("Could not open process for eject")
            return InjectionResult.ACCESS_DENIED

        try:
            h_module = ProcessUtils.get_module_base(pid, dll_name)
            if not h_module:
                self._error(f"Module '{dll_name}' not found in PID {pid}")
                return InjectionResult.MODULE_NOT_FOUND

            h_kernel32 = WinAPI.GetModuleHandleW("kernel32.dll")
            free_addr = WinAPI.GetProcAddress(h_kernel32, b"FreeLibrary")
            if not free_addr:
                self._error("Could not resolve FreeLibrary")
                return InjectionResult.LOADLIBRARY_NOT_FOUND

            result, _ = self._create_and_wait_for_remote_thread(h_process, free_addr, h_module, timeout)
            return result

        except Exception as e:
            self._error(f"Unexpected error during ejection: {e}")
            return InjectionResult.UNKNOWN_ERROR
        finally:
            WinAPI.CloseHandle(h_process)


    def _resolve_pid(self, target: int | str, index: int = 0) -> int | None:
        if isinstance(target, int):
            return target
        elif isinstance(target, str):
            pids = ProcessUtils.get_pids_by_name(target)
            if not pids:
                self._error(f"Process '{target}' not found")
                return None
            if index >= len(pids):
                self._error(f"Process '{target}' found {len(pids)} matches, but index {index} was requested")
                return None
            if len(pids) > 1:
                self._warning(f"Multiple processes found for '{target}', using index {index} (PID {pids[index]})")
            return pids[index]
        else:
            self._error("Target must be PID (int) or process name (str)")
            return None