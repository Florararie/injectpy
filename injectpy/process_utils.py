from injectpy.winapi import WinAPI, PROCESSENTRY32, TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, MODULEENTRY32
import os
import ctypes
import ctypes.wintypes as wintypes



class ProcessUtils:
    @staticmethod
    def get_pids_by_name(process_name: str) -> list[int]:
        pids = []
        h_snapshot = WinAPI.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if h_snapshot == wintypes.HANDLE(-1).value:
            return pids

        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if not WinAPI.Process32First(h_snapshot, ctypes.byref(entry)):
            WinAPI.CloseHandle(h_snapshot)
            return pids

        while True:
            exe_name = entry.szExeFile.decode(errors="ignore").rstrip("\x00").strip()
            if exe_name.lower() == process_name.lower():
                pids.append(entry.th32ProcessID)
            if not WinAPI.Process32Next(h_snapshot, ctypes.byref(entry)):
                break

        WinAPI.CloseHandle(h_snapshot)
        return pids


    @staticmethod
    def get_module_base(pid: int, module_name: str) -> int | None:
        target_name = os.path.basename(module_name).lower()
        snap_flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
        h_snapshot = WinAPI.CreateToolhelp32Snapshot(snap_flags, pid)
        if h_snapshot == wintypes.HANDLE(-1).value:
            return None

        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)

        if not WinAPI.Module32First(h_snapshot, ctypes.byref(entry)):
            WinAPI.CloseHandle(h_snapshot)
            return None

        base = None
        while True:
            try:
                name = entry.szModule.decode(errors="ignore").rstrip("\x00").lower()
            except Exception:
                name = ""
            if name == target_name:
                base = int(entry.hModule)
                break
            if not WinAPI.Module32Next(h_snapshot, ctypes.byref(entry)):
                break

        WinAPI.CloseHandle(h_snapshot)
        return base