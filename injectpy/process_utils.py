from .winapi import WinAPI, PROCESSENTRY32, TH32CS_SNAPPROCESS
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