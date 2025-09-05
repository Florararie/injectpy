import os
import argparse
from injectpy.injector import Injector
from injectpy.results import InjectionResult
from injectpy.process_utils import ProcessUtils



def main():
    parser = argparse.ArgumentParser(description="injectpy DLL injection tool")

    parser.add_argument("target", help="PID (int) or process name (str)")
    parser.add_argument("dll", nargs="?", help="Path to DLL to inject/eject")
    parser.add_argument("--index", type=int, default=None, help="Which process index if multiple")
    parser.add_argument("--timeout", type=int, default=5000, help="Timeout in ms (default 5000)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--inject", action="store_true", help="Inject the DLL")
    action.add_argument("--eject", action="store_true", help="Eject the DLL")
    action.add_argument("--status", action="store_true", help="Check if the DLL is loaded")
    action.add_argument("--list", action="store_true", help="List processes for the target name")
    parser.add_argument("--force", action="store_true", help="Force reinject by ejecting first if already loaded")

    args = parser.parse_args()
    injector = Injector(verbose=args.verbose)
    target = args.target if not args.target.isdigit() else int(args.target)


    if args.list:
        if isinstance(target, int):
            injector.logger.error("--list requires a process name, not a PID")
            return
        pids = ProcessUtils.get_pids_by_name(target)
        if not pids:
            injector.logger.info(f"No processes found with the name '{target}'.")
        else:
            injector.logger.info(f"Found {len(pids)} process(es) named '{target}':")
            for index, pid in enumerate(pids):
                injector.logger.info(f"Index: {index}, PID: {pid}")
        return


    if not args.dll:
        injector.logger.error("DLL path required for this action")
        return


    dll_path = os.path.abspath(args.dll)
    if args.inject:
        result = injector.inject(target, dll_path, index=args.index or 0, timeout=args.timeout, force=args.force)
        injector.logger.info(f"Injection result: {result.value}")


    elif args.eject:
        result = injector.eject(target, dll_path, index=args.index or 0, timeout=args.timeout)
        injector.logger.info(f"Ejection result: {result.value}")


    elif args.status:
        if isinstance(target, int):
            pid = target
            loaded = ProcessUtils.get_module_base(pid, dll_path)
            status_msg = f"{os.path.basename(dll_path)} is {'loaded' if loaded else 'NOT loaded'} in PID {pid}"
            injector.logger.info(f"Status result: {status_msg}")
        else:
            pids = ProcessUtils.get_pids_by_name(target)
            if not pids:
                injector.logger.error("Status result: Target process not found")
                return
            if args.index is None:
                for i, pid in enumerate(pids):
                    loaded = ProcessUtils.get_module_base(pid, dll_path)
                    status_msg = f"{os.path.basename(dll_path)} is {'loaded' if loaded else 'NOT loaded'} in PID {pid}"
                    injector.logger.info(f"Status result [Index {i}]: {status_msg}")
            else:
                if args.index >= len(pids):
                    injector.logger.error(f"Index {args.index} out of range for target '{target}'")
                    return
                pid = pids[args.index]
                loaded = ProcessUtils.get_module_base(pid, dll_path)
                status_msg = f"{os.path.basename(dll_path)} is {'loaded' if loaded else 'NOT loaded'} in PID {pid}"
                injector.logger.info(f"Status result [Index {args.index}]: {status_msg}")



if __name__ == "__main__":
    main()