import argparse
from .injector import Injector
from .results import InjectionResult



def main():
    parser = argparse.ArgumentParser(description="injectpy DLL injection")
    parser.add_argument("target", help="PID (int) or process name (str)")
    parser.add_argument("dll", help="Path to DLL to inject")
    parser.add_argument("--index", type=int, default=0, help="Which process index if multiple")
    parser.add_argument("--timeout", type=int, default=5000, help="Timeout in ms (default 5000)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    injector = Injector(verbose=args.verbose)
    result = injector.inject(args.target if not args.target.isdigit() else int(args.target), args.dll, args.index, args.timeout)
    injector.logger.info(f"Injection result: {result.value}")



if __name__ == "__main__":
    main()