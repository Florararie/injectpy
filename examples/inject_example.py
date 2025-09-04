from injectpy import Injector, InjectionResult

if __name__ == "__main__":
    injector = Injector(verbose=True)
    result = injector.inject("ProcessName.exe", r"C:\Path\To\DLL\File")
    injector.logger.info(f"Injection result: {result.value}")