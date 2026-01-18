from injectpy import Injector, InjectionResult

if __name__ == "__main__":
    injector = Injector(verbose=True)
    result = injector.inject("Phasmophobia.exe", r"Phas.dll")
    injector.logger.info(f"Injection result: {result.value}")
