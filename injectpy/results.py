import enum



class InjectionResult(enum.Enum):
    SUCCESS = "Success"
    FILE_NOT_FOUND = "File not found"
    PROCESS_NOT_FOUND = "Target process not found"
    INVALID_TARGET = "Invalid target type"
    ACCESS_DENIED = "Could not open process"
    MEMORY_ALLOC_FAILED = "Could not allocate memory in target process"
    WRITE_FAILED = "Could not write file to process memory"
    LOADLIBRARY_NOT_FOUND = "Could not resolve LoadLibrary"
    THREAD_CREATION_FAILED = "Could not create remote thread"
    TIMEOUT = "Injection thread timed out"
    ARCH_MISMATCH = "Architecture mismatch between injector and target"
    THREAD_EXIT_FAILED = "Could not read thread exit code"
    REMOTE_LOAD_FAILED = "LoadLibrary returned NULL"
    VERIFY_FAILED = "Module not present after load"
    UNKNOWN_ERROR = "Unknown error"
    ALREADY_LOADED = "Module already alive inside target process"
    MODULE_NOT_FOUND = "Module not found in target process"