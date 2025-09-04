import enum



class InjectionResult(enum.Enum):
    SUCCESS = "Success"
    FILE_NOT_FOUND = "File not found"
    PROCESS_NOT_FOUND = "Target process not found"
    INVALID_TARGET = "Invalid target type"
    ACCESS_DENIED = "Could not open process"
    MEMORY_ALLOC_FAILED = "Could not allocate memory in target process"
    WRITE_FAILED = "Could not write file to process memory"
    LOADLIBRARY_NOT_FOUND = "Could not resolve LoadLibraryA"
    THREAD_CREATION_FAILED = "Could not create remote thread"
    TIMEOUT = "Injection thread timed out"
    ARCH_MISMATCH = "Architecture mismatch between injector and target"
    UNKNOWN_ERROR = "Unknown error"