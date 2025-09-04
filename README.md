# injectpy
A lightweight DLL injector for Windows written in Python.

> [!WARNING]
> To avoid a Windows Defender false positive, this module disables .pyc bytecode generation only for itself, so you can use it safely alongside other Python modules.
> 
> You may still get a warning if globally installing the package for the first time though.

## Features
- Inject DLLs into processes by PID or process name
- Automatic handling of multiple processes with the same name
- Architecture check (x86/x64) before injection

## Installation
Clone the repo and install:

```cmd
git clone https://github.com/Florararie/injectpy.git
cd injectpy
pip install .
```

## Usage

Command-Line

```cmd
usage: injectpy [-h] [--index INDEX] [--timeout TIMEOUT] [--verbose] target dll

injectpy DLL injection

positional arguments:
  target             PID (int) or process name (str)
  dll                Path to DLL to inject

options:
  -h, --help         show this help message and exit
  --index INDEX      Which process index if multiple
  --timeout TIMEOUT  Timeout in ms (default 5000)
  --verbose          Enable verbose logging
```

Example

```cmd
injectpy notepad.exe C:\path\to\my.dll --index 0 --timeout 5000 --verbose
```

Python API

```python
from injectpy import Injector, InjectionResult

injector = Injector(verbose=True)
result = injector.inject("notepad.exe", r"C:\path\to\my.dll")

if result == InjectionResult.SUCCESS:
    print("DLL injected successfully!")
else:
    print(f"Injection failed: {result.value}")
```

## License

MIT License - see [LICENSE](/LICENSE) for details
