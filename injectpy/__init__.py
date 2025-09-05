import sys
from contextlib import contextmanager

__all__ = ["Injector", "InjectionResult", "ProcessUtils"]

# Injector.pyc will be flagged as malicious by Defender. This sucks, but it is what it is.
# This will at least only disable bytecode for this specific module while allowing others
# To use it properly just like normal.
@contextmanager
def _suppress_bytecode_for_module(module_name: str):
    original_dont_write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        yield
    finally:
        sys.dont_write_bytecode = original_dont_write_bytecode


with _suppress_bytecode_for_module("injectpy"):
    from injectpy.injector import Injector, InjectionResult
    from injectpy.process_utils import ProcessUtils