import os
from .go import GoManager
from .python import PythonManager
from .javascript import NodeManager
from .ruby import RubyManager
from .rust import RustManager

MANAGERS = [
    GoManager(),
    PythonManager(),
    NodeManager(),
    RubyManager(),
    RustManager(),
]


def detect_manager():
    """Checks files in the current directory and returns the correct manager."""
    files = os.listdir(".")

    for manager in MANAGERS:
        if manager.detect(files):
            return manager

    return None
