import os
from .go import GoManager
from .python import PythonManager
from .javascript import NodeManager
from .ruby import RubyManager

# Lista de todos os gerenciadores suportados
MANAGERS = [
    GoManager(),
    PythonManager(),
    NodeManager(),
    RubyManager(),
]


def detect_manager():
    """Verifica arquivos na pasta atual e retorna o gerenciador correto."""
    files = os.listdir(".")

    for manager in MANAGERS:
        # Se algum dos arquivos de lock existir na pasta
        for lock_file in manager.lock_files:
            if lock_file in files:
                return manager

    return None
