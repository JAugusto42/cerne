from abc import ABC, abstractmethod
from typing import Tuple, Dict, List
from cerne.core.model import DependencyNode

class PackageManager(ABC):
    """Base class inherited by all language managers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Friendly ecosystem name (e.g., Go, PyPI, NPM)."""
        pass

    @property
    @abstractmethod
    def lock_files(self) -> List[str]:
        """List of exact filenames to check (legacy support)."""
        pass

    def detect(self, files: List[str]) -> bool:
        """
        Returns True if this manager supports the current directory.
        Default implementation checks for exact match in lock_files.
        """
        for lock_file in self.lock_files:
            if lock_file in files:
                return True
        return False

    @abstractmethod
    def get_dependencies(self) -> Tuple[DependencyNode, Dict[str, str]]:
        pass
