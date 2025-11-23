from abc import ABC, abstractmethod
from typing import Tuple, Dict
from cerne.core.model import DependencyNode

class PackageManager(ABC):
    """ Base class, all languages dependency files managers must inherit from it """

    @property
    @abstractmethod
    def name(self) -> str:
        """Friendly name of ecosystem, like: Go, Pypi, NPM """
        pass

    @property
    @abstractmethod
    def lock_files(self) -> list[str]:
        """ Dependency files to identifier the project like go.mod, Gemfile.lock """
        pass

    @abstractmethod
    def get_dependencies(self) -> Tuple[DependencyNode, Dict[str, str]]:
        """
        Returns:
            1. Root of the tree
            2. Dict for searching in osv database {package: version}
        """
        pass
