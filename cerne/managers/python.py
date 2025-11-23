import os
import re
import logging
import sys
from typing import Tuple, Dict
from cerne.managers.base import PackageManager
from cerne.core.model import DependencyNode

# This will import toml lib only if python version > 3.11 because is a new way to set project dependencies
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


class PythonManager(PackageManager):
    @property
    def name(self) -> str:
        return "PyPI (Pip)"

    @property
    def lock_files(self) -> list[str]:
        return ["poetry.lock", "requirements.txt", "pyproject.toml"]

    def get_dependencies(self) -> Tuple[DependencyNode, Dict[str, str]]:
        # Estratégia de Prioridade
        if os.path.exists("poetry.lock"):
            return self._parse_poetry()
        elif os.path.exists("requirements.txt"):
            return self._parse_requirements()
        elif os.path.exists("pyproject.toml"):
            return self._parse_pyproject()

        raise Exception("Python dependency file not found.")

    def _parse_poetry(self):
        logging.debug("Reading poetry.lock...")
        with open("poetry.lock", "rb") as f:
            data = tomllib.load(f)

        versions = {}

        for pkg in data.get("package", []):
            name = pkg.get("name")
            version = pkg.get("version")
            if name and version:
                versions[name] = version

        root = DependencyNode("Poetry Project", "Lock", expanded=True)
        for name, ver in versions.items():
            root.children.append(DependencyNode(name, ver))

        return root, versions

    def _parse_requirements(self):
        logging.debug("Reading requirements file...")
        versions = {}

        # This regex will get package==1.0.0 or package>=1.0 and package<=1.0
        re_req = re.compile(r'^([a-zA-Z0-9\-_]+)(([<>=!~]+)([^;\s]+))?')

        with open("requirements.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue

                match = re_req.match(line)
                if match:
                    name = match.group(1)
                    # If doest have version, will be sent to osv to search for the last version
                    # or something like that, I don't know yet how to deal with this
                    ver = match.group(4) if match.group(4) else ""
                    versions[name] = ver

        root = DependencyNode("requirements.txt", "Flat", expanded=True)
        for name, ver in versions.items():
            root.children.append(DependencyNode(name, ver))

        return root, versions

    def _parse_pyproject(self):
        logging.debug("Reading pyproject.toml (PEP 621)...")
        with open("pyproject.toml", "rb") as f:
            data = tomllib.load(f)

        versions = {}
        dependencies = []

        # Modern pattern (PEP 621) -> [project] dependencies
        if "project" in data and "dependencies" in data["project"]:
            dependencies = data["project"]["dependencies"]

        # Old pattern -> [tool.poetry.dependencies]
        elif "tool" in data and "poetry" in data["tool"] and "dependencies" in data["tool"]["poetry"]:
            # Poetry use dict: {"flask": "^2.0"}
            poetry_deps = data["tool"]["poetry"]["dependencies"]
            for name, constraint in poetry_deps.items():
                if name == "python": continue  # we dont want python version
                # clean (^) or (^) to get only version number
                ver = str(constraint).lstrip("^~=>")
                versions[name] = ver
            dependencies = []

        # Parser for list of strings ["requests>=2.0", "textual"]
        re_req = re.compile(r'^([a-zA-Z0-9\-_]+)(([<>=!~]+)([^;\s]+))?')

        for dep_str in dependencies:
            match = re_req.match(dep_str)
            if match:
                name = match.group(1)
                ver = match.group(4) if match.group(4) else ""
                versions[name] = ver

        project_name = "Python Project"
        if "project" in data:
            project_name = data["project"].get("name", "Python Project")

        root = DependencyNode(project_name, "TOML", expanded=True)
        for name, ver in versions.items():
            # Visual warning if a generic version is used
            display_ver = ver if ver else "latest"
            root.children.append(DependencyNode(name, display_ver))

        return root, versions
