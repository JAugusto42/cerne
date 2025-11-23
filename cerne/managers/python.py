import os
import re
import logging
import sys
from typing import Tuple, Dict
from cerne.managers.base import PackageManager
from cerne.core.model import DependencyNode

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
        return ["poetry.lock", "pyproject.toml"]

    def detect(self, files: list[str]) -> bool:
        if super().detect(files):
            return True

        for f in files:
            if "requirements" in f and f.endswith(".txt"):
                return True

        return False

    def get_dependencies(self) -> Tuple[DependencyNode, Dict[str, str]]:
        if os.path.exists("poetry.lock"):
            return self._parse_poetry()

        req_files = [f for f in os.listdir(".") if "requirements" in f and f.endswith(".txt")]
        if req_files:
            return self._parse_requirements(req_files)

        elif os.path.exists("pyproject.toml"):
            return self._parse_pyproject()

        raise Exception("No Python dependency file found.")

    def _parse_poetry(self):
        logging.debug("Parsing poetry.lock...")
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

    def _parse_requirements(self, filenames: list[str]):
        logging.debug(f"Parsing requirements files: {filenames}")
        versions = {}

        # Matches: package==1.0, package>=1.0, package
        re_req = re.compile(r'^([a-zA-Z0-9\-_]+)(([<>=!~]+)([^;\s]+))?')

        for filename in filenames:
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith(("#", "-r", "-c")): continue

                        match = re_req.match(line)
                        if match:
                            name = match.group(1)
                            ver = match.group(4) if match.group(4) else ""
                            versions[name] = ver
            except Exception as e:
                logging.warning(f"Error reading {filename}: {e}")

        display_name = filenames[0] if len(filenames) == 1 else f"Requirements ({len(filenames)} files)"

        root = DependencyNode(display_name, "Flat", expanded=True)
        for name, ver in versions.items():
            root.children.append(DependencyNode(name, ver))

        return root, versions

    def _parse_pyproject(self):
        logging.debug("Parsing pyproject.toml (PEP 621)...")
        with open("pyproject.toml", "rb") as f:
            data = tomllib.load(f)

        versions = {}
        dependencies = []

        # PEP 621
        if "project" in data and "dependencies" in data["project"]:
            dependencies = data["project"]["dependencies"]

        # Poetry (Legacy)
        elif "tool" in data and "poetry" in data["tool"] and "dependencies" in data["tool"]["poetry"]:
            poetry_deps = data["tool"]["poetry"]["dependencies"]
            for name, constraint in poetry_deps.items():
                if name == "python": continue
                ver = str(constraint).lstrip("^~=>")
                versions[name] = ver
            dependencies = []

        re_req = re.compile(r'^([a-zA-Z0-9\-_]+)(([<>=!~]+)([^;\s]+))?')
        for dep_str in dependencies:
            match = re_req.match(dep_str)
            if match:
                name = match.group(1)
                ver = match.group(4) if match.group(4) else ""
                versions[name] = ver

        project_name = data.get("project", {}).get("name", "Python Project")

        root = DependencyNode(project_name, "TOML", expanded=True)
        for name, ver in versions.items():
            display_ver = ver if ver else "latest"
            root.children.append(DependencyNode(name, display_ver))

        return root, versions
