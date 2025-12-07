import json
import logging
import os
from typing import Tuple, Dict
from cerne.managers.base import PackageManager
from cerne.core.model import DependencyNode


class NodeManager(PackageManager):
    @property
    def name(self) -> str:
        return "NPM/Yarn"

    @property
    def lock_files(self) -> list[str]:
        return ["package-lock.json", "yarn.lock"]

    def get_dependencies(self) -> Tuple[DependencyNode, Dict[str, str]]:
        if os.path.exists("yarn.lock"):
            return self._parse_yarn()
        elif os.path.exists("package-lock.json"):
            return self._parse_npm()

        raise Exception("No JS dependency file found.")

    def _parse_npm(self):
        logging.debug("Parsing package-lock.json...")
        try:
            with open("package-lock.json", "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise Exception(f"Error reading package-lock.json: {e}")

        root_name = data.get("name", "package-lock")
        versions_map = {}

        def build_tree(name, current_data, depth=0):
            version = current_data.get("version", "")
            if version: versions_map[name] = version

            node = DependencyNode(name, version, expanded=(depth == 0))
            dependencies = current_data.get("dependencies", {})

            for dep_name, dep_data in dependencies.items():
                child_node = build_tree(dep_name, dep_data, depth + 1)
                node.children.append(child_node)
            return node

        root_node = build_tree(root_name, data)
        return root_node, versions_map

    def _parse_yarn(self):
        logging.debug("Parsing yarn.lock + package.json...")

        try:
            with open("package.json", "r", encoding="utf-8") as f:
                pkg_json = json.load(f)
        except FileNotFoundError:
            raise Exception("yarn.lock found but package.json is missing.")

        project_name = pkg_json.get("name", "Yarn Project")

        direct_deps = {}
        direct_deps.update(pkg_json.get("dependencies", {}))
        direct_deps.update(pkg_json.get("devDependencies", {}))

        with open("yarn.lock", "r", encoding="utf-8") as f:
            lock_content = f.read()

        # resolved_map["pacote@range"] = { "version": "1.2.3", "deps": {"sub": "ver"} }
        resolved_map = {}

        current_entry = None
        current_keys = []
        in_deps_block = False

        lines = lock_content.splitlines()
        for line in lines:
            if line.startswith("#") or not line.strip(): continue

            if not line.startswith(" ") and line.strip().endswith(":"):
                keys_raw = line.strip()[:-1]  # remove :
                keys = [k.strip().replace('"', '') for k in keys_raw.split(",")]

                current_keys = keys
                current_entry = {"version": "", "deps": {}}
                in_deps_block = False
                continue

            if line.strip().startswith("version") and current_entry is not None:
                ver = line.strip().split(maxsplit=1)[1].replace('"', '')
                current_entry["version"] = ver
                continue

            if line.strip().startswith("dependencies:"):
                in_deps_block = True
                continue

            if in_deps_block and line.startswith("    "):
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2:
                    d_name = parts[0].replace('"', '')
                    d_range = parts[1].replace('"', '')
                    current_entry["deps"][d_name] = d_range
            if current_keys and current_entry and current_entry["version"]:
                for k in current_keys:
                    resolved_map[k] = current_entry

        versions_flat = {}

        def build_tree(name, range_req, depth=0, ancestors=None):
            if ancestors is None: ancestors = set()

            key = f"{name}@{range_req}"
            data = resolved_map.get(key)

            if not data:
                pass

            if not data:
                return DependencyNode(name, range_req + "?", expanded=False)

            version = data["version"]
            versions_flat[name] = version

            if name in ancestors:
                return DependencyNode(name, version + " ⟳", expanded=False)

            node = DependencyNode(name, version, expanded=(depth == 0))

            new_ancestors = ancestors.copy()
            new_ancestors.add(name)

            for dep_name, dep_range in data["deps"].items():
                if depth < 8:
                    child = build_tree(dep_name, dep_range, depth + 1, new_ancestors)
                    node.children.append(child)

            return node

        root = DependencyNode(project_name, "Yarn", expanded=True)

        for name, ver_range in direct_deps.items():
            root.children.append(build_tree(name, ver_range, depth=1))

        logging.debug(f"Yarn tree built. {len(versions_flat)} unique packages.")
        return root, versions_flat
