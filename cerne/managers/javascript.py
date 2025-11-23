import json
import logging
from typing import Tuple, Dict
from cerne.managers.base import PackageManager
from cerne.core.model import DependencyNode


class NodeManager(PackageManager):
    @property
    def name(self) -> str:
        return "NPM"  # mapping to npm on scanner.py

    @property
    def lock_files(self) -> list[str]:
        return ["package-lock.json"]

    def get_dependencies(self) -> Tuple[DependencyNode, Dict[str, str]]:
        logging.debug("reading package-lock.json...")

        try:
            with open("package-lock.json", "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise Exception(f"Error when try to read package-lock.json (Invalid JSON): \n{e}")
        except FileNotFoundError:
            raise Exception("Dependency file not found!")

        root_name = data.get("name", "package-lock")

        # Build map to osv database consulting
        versions_map = {}

        logging.debug("Start converting JSON -> Tree ...")

        def build_tree(name, current_data, depth=0):
            version = current_data.get("version", "")

            # Add version to map to search for vulnerabilities later
            if version:
                versions_map[name] = version

            node = DependencyNode(name, version, expanded=(depth == 0))

            # NPM stores child dependencies inside dependencies
            dependencies = current_data.get("dependencies", {})

            for dep_name, dep_data in dependencies.items():
                # Yes, I like recursion ...
                child_node = build_tree(dep_name, dep_data, depth + 1)
                node.children.append(child_node)

            return node

        root_node = build_tree(root_name, data)

        logging.debug(f"NPM Tree NPM built. {len(versions_map)} packages.")
        return root_node, versions_map
