import subprocess
import logging
from typing import Tuple, Dict
from cerne.managers.base import PackageManager
from cerne.core.model import DependencyNode


class GoManager(PackageManager):
    @property
    def name(self) -> str:
        return "Go Modules"

    @property
    def lock_files(self) -> list[str]:
        return ["go.mod"]

    def get_dependencies(self) -> Tuple[DependencyNode, Dict[str, str]]:
        logging.debug("Starting reading Go Modules ...")

        try:
            # Get root
            root_name = subprocess.check_output(
                ["go", "list", "-m"],
                text=True,
                timeout=10,
                stderr=subprocess.PIPE
            ).strip()

            # read graph from go mod
            graph_out = subprocess.check_output(
                ["go", "mod", "graph"],
                text=True,
                timeout=30,
                stderr=subprocess.PIPE
            )
            logging.debug(f"Graph obtained. Processing. {len(graph_out)} bytes...")

        except Exception as e:
            logging.error(f"Go Error: {e}")
            raise Exception(f"Fail to read Go dependencies: {e}")

        adjacency = {}
        versions = {}

        for line in graph_out.splitlines():
            parts = line.split()
            if len(parts) != 2: continue

            parent, child = parts
            child_name, child_ver = self._split_ver(child)
            parent_name, _ = self._split_ver(parent)

            if parent_name not in adjacency:
                adjacency[parent_name] = []
            adjacency[parent_name].append(child_name)

            if child_ver:
                versions[child_name] = child_ver

        logging.debug(f"Start building the tree ...")

        def build_tree(name, depth=0, ancestor_set=None):
            if ancestor_set is None:
                ancestor_set = set()

            ver = versions.get(name, "")

            if depth > 10:
                return DependencyNode(name, ver + "...", expanded=False)
            if name in ancestor_set:
                return DependencyNode(name, ver + " (ciclo ⟳)", expanded=False)

            node = DependencyNode(name, ver, expanded=(depth == 0))

            new_ancestors = ancestor_set.copy()
            new_ancestors.add(name)

            children_names = adjacency.get(name, [])
            for child in children_names:
                child_node = build_tree(child, depth + 1, new_ancestors)
                node.children.append(child_node)

            return node

        root_node = build_tree(root_name)
        logging.debug("Tree successfully constructed.")

        return root_node, versions

    @staticmethod
    def _split_ver(txt):
        if "@" not in txt: return txt, ""
        return txt.split("@", 1)
