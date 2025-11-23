import re
import logging
from typing import Tuple, Dict
from cerne.managers.base import PackageManager
from cerne.core.model import DependencyNode


class RubyManager(PackageManager):
    @property
    def name(self) -> str:
        return "RubyGems"

    @property
    def lock_files(self) -> list[str]:
        return ["Gemfile.lock"]

    def get_dependencies(self) -> Tuple[DependencyNode, Dict[str, str]]:
        logging.debug("Reading Gemfile.lock...")

        try:
            with open("Gemfile.lock", "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            raise Exception("Gemfile.lock not found.")

        versions = {}  # { "rails": "7.0.0" }
        adjacency = {}  # { "rails": ["actionpack", "activesupport"] }

        # Get name (version)
        re_spec = re.compile(r'^ {4}([a-zA-Z0-9\-_.]+)\s\(([\d.]+).*\)')

        # Get dependency
        re_dep = re.compile(r'^ {6}([a-zA-Z0-9\-_.]+)')

        # Parser state
        current_parent = None
        in_gem_block = False

        lines = content.splitlines()
        for line in lines:
            if line.strip() == "specs:":
                in_gem_block = True
                continue

            if in_gem_block and line.strip() and not line.startswith(" "):
                in_gem_block = False
                current_parent = None

            if in_gem_block:
                # Try to find a root dependency
                match_spec = re_spec.match(line)
                if match_spec:
                    name = match_spec.group(1)
                    ver = match_spec.group(2)
                    versions[name] = ver
                    current_parent = name
                    if name not in adjacency:
                        adjacency[name] = []
                    continue

                # try to find a sub dependency
                match_dep = re_dep.match(line)
                if match_dep and current_parent:
                    dep_name = match_dep.group(1)
                    adjacency[current_parent].append(dep_name)

        logging.debug(f"Parser done. {len(versions)} gems found.")

        # If nobody is my root, im am a root. I am groot
        children_set = set()
        for deps in adjacency.values():
            for dep in deps:
                children_set.add(dep)

        roots = []
        for pkg in versions.keys():
            if pkg not in children_set:
                roots.append(pkg)

        virtual_root = DependencyNode("Gemfile", "Lock", expanded=True)

        def build_tree(name, depth=0, ancestor_set=None):
            if ancestor_set is None: ancestor_set = set()

            ver = versions.get(name, "")

            # Protection against loops (common in rails: railties <-> rails)
            if name in ancestor_set:
                return DependencyNode(name, ver + " ⟳", expanded=False)

            # Visual depth limit
            node = DependencyNode(name, ver, expanded=False)

            new_ancestors = ancestor_set.copy()
            new_ancestors.add(name)

            children = adjacency.get(name, [])
            for child_name in children:
                # Ruby has optional dependencies that are sometimes not included in the specifications.
                if child_name in versions:
                    node.children.append(build_tree(child_name, depth + 1, new_ancestors))

            return node

        for r in roots:
            virtual_root.children.append(build_tree(r))

        return virtual_root, versions
