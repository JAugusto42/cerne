import os
import sys
import logging
from typing import Tuple, Dict, List
from cerne.managers.base import PackageManager
from cerne.core.model import DependencyNode

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

class RustManager(PackageManager):
    @property
    def name(self) -> str:
        return "Cargo (Rust)"

    @property
    def lock_files(self) -> list[str]:
        return ["Cargo.lock"]

    def get_dependencies(self) -> Tuple[DependencyNode, Dict[str, str]]:
        if not os.path.exists("Cargo.lock"):
            raise Exception("Cargo.lock not found.")

        logging.debug("Parsing Cargo.lock...")
        with open("Cargo.lock", "rb") as f:
            data = tomllib.load(f)

        packages = data.get("package", [])
        versions_map = {}
        pkg_lookup = {}
        
        for pkg in packages:
            name = pkg.get("name")
            version = pkg.get("version")
            
            if name and version:
                versions_map[name] = version
                pkg_lookup[name] = pkg

        roots = [p for p in packages if "source" not in p]
        project_name = "Rust Project"

        if roots:
            if len(roots) == 1:
                project_name = roots[0].get("name", "Rust Project")
            else:
                project_name = "Rust Workspace"
        elif os.path.exists("Cargo.toml"):
            try:
                with open("Cargo.toml", "rb") as f:
                    toml_data = tomllib.load(f)
                    project_name = toml_data.get("package", {}).get("name", "Rust Project")
            except:
                pass

        def build_tree(pkg_name, pkg_ver, depth=0, visited=None):
            if visited is None: visited = set()

            if pkg_name in visited:
                return DependencyNode(pkg_name, pkg_ver + " ⟳", expanded=False)

            node = DependencyNode(pkg_name, pkg_ver, expanded=(depth==0))
            
            new_visited = visited.copy()
            new_visited.add(pkg_name)

            pkg_data = pkg_lookup.get(pkg_name)
            
            if pkg_data and "dependencies" in pkg_data:
                for dep_entry in pkg_data["dependencies"]:
                    parts = dep_entry.split()
                    dep_name = parts[0]

                    dep_ver = "?"
                    if len(parts) >= 2 and parts[1][0].isdigit():
                        dep_ver = parts[1]
                    else:
                        target_pkg = pkg_lookup.get(dep_name)
                        if target_pkg:
                            dep_ver = target_pkg.get("version", "?")
                    if depth < 8:
                        child = build_tree(dep_name, dep_ver, depth + 1, new_visited)
                        node.children.append(child)

            return node

        root_node = DependencyNode(project_name, "Cargo", expanded=True)

        if roots:
            for r in roots:
                root_node.children.append(build_tree(r.get("name"), r.get("version"), depth=1))
        else:
            for name, ver in versions_map.items():
                 root_node.children.append(DependencyNode(name, ver))

        logging.debug(f"Cargo tree built. {len(versions_map)} unique packages.")
        return root_node, versions_map
