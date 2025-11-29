import logging
from typing import Any, Dict, List

from rich.markup import escape
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Label, LoadingIndicator, Markdown, Tree

from cerne.__version__ import __version__
from cerne.core.scanner import check_vulnerabilities, enrich_tree
from cerne.managers import detect_manager

# Log Configuration
logging.basicConfig(
    filename="debug.log",
    level=logging.DEBUG,
    filemode="w",
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class VulnerabilityScreen(ModalScreen):
    """Modal to display vulnerability details in a clean view."""

    DEFAULT_CSS = """
    VulnerabilityScreen {
        align: center middle;
        background: rgba(0, 0, 0, 0.8);
    }
    #dialog {
        padding: 0 1;
        width: 85%;
        height: 85%;
        border: heavy $error;
        background: $surface;
        layout: vertical;
    }
    #title {
        text-align: center;
        text-style: bold;
        background: $error;
        color: white;
        width: 100%;
        padding: 1;
    }
    #content-scroll {
        height: 1fr;
        margin: 1 0;
        overflow-y: auto;
        scrollbar-gutter: stable;
    }
    #close-btn {
        width: 100%;
        dock: bottom;
    }
    """

    def __init__(self, package_name: str, version: str, vulns: List[Dict[str, Any]]) -> None:
        super().__init__()
        self.pkg_name = package_name
        self.pkg_ver = version
        self.vulns = vulns

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label(f"[!] {self.pkg_name} v{self.pkg_ver}", id="title"),
            VerticalScroll(
                Markdown(self._build_full_report()),
                id="content-scroll"
            ),
            Button("Close (Esc)", variant="error", id="close-btn"),
            id="dialog",
        )

    def _build_full_report(self) -> str:
        md_output = []

        for vuln in self.vulns:
            vid = vuln.get("id", "Unknown ID")
            summary = vuln.get("summary") or self._get_summary_fallback(vuln)
            details = vuln.get("details", "_No technical details provided._")

            md_output.append(f"# (X) {vid}\n")
            md_output.append(f"**{summary}**\n")
            md_output.append(f"{details}\n")

            md_output.append("### Links\n")

            osv_url = f"https://osv.dev/vulnerability/{vid}"
            md_output.append(f"- **OSV Database**: [{osv_url}]({osv_url})")

            for ref in vuln.get("references", []):
                url = ref.get("url", "#")
                rtype = ref.get("type", "Link").title()
                if url != osv_url:
                    md_output.append(f"- **{rtype}**: [{url}]({url})")

            md_output.append("\n---\n")

        if not md_output:
            return "No vulnerability data found."

        return "\n".join(md_output)

    def _get_summary_fallback(self, vuln: Dict) -> str:
        details = vuln.get("details", "")
        if details:
            return f"{details[:100]}..."
        return "No description available."

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def key_escape(self) -> None:
        self.dismiss()


class CerneApp(App):
    TITLE = "Cerne"
    SUB_TITLE = f"v{__version__}"

    DEFAULT_CSS = """
    Screen { layout: vertical; }

    #info-bar {
        height: 3; 
        dock: top;
        background: $surface;
        border-bottom: solid $primary;
        align: left middle; 
        padding: 0 1;
    }

    .info-label {
        width: auto;
        height: 1;
        padding: 0 2;
        color: $text;
    }

    #tree-container { 
        height: 1fr; 
        border: none; 
        margin: 0 1; 
    }
    Tree { padding: 1; background: $surface; }

    #loading-container { height: 100%; align: center middle; }

    .filter-active { background: $error; color: white; text-style: bold; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("l", "expand_node", "Expand"),
        Binding("h", "collapse_node", "Collapse"),
        Binding("space", "toggle_node", "Toggle"),
        Binding("enter", "show_details", "Details"),
        Binding("v", "toggle_filter", "Vuln Only"),
    ]

    show_only_vulnerable: bool = False
    total_pkgs: int = 0
    vuln_pkgs: int = 0
    manager_name: str = "..."

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal(id="info-bar"):
            yield Label(f"[b]Context:[/b] [cyan]{self.manager_name}[/]", id="lbl-context", classes="info-label")
            yield Label(f"[b]Total:[/b] [blue]{self.total_pkgs}[/]", id="lbl-total", classes="info-label")
            yield Label(f"[b]Vuln:[/b] [red]{self.vuln_pkgs}[/]", id="lbl-vuln", classes="info-label")
            yield Label(f"[b]Safe:[/b] [green]0[/]", id="lbl-safe", classes="info-label")

        with Container(id="main-area"):
            with Container(id="loading-container"):
                yield LoadingIndicator()
                yield Label("Initializing Cerne...", id="status-label")

            with Container(id="tree-container"):
                yield Tree("Root", id="dep-tree")

        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#tree-container").display = False
        self.scan_project()

    # --- ACTIONS ---

    def action_cursor_down(self) -> None:
        self.query_one("#dep-tree").action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#dep-tree").action_cursor_up()

    def action_expand_node(self) -> None:
        tree = self.query_one("#dep-tree")
        if tree.cursor_node:
            tree.cursor_node.expand()

    def action_collapse_node(self) -> None:
        tree = self.query_one("#dep-tree")
        node = tree.cursor_node
        if node:
            if node.is_expanded:
                node.collapse()
            elif node.parent:
                tree.select_node(node.parent)
                node.parent.collapse()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        node_data = event.node.data
        if node_data and node_data.vulnerable:
            self.push_screen(
                VulnerabilityScreen(node_data.name, node_data.version, node_data.vuln_details)
            )
        else:
            self.notify("This package seems safe.", severity="information")

    def action_toggle_filter(self) -> None:
        self.show_only_vulnerable = not self.show_only_vulnerable

        status = "enabled" if self.show_only_vulnerable else "disabled"
        severity = "warning" if self.show_only_vulnerable else "information"
        msg = "Showing vulnerable packages only." if self.show_only_vulnerable else "Showing all packages."

        self.notify(f"Filter {status}: {msg}", severity=severity)

        root_data = self.query_one("#dep-tree").root.data
        if root_data:
            self.render_tree(root_data)

    # --- LOGIC ---

    def _has_vulnerable_descendant(self, node: Any) -> bool:
        if node.vulnerable:
            return True
        for child in node.children:
            if self._has_vulnerable_descendant(child):
                return True
        return False

    def update_progress(self, current: int, total: int) -> None:
        # CORREÇÃO: Chamada direta, pois estamos no loop principal (async)
        self.update_status(f"Scanning security... (Batch {current} of {total})")

    def update_status(self, msg: str) -> None:
        try:
            self.query_one("#status-label").update(msg)
        except Exception:
            pass

    def update_dashboard_ui(self) -> None:
        safe_count = self.total_pkgs - self.vuln_pkgs
        self.query_one("#lbl-context", Label).update(f"[b]Context:[/b] [cyan]{self.manager_name}[/]")
        self.query_one("#lbl-total", Label).update(f"[b]Total:[/b] [blue]{self.total_pkgs}[/]")
        self.query_one("#lbl-vuln", Label).update(f"[b]Vuln:[/b] [red]{self.vuln_pkgs}[/]")
        self.query_one("#lbl-safe", Label).update(f"[b]Safe:[/b] [green]{safe_count}[/]")

    def show_error(self, message: str) -> None:
        self.query_one("#status-label").update(f"[bold red]Fatal Error:[/]\n{message}")
        self.query_one("LoadingIndicator").display = False

    # CORREÇÃO: Worker Async rodando na thread principal
    @work(thread=False)
    async def scan_project(self) -> None:
        try:
            logging.info("Worker started.")
            self.update_status("Detecting project...")

            manager = detect_manager()
            if not manager:
                raise Exception("No supported project found.")

            self.manager_name = manager.name
            self.update_dashboard_ui()

            logging.info(f"Manager: {manager.name}")
            self.update_status(f"Parsing dependencies ({manager.name})...")

            root_node, packages = manager.get_dependencies()
            self.total_pkgs = len(packages)
            self.update_dashboard_ui()

            vulns = await check_vulnerabilities(
                packages,
                ecosystem=manager.name,
                on_progress=self.update_progress
            )

            self.update_status("Rendering tree...")
            enrich_tree(root_node, vulns)
            self.vuln_pkgs = len(vulns)

            self.update_dashboard_ui()
            self.render_tree(root_node)

        except Exception as e:
            logging.exception("Fatal error in worker:")
            self.show_error(str(e))

    def render_tree(self, root_node: Any) -> None:
        tree = self.query_one("#dep-tree")
        tree.clear()
        tree.root.data = root_node
        tree.root.label = f"📂 {root_node.name}"
        tree.root.expand()

        def add_nodes(tree_node, data_node):
            for child in data_node.children:
                if self.show_only_vulnerable and not self._has_vulnerable_descendant(child):
                    continue

                safe_name = escape(child.name)
                safe_ver = escape(child.version)

                # Logic for Child Count Indicator
                child_count = len(child.children)
                if child_count > 0:
                    count_suffix = f" [dim]↳[/] {child_count}"
                else:
                    count_suffix = ""

                if child.vulnerable:
                    safe_info = escape(child.vuln_summary)
                    label = f"[bold red](!) {safe_name}[/] [dim]{safe_ver}[/] [red]({safe_info})[/]{count_suffix}"
                elif not child.version:
                    label = f"[blue](-) {safe_name}[/]{count_suffix}"
                else:
                    label = f"[green](•) {safe_name} [dim]{safe_ver}[/]{count_suffix}"

                new_node = tree_node.add(label, expand=child.expanded, data=child)
                if self.show_only_vulnerable:
                    new_node.expand()

                add_nodes(new_node, child)

        add_nodes(tree.root, root_node)
        self.query_one("#loading-container").display = False
        self.query_one("#tree-container").display = True
        tree.focus()
