import logging
from rich.markup import escape
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Tree, Label, LoadingIndicator, Markdown, Button
from textual.containers import Container, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual import work
from textual.binding import Binding

from cerne.managers import detect_manager
from cerne.core.scanner import check_vulnerabilities, enrich_tree
from cerne.__version__ import __version__

logging.basicConfig(
    filename="debug.log",
    level=logging.DEBUG,
    filemode="w",
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class VulnerabilityScreen(ModalScreen):
    CSS = """
    VulnerabilityScreen {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }
    #dialog {
        padding: 1 2;
        width: 90%;
        height: 90%;
        border: thick $error;
        background: $surface;
    }
    #title {
        text-align: center;
        text-style: bold;
        padding-bottom: 1;
        border-bottom: solid $primary;
    }
    #content {
        height: 1fr;
        margin: 1 0;
    }
    #close-btn {
        width: 100%;
    }
    """

    def __init__(self, package_name, version, vulns):
        super().__init__()
        self.pkg_name = package_name
        self.pkg_ver = version
        self.vulns = vulns

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label(f"🚨 {self.pkg_name} v{self.pkg_ver}", id="title"),
            VerticalScroll(
                Markdown(self._generate_markdown()),
                id="content"
            ),
            Button("Close (Esc)", variant="error", id="close-btn"),
            id="dialog"
        )

    def _generate_markdown(self):
        md = ""
        for v in self.vulns:
            # 1. Header (ID)
            vid = v.get("id", "Unknown Vulnerability")
            md += f"# 🔴 {vid}\n\n"

            summary = v.get("summary", "")
            if not summary:
                details_preview = v.get("details", "")[:100]
                summary = f"No summary available. ({details_preview}...)" if details_preview else "Description unavailable."

            md += f"**{summary}**\n\n"

            details = v.get("details", "")
            if details:
                md += f"{details}\n\n"
            else:
                md += "_No technical details provided in the API response._\n\n"

            md += "### 🔗 References\n\n"

            # Official OSV Link
            if vid != "Unknown Vulnerability":
                osv_url = f"https://osv.dev/vulnerability/{vid}"
                md += f"- **OSV Database (Official)**: [{osv_url}]({osv_url})\n"

            # Other API References
            refs = v.get("references", [])
            if refs:
                for ref in refs:
                    url = ref.get("url", "#")
                    rtype = ref.get("type", "Link").replace("_", " ").title()
                    if url != f"https://osv.dev/vulnerability/{vid}":
                        md += f"- **{rtype}**: [{url}]({url})\n"

            md += "\n---\n"

        if not md: md = "No vulnerability data found."
        return md

    def on_button_pressed(self, event):
        self.dismiss()

    def key_escape(self):
        self.dismiss()


class CerneApp(App):
    TITLE = "Cerne"
    SUB_TITLE = f"v {__version__}"
    CSS = """
    Tree { padding: 1; background: $surface; }
    #loading-container { height: 100%; align: center middle; }
    Label { margin-top: 1; color: $text-muted; }
    .filter-active { background: $error; color: white; text-style: bold; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("j", "cursor_down", "Down"),
        Binding("k", "cursor_up", "Up", ),
        Binding("l", "expand_node", "Expand"),
        Binding("h", "collapse_node", "Collapse"),
        Binding("space", "toggle_node", "Toggle", show=True),
        Binding("enter", "show_details", "Details", show=True),
        Binding("v", "toggle_filter", "Vuln Only", show=True),
    ]

    show_only_vulnerable = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="loading-container"):
            yield LoadingIndicator()
            yield Label("Starting Cerne...", id="status-label")
        yield Tree("Root", id="dep-tree")
        yield Footer()

    def on_mount(self):
        self.query_one("#dep-tree").display = False
        self.scan_project()

    # --- ACTIONS ---

    def action_cursor_down(self):
        self.query_one("#dep-tree").action_cursor_down()

    def action_cursor_up(self):
        self.query_one("#dep-tree").action_cursor_up()

    def action_expand_node(self):
        tree = self.query_one("#dep-tree")
        if tree.cursor_node: tree.cursor_node.expand()

    def action_collapse_node(self):
        tree = self.query_one("#dep-tree")
        node = tree.cursor_node
        if node:
            if node.is_expanded:
                node.collapse()
            elif node.parent:
                tree.select_node(node.parent)
                node.parent.collapse()

    def on_tree_node_selected(self, event):
        node_data = event.node.data
        if node_data and node_data.vulnerable:
            self.push_screen(VulnerabilityScreen(node_data.name, node_data.version, node_data.vuln_details))
        else:
            self.notify("This package seems safe.", severity="information")

    def action_toggle_filter(self):
        self.show_only_vulnerable = not self.show_only_vulnerable
        if self.show_only_vulnerable:
            self.notify("Filter enabled: Showing vulnerable packages only.", severity="warning")
        else:
            self.notify("Filter disabled: Showing all packages.", severity="information")

        # Re-render tree using stored root data
        root_data = self.query_one("#dep-tree").root.data
        if root_data: self.render_tree(root_data)

    def has_vulnerable_descendant(self, node):
        if node.vulnerable: return True
        for child in node.children:
            if self.has_vulnerable_descendant(child): return True
        return False

    # --- SCANNER & RENDER ---

    def update_progress(self, current, total):
        self.app.call_from_thread(self.update_status, f"Scanning security... (Batch {current} of {total})")

    @work(thread=True)
    def scan_project(self):
        try:
            logging.info("Worker started.")
            self.app.call_from_thread(self.update_status, "Detecting project...")
            manager = detect_manager()
            if not manager: raise Exception("No supported project found.")

            logging.info(f"Manager: {manager.name}")

            self.app.call_from_thread(self.update_status, f"Parsing dependencies ({manager.name})...")
            root_node, packages = manager.get_dependencies()

            vulns = check_vulnerabilities(packages, ecosystem=manager.name, on_progress=self.update_progress)

            self.app.call_from_thread(self.update_status, "Rendering tree...")
            enrich_tree(root_node, vulns)

            self.app.call_from_thread(self.render_tree, root_node)
        except Exception as e:
            logging.exception("Fatal error in worker:")
            self.app.call_from_thread(self.show_error, str(e))

    def update_status(self, msg):
        try:
            self.query_one("#status-label").update(msg)
        except:
            pass

    def render_tree(self, root_node):
        tree = self.query_one("#dep-tree")
        tree.clear()
        tree.root.data = root_node
        tree.root.label = f"📂 {root_node.name}"
        tree.root.expand()

        def add_nodes(tree_node, data_node):
            for child in data_node.children:
                if self.show_only_vulnerable and not self.has_vulnerable_descendant(child):
                    continue

                # Escape markup to prevent crashes with brackets in names
                safe_name = escape(child.name)
                safe_ver = escape(child.version)

                if child.vulnerable:
                    safe_info = escape(child.vuln_summary)
                    label = f"[bold red]⚠️ {safe_name}[/] [dim]{safe_ver}[/] [red]({safe_info})[/]"
                elif not child.version:
                    label = f"[blue]🔹 {safe_name}[/]"
                else:
                    label = f"[green]✔[/] {safe_name} [dim]{safe_ver}[/]"

                new_node = tree_node.add(label, expand=child.expanded, data=child)
                if self.show_only_vulnerable: new_node.expand()
                add_nodes(new_node, child)

        add_nodes(tree.root, root_node)
        self.query_one("#loading-container").display = False
        tree.display = True
        tree.focus()

    def show_error(self, message):
        self.query_one("#status-label").update(f"[bold red]Fatal Error:[/]\n{message}")
        self.query_one("LoadingIndicator").display = False
