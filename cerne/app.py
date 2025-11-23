import logging
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Tree, Label, LoadingIndicator, Markdown, Button
from textual.containers import Container, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual import work
from textual.binding import Binding

from cerne.managers import detect_manager
from cerne.core.scanner import check_vulnerabilities, enrich_tree

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
        width: 85%;
        height: 85%;
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
            vid = v.get("id", "Unknow Vulnerability")
            md += f"# 🔴 {vid}\n"

            summary = v.get("summary", "")
            if not summary:
                details_preview = v.get("details", "")[:100]
                summary = f"Summary not available. ({details_preview}...)" if details_preview else "No Description."
            md += f"**{summary}**\n\n"

            details = v.get("details", "")
            if details:
                md += f"{details}\n\n"
            else:
                md += "_No technical details._\n\n"

            references = v.get("references", [])
            if references:
                md += "### 🔗 References:\n"
                for ref in references:
                    url = ref.get("url", "#")
                    ref_type = ref.get("type", "Link")
                    md += f"- [{ref_type}]({url})\n"
            md += "\n---\n"

        if not md: md = "Information about vulnerability not found."
        return md

    def on_button_pressed(self, event):
        self.dismiss()

    def key_escape(self):
        self.dismiss()


class CerneApp(App):
    show_only_vulnerable = False

    CSS = """
    Tree { padding: 1; background: $surface; }
    #loading-container { height: 100%; align: center middle; }
    Label { margin-top: 1; color: $text-muted; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("j", "cursor_down", "Down"),
        Binding("k", "cursor_up", "Up"),
        Binding("l", "expand_node", "Expand"),
        Binding("h", "collapse_node", "Collapse"),
        Binding("space", "toggle_node", "Toggle", show=True),
        Binding("enter", "show_details", "Show Details", show=True),
        Binding("v", "toggle_filter", "Only Vulnerable packages", show=True)
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="loading-container"):
            yield LoadingIndicator()
            yield Label("Starting Cerne...", id="status-label")
        yield Tree("Raiz", id="dep-tree")
        yield Footer()

    def on_mount(self):
        self.query_one("#dep-tree").display = False
        self.scan_project()

    def action_cursor_down(self):
        self.query_one("#dep-tree").action_cursor_down()

    def action_cursor_up(self):
        self.query_one("#dep-tree").action_cursor_up()

    def action_expand_node(self):
        """'l': Expande o nó atual."""
        tree = self.query_one("#dep-tree")
        if tree.cursor_node:
            tree.cursor_node.expand()

    def action_collapse_node(self):
        """
        'h': if is collapsed, will close if is not the cursor will be moved to root.
        """
        tree = self.query_one("#dep-tree")
        node = tree.cursor_node
        if node:
            if node.is_expanded:
                node.collapse()
            elif node.parent:
                tree.select_node(node.parent)
                node.parent.collapse()

    def on_tree_node_selected(self, event: Tree.NodeSelected):
        """Enter: To open details """
        node_data = event.node.data
        if node_data and node_data.vulnerable:
            self.push_screen(VulnerabilityScreen(
                node_data.name,
                node_data.version,
                node_data.vuln_details
            ))
        else:
            self.notify("This package looks secure.", severity="information")

    def update_progress(self, current, total):
        self.app.call_from_thread(
            self.update_status,
            f"Analysing... ({current} of {total})"
        )

    def action_toggle_filter(self):
        """ Toggles the filter to show only vulnerable packages """
        self.show_only_vulnerable = not self.show_only_vulnerable

        if self.show_only_vulnerable:
            self.notify("Filter applied: Showing only vulnerable packages.", severity="warning")
        else:
            self.notify("Filter removed: Showing all packages.", severity="information")

        root_data = self.query_one("#dep-tree").root.data
        if root_data:
            self.render_tree(root_data)

    @work(thread=True)
    def scan_project(self):
        try:
            logging.info("Worker Started.")
            self.app.call_from_thread(self.update_status, "Finding dependency file ...")

            manager = detect_manager()
            if not manager:
                logging.error("Dependency file not found.")
                raise Exception(
                    "Dependency file not found..\n(go.mod, Gemfile.lock, package-lock.json, pyproject.toml, requirements.txt)")

            logging.info(f"Dependency File: {manager.name}")

            self.app.call_from_thread(self.update_status, f"Reading dependencies ({manager.name})...")
            root_node, packages = manager.get_dependencies()

            vulns = check_vulnerabilities(packages, ecosystem=manager.name, on_progress=self.update_progress)

            self.app.call_from_thread(self.update_status, "Render tree...")
            enrich_tree(root_node, vulns)

            self.app.call_from_thread(self.render_tree, root_node)

        except Exception as e:
            logging.exception("Fatal Error on worker:")
            self.app.call_from_thread(self.show_error, str(e))

    def update_status(self, msg):
        try:
            self.query_one("#status-label").update(msg)
        except Exception as e:
            logging.exception(f"Fail to update status {e}")
            pass

    def render_tree(self, root_node):
        tree = self.query_one("#dep-tree")
        tree.clear()
        tree.root.data = root_node
        tree.root.label = f"📂 {root_node.name}"
        tree.root.expand()

        def add_nodes(tree_node, data_node):
            for child in data_node.children:
                if self.show_only_vulnerable is True and child.vulnerable is False:
                    continue
                if child.vulnerable:
                    label = f"[bold red]⚠️ {child.name}[/] [dim]{child.version}[/] [red]({child.vuln_summary})[/]"
                elif not child.version:
                    label = f"[blue]🔹 {child.name}[/]"
                else:
                    label = f"[green]✔[/] {child.name} [dim]{child.version}[/]"

                new_node = tree_node.add(label, expand=child.expanded, data=child)

                if self.show_only_vulnerable:
                    new_node.expand()

                add_nodes(new_node, child)

        add_nodes(tree.root, root_node)
        self.query_one("#loading-container").display = False
        tree.display = True
        tree.focus()

    def show_error(self, message):
        self.query_one("#status-label").update(f"[bold red]Fatal Error:[/]\n{message}")
        self.query_one("LoadingIndicator").display = False
