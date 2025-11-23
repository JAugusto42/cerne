import unittest
from unittest.mock import patch
from cerne.managers.go import GoManager


class TestGoManager(unittest.TestCase):

    def setUp(self):
        self.manager = GoManager()

    @patch("subprocess.check_output")
    def test_go_dependency_tree_parsing(self, mock_subprocess):
        def side_effect(cmd, **kwargs):
            if "list" in cmd:
                return "my-go-project"
            if "graph" in cmd:
                return """
                my-go-project github.com/gin-gonic/gin@v1.7.0
                github.com/gin-gonic/gin@v1.7.0 github.com/go-playground/validator@v10
                """
            return ""

        mock_subprocess.side_effect = side_effect

        root, versions = self.manager.get_dependencies()

        self.assertEqual(root.name, "my-go-project")

        self.assertEqual(root.children[0].name, "github.com/gin-gonic/gin")
        self.assertEqual(root.children[0].version, "v1.7.0")

        self.assertEqual(root.children[0].children[0].name, "github.com/go-playground/validator")

    @patch("subprocess.check_output")
    def test_circular_dependency_handling(self, mock_subprocess):
        """ This test ensure cerne do not stop in loops """

        def side_effect(cmd, **kwargs):
            if "list" in cmd: return "root"
            if "graph" in cmd:
                return """
                root pkg-A@v1
                pkg-A@v1 pkg-B@v1
                pkg-B@v1 pkg-A@v1
                """
            return ""

        mock_subprocess.side_effect = side_effect

        root, _ = self.manager.get_dependencies()

        node_a = root.children[0]
        node_b = node_a.children[0]
        node_cycle = node_b.children[0]

        self.assertIn("pkg-A", node_cycle.name)
        self.assertIn("⟳", node_cycle.version)
        self.assertEqual(len(node_cycle.children), 0)
