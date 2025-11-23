import unittest
from unittest.mock import patch, mock_open
from cerne.managers.python import PythonManager


class TestPythonManager(unittest.TestCase):

    def setUp(self):
        self.manager = PythonManager()

    def test_parse_requirements_simple(self):
        mock_content = """
        requests==2.31.0
        flask>=2.0
        # comment
        textual
        """

        with patch("builtins.open", mock_open(read_data=mock_content)):
            root, versions = self.manager._parse_requirements(["requirements.txt"])

        self.assertEqual(root.name, "requirements.txt")
        self.assertEqual(versions["requests"], "2.31.0")
        self.assertEqual(versions["flask"], "2.0")
        self.assertEqual(versions["textual"], "")
        self.assertEqual(len(root.children), 3)

    @patch("os.listdir")
    def test_detect_requirements_files(self, mock_listdir):
        mock_listdir.return_value = ["main.py", "requirements.txt", "requirements_dev.txt", "README.md"]

        self.assertTrue(self.manager.detect(mock_listdir.return_value))

    @patch("cerne.managers.python.os.path.exists")
    @patch("cerne.managers.python.os.listdir")
    def test_priority_logic(self, mock_listdir, mock_exists):
        mock_exists.return_value = False
        mock_listdir.return_value = ["requirements.txt"]

        with patch.object(self.manager, '_parse_requirements') as mock_parse:
            mock_parse.return_value = ("FakeRoot", {})

            self.manager.get_dependencies()

            mock_parse.assert_called_once()
