import unittest
from unittest.mock import patch, mock_open
from cerne.managers.ruby import RubyManager


class TestRubyManager(unittest.TestCase):

    def setUp(self):
        self.manager = RubyManager()

    def test_parse_gemfile_lock_structure(self):
        mock_content = """GEM
  remote: https://rubygems.org/
  specs:
    rails (5.2.0)
      actionpack (= 5.2.0)
      activesupport (= 5.2.0)
    actionpack (5.2.0)
      rack (~> 2.0)
    activesupport (5.2.0)
      i18n (>= 0.7)
    rack (2.0.5)
    i18n (1.0.1)

PLATFORMS
  ruby

DEPENDENCIES
  rails (= 5.2.0)
"""
        with patch("builtins.open", mock_open(read_data=mock_content)):
            root, versions = self.manager.get_dependencies()

        rails_node = None
        for child in root.children:
            if child.name == "rails":
                rails_node = child
                break

        self.assertIsNotNone(rails_node)
        self.assertEqual(rails_node.version, "5.2.0")

        child_names = [c.name for c in rails_node.children]
        self.assertIn("actionpack", child_names)
        self.assertIn("activesupport", child_names)

    def test_ruby_circular_dependency(self):
        mock_content = """GEM
  specs:
    entry-gem (1.0)
      gem-A (= 1.0)
    gem-A (1.0)
      gem-B (= 1.0)
    gem-B (1.0)
      gem-A (= 1.0)
"""
        with patch("builtins.open", mock_open(read_data=mock_content)):
            root, _ = self.manager.get_dependencies()

        node_entry = root.children[0]
        self.assertEqual(node_entry.name, "entry-gem")
        node_a = node_entry.children[0]
        self.assertEqual(node_a.name, "gem-A")
        node_b = node_a.children[0]
        self.assertEqual(node_b.name, "gem-B")
        node_cycle = node_b.children[0]
        self.assertEqual(node_cycle.name, "gem-A")
        self.assertIn("⟳", node_cycle.version)
        self.assertEqual(len(node_cycle.children), 0)
