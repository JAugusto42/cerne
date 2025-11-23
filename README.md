# Cerne

**Cerne** is a terminal-based (TUI) Software Composition Analysis (SCA) tool. It visualizes your project's dependency tree and detects security vulnerabilities using the [OSV.dev](https://osv.dev) database.

![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10+-blue)

## Features

* **Multi-Language Support:** Auto-detects Go, Python, Ruby, and Node.js projects.
* **Vulnerability Scanning:** Checks dependencies against the OSV database in real-time.
* **Interactive TUI:** Built with [Textual](https://textual.textualize.io/), featuring mouse support and modals.
* **Vim-like Navigation:** Navigate the tree efficiently using `h`, `j`, `k`, `l`.
* **Smart Filtering:** Focus quickly on vulnerable packages.

## Supported Ecosystems

Cerne automatically detects the following lockfiles/manifests:

| Ecosystem   | Supported Files                                      |
|:------------|:-----------------------------------------------------|
| **Python**  | `poetry.lock`, `requirements*.txt`, `pyproject.toml` |
| **Node.js** | `package-lock.json` (NPM), `yarn.lock` (Yarn)        |
| **Go**      | `go.mod`                                             |
| **Ruby**    | `Gemfile.lock`                                       |

## Installation

Requires Python 3.10+.

# Install from source (local)
```bash
pip install .
```

# Or via wheel (if distributed)
```bash
pip install cerne-0.1.0-py3-none-any.whl
```
