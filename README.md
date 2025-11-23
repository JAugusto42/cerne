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

# Or via wheel (in github release page)
```bash
pip install cerne-version-py3-none-any.whl
```

# For developers
clone this repo
```bash
cd cerne
pip install -e .
```

## Usage
Enter the project folder and run:
```bash
cerne .
```

## 📸 Demo & Interface

Cerne provides a clean, interactive way to explore dependency trees and spot security risks instantly.

### Dependency Tree Navigation

Visualize your project structure. Use Vim keys (`h`, `j`, `k`, `l`) or the mouse to navigate, expand, and collapse nodes.

| Standard View | Filtered View (Press `v`) |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/8011e027-0662-4673-9c3a-005b5d3cff53" alt="Main Tree View" width="450"/> | <img src="https://github.com/user-attachments/assets/8c226f13-3026-417c-986e-b1903c275ec9" alt="Vulnerable Only Mode" width="450"/> |
| *Clear overview of direct and indirect dependencies.* | *Focus instantly on vulnerable packages only.* |

### Vulnerability Details

Spot threats immediately (marked in red) and press **Enter** to inspect the CVE details, summaries, and references in a modal window.

<div align="center">
  <img src="https://github.com/user-attachments/assets/68d4d5dd-944f-4c62-b45c-9c19dde56eb7" alt="Vulnerability Details Modal" width="85%"/>
  <p><em>Detailed security information provided by the OSV.dev database.</em></p>
</div>
