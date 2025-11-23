# Cerne

**Cerne** is a terminal-based (TUI) Software Composition Analysis (SCA) tool. It visualizes your project's dependency tree and detects security vulnerabilities using the [OSV.dev](https://osv.dev) database.

![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10+-blue)

## Features

* **Multi-Language Support:** Auto-detects Go, Python, Ruby, and Node.js projects.
* **⚡ High Performance:** Multi-threaded scanning with **local caching (24h)** for instant results on repeated runs.
* **Vulnerability Scanning:** Checks dependencies against the OSV database in real-time.
* **Interactive TUI:** Built with [Textual](https://textual.textualize.io/), featuring mouse support and detailed modals.
* **Vim-like Navigation:** Navigate the tree efficiently using `h`, `j`, `k`, `l`.
* **Smart Filtering:** Toggle the "Vulnerable Only" mode (press `v`) to focus on security risks.

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

### Option 1: Using pipx (Recommended)
Install globally in an isolated environment:

```bash
# Install from the latest release wheel
pipx install cerne-1.0.0-py3-none-any.whl

# OR install from source (if cloned)
pipx install .
```

### Option 2: Using pip

```bash
pip install cerne-1.0.0-py3-none-any.whl
```

### Option 3: For Developers

```bash
git clone https://github.com/your-username/cerne.git
cd cerne
pip install -e .
```

## Usage

Navigate to your project's root directory and run:

```bash
cerne .
```

## Keybindings

| Key           | Action                                           |
|:--------------|:-------------------------------------------------|
| **`j` / `k`** | Move cursor Down / Up                            |
| **`l` / `h`** | Expand / Collapse node                           |
| **`Enter`**   | View vulnerability details (Modal)               |
| **`v`**       | **Toggle Filter:** Show only vulnerable packages |
| **`Space`**   | Toggle expand/collapse                           |
| **`q`**       | Quit                                             |

## 📸 Demo & Interface

Cerne provides a clean, interactive way to explore dependency trees and spot security risks instantly.

### Dependency Tree Navigation

Visualize your project structure. Use Vim keys (`h`, `j`, `k`, `l`) or the mouse to navigate, expand, and collapse nodes.

|                                                                                                  Standard View                                                                                                   |                                                                                               Filtered View (Press `v`)                                                                                                |
|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| <img src="[https://github.com/user-attachments/assets/8011e027-0662-4673-9c3a-005b5d3cff53](https://github.com/user-attachments/assets/8011e027-0662-4673-9c3a-005b5d3cff53)" alt="Main Tree View" width="450"/> | <img src="[https://github.com/user-attachments/assets/8c226f13-3026-417c-986e-b1903c275ec9](https://github.com/user-attachments/assets/8c226f13-3026-417c-986e-b1903c275ec9)" alt="Vulnerable Only Mode" width="450"/> |
|                                                                              *Clear overview of direct and indirect dependencies.*                                                                               |                                                                                     *Focus instantly on vulnerable packages only.*                                                                                     |

### Vulnerability Details

Spot threats immediately (marked in red) and press **Enter** to inspect the CVE details, summaries, and references in a modal window.

<div align="center">
  <img src="[https://github.com/user-attachments/assets/68d4d5dd-944f-4c62-b45c-9c19dde56eb7](https://github.com/user-attachments/assets/68d4d5dd-944f-4c62-b45c-9c19dde56eb7)" alt="Vulnerability Details Modal" width="85%"/>
  <p><em>Detailed security information provided by the OSV.dev database.</em></p>
</div>
