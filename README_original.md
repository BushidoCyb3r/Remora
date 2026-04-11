
# Volatility3 GUI

> A professional, forensically-conscious PyQt5 graphical frontend for the [Volatility3](https://github.com/volatilityfoundation/volatility3) memory forensics framework.  
> Designed for analysts who need speed, auditability, and a clean workflow — without touching the command line for every query.

---

## Table of Contents

- [Overview](#overview)
- [Forensic Soundness](#forensic-soundness)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Custom Symbol Tables (Linux & macOS)](#custom-symbol-tables-linux--macos)
- [Embedded Volshell](#embedded-volshell)
- [Automatic Log Files](#automatic-log-files)
- [Exporting Results](#exporting-results)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Directory Structure](#directory-structure)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

Volatility3 GUI (`vol_gui.py`) is a single-file graphical frontend that sits directly inside your cloned Volatility3 repository and wraps the `vol.py` and `volshell.py` entry points. It exposes every discovered plugin through a categorised browser, auto-generates argument forms, streams output into tabbed result views, and writes a persistent, timestamped audit log for every action taken against a memory image — with zero modification to the image itself.

It is built for:

- **Digital forensic examiners** working case evidence who need a defensible chain-of-custody record of every analysis action
- **Incident responders** triaging compromised systems who need fast, repeatable plugin execution
- **Malware analysts** pivoting between memory artefacts who need interactive Volshell access alongside structured plugin output
- **Trainers and students** learning memory forensics who benefit from a visual, discoverable plugin interface

---

## Forensic Soundness

Forensic soundness is a core design principle, not an afterthought. Every decision in this tool has been made to ensure that analysis activity is reproducible, auditable, and leaves the evidence unchanged.

### Read-Only Evidence Handling

- `vol_gui.py` passes evidence files to Volatility3 exclusively via the `-f` flag
- No write operations are performed against the image at any point
- The tool never copies, modifies, or moves the original file
- File size and path are displayed in the UI on load so the examiner can confirm the correct image is loaded before running any plugin

### Automatic Timestamped Audit Log

Every action taken in the GUI against a memory image is automatically written to a plain-text log file the moment an image is loaded. This log:

- Is named `<image_stem>_<YYYY-MM-DD>.log` and saved **in the same directory as the evidence file**, keeping artefacts co-located with the exhibit
- Uses **full ISO 8601 timestamps** (`YYYY-MM-DD HH:MM:SS`) on every entry — not just relative times — so the log is interpretable weeks or months later without context
- Appends to an existing file if the same image is re-examined on the same date, with a clearly delimited session header, creating an unbroken chronological record across multiple examination sessions
- Records every plugin invocation with the exact command-line arguments passed to `vol.py`, so results can be independently reproduced
- Records plugin completion status, row counts, and any errors or warnings emitted by Volatility3

A typical log entry sequence looks like this:

```
========================================================================
  Session started : 2026-04-10 14:32:01
  Image           : /cases/exhibit_001/memdump.raw
========================================================================
[2026-04-10 14:32:01] [SUCCESS] Loaded: /cases/exhibit_001/memdump.raw
[2026-04-10 14:32:07] [INFO   ] → windows.pslist.PsList
[2026-04-10 14:32:08] [CMD    ] $ python3 vol.py -q --renderer json -f /cases/exhibit_001/memdump.raw windows.pslist.PsList
[2026-04-10 14:32:19] [SUCCESS] ← PsList  312 rows
[2026-04-10 14:33:02] [INFO   ] → windows.cmdline.CmdLine
[2026-04-10 14:33:02] [CMD    ] $ python3 vol.py -q --renderer json -f /cases/exhibit_001/memdump.raw windows.cmdline.CmdLine
[2026-04-10 14:33:11] [SUCCESS] ← CmdLine  88 rows
```

This log constitutes a **contemporaneous record** of analysis activity and can be attached to a forensic report or case file as supporting documentation.

### Exact Command Transparency

Every time a plugin is run, the full `vol.py` command — including all flags and arguments — is logged at the `CMD` level. This means:

- Any finding can be independently verified by re-running the logged command verbatim
- Argument changes between runs are visible in the log history
- There is no hidden processing: what you see in the log is exactly what was executed

### No Network Access

`vol_gui.py` makes no outbound network connections. All processing is local. Symbol table files are loaded from paths you specify on disk. PDB downloads (if used via the Windows symbol resolver) are a Volatility3 core function, not initiated by the GUI.

### Non-Destructive Stop

The **■ Stop** button in the status bar terminates the running plugin process cleanly. Stopping a plugin does not affect the evidence file, does not corrupt any in-progress output, and logs a `[WARNING] Plugin stopped by user.` entry so the interruption is recorded in the audit trail.

### Output Directory Isolation

If a plugin dumps files (e.g. `windows.dumpfiles`, `windows.procdump`), the output directory is specified explicitly in the config panel. Dumped files are written there — not alongside the evidence image — keeping the exhibit directory uncontaminated.

---

## Features

### Plugin Browser
- All Volatility3 plugins are auto-discovered at startup and organised into **Windows**, **Linux**, **macOS**, and **Other** categories in a collapsible tree
- Double-click any plugin to run it immediately; single-click loads its configuration form
- Search / filter bar narrows the plugin list in real time
- Plugin count displayed in the status bar

### Plugin Configuration Panel
- Requirement fields are automatically generated from each plugin's declared requirements
- Required fields are marked with `*`
- Supported field types: boolean toggle, integer spinner, choice dropdown, URI browser, list input, free text
- Output directory picker for plugins that dump files

### Results Tabs
- Each plugin run opens in its own closeable, movable tab
- Full-text filter across all columns
- Column header click to sort
- Right-click context menu on any cell
- Alternating row colours, monospace font for readability
- Tabs can be closed individually or all at once via **Results > Close All Tabs**

### Exports
Every result tab can be exported in six formats:

| Format | Notes |
|--------|-------|
| **CSV** | Comma-separated, UTF-8, suitable for Excel / LibreOffice |
| **TSV** | Tab-separated |
| **JSON** | Structured object with plugin name, image path, timestamp, and rows |
| **TXT** | Fixed-width aligned plain text, suitable for reports |
| **HTML** | Self-contained styled page, dark theme |
| **PDF** | Via Qt print support (requires `PyQt5.QtPrintSupport`) |
| **XLSX** | Excel workbook with metadata header rows (requires `openpyxl`) |

### Custom Symbol Tables
- **Symbols** menu provides dedicated sub-menus for Linux and macOS symbol paths
- Load individual files (`.json`, `.json.gz`, `.isf`, `.isf.gz`) or entire directories
- Loaded paths are automatically injected as `--symbols` into every `vol.py` invocation
- Path counts shown in the menu; full list viewable on click

### Embedded Volshell
- **Tools > Open Volshell…** (`Ctrl+Shift+S`) opens an interactive Volshell tab inside the GUI
- Spawns `volshell.py -f <loaded image>` as a subprocess
- Input bar with Up/Down arrow command history
- Restart and Kill controls in the tab toolbar
- All Volshell input/output is shown in a monospace display

### Theme
- Dark (default) and Light themes, toggled from the header bar
- Theme preference is persisted between sessions

### Stop Button
- A red **■ Stop** button appears in the status bar while a plugin is running
- Clicking it immediately terminates the plugin process and logs the interruption

---

## Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| Python | ≥ 3.8 | 3.10+ recommended |
| PyQt5 | ≥ 5.15 | Required |
| Volatility3 | latest | Must be cloned from GitHub (see Installation) |
| openpyxl | any | Optional — XLSX export only |

---

## Installation

### 1. Clone Volatility3

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
```

### 2. Install Volatility3 Dependencies

```bash
pip install -r requirements.txt
```

### 3. Install GUI Dependencies

```bash
pip install PyQt5

# Optional: Excel export support
pip install openpyxl
```

### 4. Place vol_gui.py

`vol_gui.py` must live in the **root of the cloned Volatility3 repository** — the same directory as `vol.py` and `volshell.py`.

```
volatility3/
├── vol.py              ← Volatility3 CLI entry point
├── volshell.py         ← Volatility3 interactive shell
├── vol_gui.py          ← Place this file here
├── volatility3/
│   ├── framework/
│   ├── plugins/
│   └── symbols/
├── requirements.txt
└── setup.py
```

### 5. (Optional) Install Linux/macOS Symbol Packages

For Linux and macOS memory images you will need matching ISF symbol tables. These are not bundled with Volatility3 and must be obtained separately:

- **Linux:** Generate with [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) against the target kernel's debug symbols, or download pre-built tables from the [Volatility3 symbols repository](https://github.com/volatilityfoundation/volatility3-symbols)
- **macOS:** Use dwarf2json against the target macOS kernel, or use pre-built tables where available

Once you have the files, load them via **Symbols > Linux Symbol Tables** or **Symbols > macOS Symbol Tables** in the GUI.

---

## Usage

```bash
# From inside the volatility3 directory
python3 vol_gui.py
```

### Basic Workflow

1. **Load an image** — drag and drop a memory image onto the drop zone at the top of the window, or use **File > Open Image…** (`Ctrl+O`)
2. **Browse plugins** — expand a category in the left panel and click a plugin name to load its configuration
3. **Configure** — fill in any optional arguments in the centre panel. Required fields are marked `*`. Set an output directory if the plugin dumps files
4. **Run** — click **▶ Run Plugin** or double-click the plugin name in the browser
5. **Inspect results** — the output appears in a new tab. Use the filter bar to search, click column headers to sort, right-click cells to copy
6. **Export** — use the toolbar buttons in the results tab to export in your preferred format
7. **Review the log** — the log panel at the bottom records every action. The log file is written automatically next to your evidence image

---

## Custom Symbol Tables (Linux & macOS)

Volatility3 requires ISF (Intermediate Symbol Format) JSON files to analyse Linux and macOS memory images. These are kernel-specific and must match the exact kernel version of the image.

### Loading via the GUI

1. Open **Symbols > Linux Symbol Tables** or **Symbols > macOS Symbol Tables**
2. Choose **Add Symbol Table File(s)…** to select one or more `.json` / `.json.gz` / `.isf` / `.isf.gz` files, or **Add Symbol Table Directory…** to point at a folder containing multiple tables
3. The menu updates to show how many paths are loaded
4. All subsequent plugin runs will automatically include `--symbols <path>` for each loaded path

### Generating Symbol Tables with dwarf2json

```bash
# Install dwarf2json
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json && go build

# Generate from a Linux kernel with debug symbols
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > linux-$(uname -r).json
```

---

## Embedded Volshell

Volshell gives you a live Python REPL with direct access to Volatility3's layer and symbol APIs against the loaded memory image.

### Opening Volshell

- **Menu:** Tools > Open Volshell…
- **Keyboard:** `Ctrl+Shift+S`
- A memory image must be loaded first

### Using Volshell

Type Python expressions in the input bar at the bottom of the Volshell tab and press **Enter** or click **Send**. Output streams into the display above.

```python
# List processes
for proc in context.modules["primary"].object_table:
    print(proc)

# Access the kernel module
krnl = context.modules["kernel"]

# Inspect a specific process by PID
ps = [p for p in context.modules["primary"].object_table if p.UniqueProcessId == 1234][0]
```

**Command history:** Use **Up** / **Down** arrow keys in the input bar to cycle through previously entered commands.

**Controls:**
- **Restart** — kills the current Volshell process and starts a fresh one against the same image
- **Kill** — terminates the process without restarting

---

## Automatic Log Files

A log file is created automatically the moment a memory image is loaded. No configuration is required.

### File Naming

```
<image_stem>_<YYYY-MM-DD>.log
```

Examples:
- Image: `/cases/exhibit_001/memdump.raw` → Log: `/cases/exhibit_001/memdump_2026-04-10.log`
- Image: `/mnt/evidence/WIN10-SUSPECT.vmem` → Log: `/mnt/evidence/WIN10-SUSPECT_2026-04-10.log`

### Append Behaviour

If a log file with the same name already exists (i.e. the same image is re-examined on the same date), new entries are **appended** rather than overwriting. Each new session is delimited by a clearly formatted header block:

```
========================================================================
  Session started : 2026-04-10 09:14:22
  Image           : /cases/exhibit_001/memdump.raw
========================================================================
```

This creates a continuous, unbroken record across multiple examination sessions on the same day.

### Log Levels

| Level | Meaning |
|-------|---------|
| `SUCCESS` | Plugin completed, image loaded |
| `INFO` | Plugin dispatched, general status |
| `CMD` | Exact command executed |
| `WARNING` | Plugin stopped, non-fatal issue |
| `ERROR` | Volatility3 error output, process failure |
| `DEBUG` | Verbose Volatility3 stderr |

### Log Location Indicator

The filename of the active log is shown in the log panel header bar (e.g. `→ memdump_2026-04-10.log`). Hovering over it shows the full path as a tooltip.

---

## Exporting Results

Each result tab has a toolbar with export buttons. Exports respect any active column filter — only the rows currently visible are exported.

```
[ CSV ]  [ TSV ]  [ JSON ]  [ TXT ]  [ HTML ]  [ PDF ]  [ XLSX ]
```

All exports include plugin name, image path, and timestamp as metadata.

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Open memory image |
| `Ctrl+Q` | Exit |
| `Ctrl+Shift+S` | Open Volshell |
| `F5` | Refresh plugin list |

---

## Directory Structure

After setup, your repository root should look like this:

```
volatility3/
├── vol.py
├── volshell.py
├── vol_gui.py                  ← GUI frontend
├── requirements.txt
├── setup.py
├── volatility3/
│   ├── framework/
│   ├── plugins/
│   │   ├── windows/
│   │   ├── linux/
│   │   └── mac/
│   └── symbols/
│       ├── generic/
│       └── (your .json symbol files)
└── README_GUI.md
```

---

## Troubleshooting

### `ERROR: PyQt5 is required`
```bash
pip install PyQt5
```

### No plugins appear in the browser
Ensure you are running `vol_gui.py` from inside the cloned `volatility3/` directory, or that `volatility3` is importable from your Python environment.

### Linux/macOS plugins fail with `No symbol table`
You need a matching ISF symbol file for the target kernel. Load it via **Symbols > Linux Symbol Tables > Add Symbol Table File(s)…** See [Custom Symbol Tables](#custom-symbol-tables-linux--macos).

### PDF export button is greyed out
Qt print support is required:
```bash
pip install PyQt5   # full install usually includes print support
# On some Linux distributions you may also need:
apt install python3-pyqt5.qtprintsupport
```

### XLSX export unavailable
```bash
pip install openpyxl
```

### Volshell tab shows `Failed to start volshell.py`
Confirm `volshell.py` exists in the same directory as `vol_gui.py` and that Volatility3's dependencies are fully installed.

---

## License

`vol_gui.py` is released under the same licence as Volatility3 — see [LICENSE](LICENSE) in the repository root.

Volatility3 is copyright the Volatility Foundation and contributors.

---

*Built to complement [Volatility3](https://github.com/volatilityfoundation/volatility3) — the world's leading open-source memory forensics framework.*
