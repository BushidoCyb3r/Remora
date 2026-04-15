# Remora

> A professional, forensically-conscious PyQt5 graphical frontend for the [Volatility3](https://github.com/volatilityfoundation/volatility3) memory forensics framework.
> Built for analysts who need speed, auditability, and intelligence-informed triage — without touching the command line for every query.

---

## Table of Contents

- [Overview](#overview)
- [What's New in v2](#whats-new-in-v2)
- [Forensic Soundness](#forensic-soundness)
- [Requirements](#requirements)
- [Installation](#installation)
- [Interface Layout](#interface-layout)
- [Loading a Memory Image](#loading-a-memory-image)
- [Plugin Browser](#plugin-browser)
- [MITRE ATT&CK / Threat Actor Filter](#mitre-attck--threat-actor-filter)
- [Plugin Configuration Panel](#plugin-configuration-panel)
- [Running Plugins](#running-plugins)
- [Results Tabs](#results-tabs)
- [Exporting Results](#exporting-results)
- [MITRE Coverage Matrix](#mitre-coverage-matrix)
- [Custom Symbol Tables](#custom-symbol-tables-linux--macos)
- [Embedded Volshell](#embedded-volshell)
- [Automatic Log Files](#automatic-log-files)
- [Theme](#theme)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Directory Structure](#directory-structure)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

`remora.py` is a single-file graphical frontend that lives inside your cloned Volatility3 repository and wraps the `vol.py` and `volshell.py` entry points. It exposes every discovered plugin through a categorised, searchable browser, auto-generates argument forms, streams output into tabbed result views, writes a persistent timestamped audit log for every action, and — new in v2 — maps every plugin to the MITRE ATT&CK framework and known threat actor groups so that plugin selection and result exports are intelligence-aware from the start.

**Built for:**

- **Digital forensic examiners** who need a defensible chain-of-custody record of every analysis step
- **Incident responders** triaging live or acquired memory who need fast, repeatable plugin execution guided by known adversary TTPs
- **Threat hunters** correlating memory artefacts against specific threat actor toolkits
- **Malware analysts** pivoting between structured plugin output and interactive Volshell access
- **Trainers and students** learning memory forensics in a visual, discoverable interface

---

## What's New in v2

### MITRE ATT&CK Integration Throughout

v2 adds a complete MITRE ATT&CK mapping layer across the entire tool:

| Component | What It Does |
|---|---|
| **Technique / Actor Filter** | Dropdown in the plugin browser that narrows the plugin list to only those relevant to a selected technique ID or threat actor group |
| **Coverage Matrix** | Standalone window (Tools menu) showing every mapped plugin against 10 ATT&CK tactic columns with H/M/L confidence ratings |
| **Export metadata** | Every export format (CSV, TSV, JSON, TXT, HTML, PDF, XLSX) now embeds the MITRE techniques and matching threat actors for the plugin that produced the results |
| **Plugin tooltips** | Hovering over a plugin in the browser shows its mapped ATT&CK techniques inline |

### MITRE Data Scale

| Data Set | Count |
|---|---|
| ATT&CK technique IDs mapped | 65 |
| Plugin-to-technique mappings | 137 plugin keys |
| Plugins with at least one ATT&CK mapping | 181 of 197 discovered |
| Threat actor / group profiles | 26 |
| High-confidence tactic cells in the matrix | 89 |

### What Remora Does NOT Do

Plugins that are **forensic infrastructure only** — `windows.info`, `windows.crashinfo`, `windows.statistics`, `windows.virtmap`, `windows.poolscanner`, and similar — carry **no ATT&CK mapping**. This is intentional. These plugins establish ground truth about the system; they do not detect adversary behaviour. Falsely tagging them would pollute threat-actor filters with noise.

---

## Forensic Soundness

Forensic soundness is a core design principle, not an afterthought.

### Read-Only Evidence Handling

- `remora.py` passes evidence files to Volatility3 exclusively via the `-f` flag
- No write operations are performed against the image at any point
- The tool never copies, modifies, or moves the original file
- File name, path, and size are displayed on load so the examiner can confirm the correct image before running any plugin

### Automatic Timestamped Audit Log

Every action taken against a memory image is written to a plain-text log file the moment an image is loaded:

- Named `<image_stem>_<YYYY-MM-DD>.log`, saved **in the same directory as the evidence**, keeping artefacts co-located with the exhibit
- Uses full ISO 8601 timestamps (`YYYY-MM-DD HH:MM:SS`) on every entry
- Appends across multiple sessions on the same date, with a clearly delimited session header
- Records the exact `vol.py` command-line for every plugin invocation — results are independently reproducible by re-running the logged command verbatim
- Records plugin completion status, row counts, and any warnings or errors

```
========================================================================
  Session started : 2026-04-10 14:32:01
  Image           : /cases/exhibit_001/memdump.raw
========================================================================
[2026-04-10 14:32:01] [SUCCESS] Loaded: /cases/exhibit_001/memdump.raw
[2026-04-10 14:32:07] [INFO   ] → windows.malfind.Malfind
[2026-04-10 14:32:08] [CMD    ] $ python3 vol.py -q --renderer json -f /cases/exhibit_001/memdump.raw windows.malfind.Malfind
[2026-04-10 14:32:19] [SUCCESS] ← Malfind  14 rows
```

### Exact Command Transparency

Every plugin invocation logs the full `vol.py` command including all flags. Any finding can be independently reproduced by re-running the logged command verbatim.

### No Network Access

`remora.py` makes no outbound network connections. All processing is local. PDB downloads (if used via the Windows symbol resolver) are a Volatility3 core function, not initiated by the GUI.

### Non-Destructive Stop

The **■ Stop** button terminates the running plugin process cleanly. Stopping a plugin does not affect the evidence file, does not corrupt in-progress output, and writes a `[WARNING] Plugin stopped by user.` entry to the audit log.

### Output Directory Isolation

Plugins that dump files (e.g. `windows.dumpfiles`) write to an explicitly specified output directory, not alongside the evidence image.

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Python | ≥ 3.8 | 3.10+ recommended |
| PyQt5 | ≥ 5.15 | Required |
| Volatility3 | latest | Cloned from GitHub |
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

# Optional: Excel export
pip install openpyxl
```

### 4. Place remora.py

`remora.py` must live in the **root of the cloned Volatility3 repository** — the same directory as `vol.py` and `volshell.py`.

```
volatility3/
├── vol.py
├── volshell.py
├── remora.py          ← place here
├── volatility3/
│   ├── framework/
│   ├── plugins/
│   │   ├── windows/
│   │   ├── linux/
│   │   └── mac/
│   └── symbols/
├── requirements.txt
└── setup.py
```

### 5. Launch

```bash
python3 remora.py
```

---

## Interface Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ▌ Volatility3   Memory Forensics          [image · size]  ▶ plugin  ☀ │  ← header bar
├────────────────────────────────────────────────────────────────────────│
│  Drop a memory image here  —  or click to browse                        │  ← drop zone
├───────────────┬──────────────────┬─────────────────────────────────────│
│  PLUGINS      │  CONFIGURE       │  (results tabs)                      │
│  ─────────    │  ─────────────── │                                      │
│  [Filter…]    │  Plugin name     │  plugin_name  · N rows  · image.raw  │
│  [MITRE ▾]    │  Description     │  [Filter rows…] [Columns▾] [Export▾] │
│               │                  │  ┌──────────────────────────────┐    │
│  ▶ WINDOWS    │  * Required arg  │  │ col1  col2  col3  col4  ...  │    │
│     malfind   │    Optional arg  │  │ ...                          │    │
│     pslist    │                  │  └──────────────────────────────┘    │
│     netscan   │  OUTPUT DIR      │                                      │
│  ▶ LINUX      │  [path…] [Browse]│                                      │
│  ▶ MACOS      │                  │                                      │
│  ▶ OTHER      │  [▶  Run Plugin] │  (log panel)                         │
├───────────────┴──────────────────┴─────────────────────────────────────│
│ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ (2px progress bar)           │
│ Ready                                    Running Malfind…  [■ Stop]     │  ← status bar
└─────────────────────────────────────────────────────────────────────────┘
```

Three-pane layout with resizable splitters:
- **Left** — Plugin browser (collapsible tree, text search, MITRE/actor filter)
- **Centre** — Plugin configuration form (auto-generated from plugin requirements)
- **Right** — Results tabs above, log panel below

---

## Loading a Memory Image

**Method 1 — Drag and drop:** Drag any supported memory image file directly onto the drop zone bar.

**Method 2 — File menu:** `File > Open Image…` (`Ctrl+O`).

**Supported extensions:** `.dmp` `.mem` `.vmem` `.raw` `.img` `.bin` `.lime` `.dd` `.E01` `.e01`

Once loaded:
- The file name and size appear in the header bar
- The log file is created (or opened for append) next to the evidence file
- The **▶ Run Plugin** button becomes active
- The drop zone label updates to confirm the load

To load a different image, simply drag another file or use File > Open again.

---

## Plugin Browser

The plugin browser occupies the left panel. All Volatility3 plugins are discovered at startup and organised into four categories:

| Category | Contents |
|---|---|
| **WINDOWS** | All `windows.*` plugins |
| **LINUX** | All `linux.*` plugins |
| **MACOS** | All `mac.*` plugins |
| **OTHER** | Cross-platform plugins: `timeliner`, `yarascan`, `banners`, `regexscan`, etc. |

### Navigation

- **Single-click** a plugin to load its configuration form in the centre panel
- **Double-click** a plugin to run it immediately with default settings (image must be loaded)
- **Right-click** a plugin for a context menu with Configure and Run options
- The **count badge** in the panel header shows total plugins, or `visible/total` when a filter is active

### Text Search

The **Filter plugins…** bar narrows the tree in real time by substring match against the full plugin name. Matching categories auto-expand; empty categories hide.

---

## MITRE ATT&CK / Threat Actor Filter

The dropdown below the text search is the primary new feature. It filters the plugin tree to show **only plugins that map to the selected ATT&CK technique or threat actor group**.

### How to Use

1. Click the dropdown — it opens with three sections:
   - `— All Plugins —` (clears the filter)
   - **MITRE ATT&CK Techniques** — 65 technique IDs listed as `T1055  –  Process Injection`
   - **Known Threat Actors / Groups** — 26 profiles

2. Select a technique ID or actor name
3. The plugin tree immediately filters to show only relevant plugins; the count badge updates to `visible/total`
4. The text search and MITRE filter combine with AND logic — you can search for "scan" among APT29 plugins simultaneously

### Technique Filter Logic

Selecting a parent technique (e.g. `T1003 – OS Credential Dumping`) also reveals plugins mapped to subtechniques (`T1003.001`, `T1003.002`, `T1003.004`, `T1003.005`). Selecting a subtechnique shows only plugins with that specific mapping.

### Threat Actor Profiles

Each threat actor profile is a set of technique IDs sourced from MITRE ATT&CK Groups and published threat reports. Selecting an actor shows all plugins relevant to **any** technique in that actor's toolkit (OR logic across techniques).

**Included threat actor profiles:**

| Actor | Also Known As |
|---|---|
| APT1 | Comment Crew, Unit 61398 |
| APT28 | Fancy Bear, Sofacy, Pawn Storm |
| APT29 | Cozy Bear, The Dukes |
| APT32 | OceanLotus, Cobalt Kitty |
| APT38 / Lazarus Group | Hidden Cobra |
| APT41 | Winnti, BARIUM, Double Dragon |
| BlackCat / ALPHV | — |
| Carbanak / FIN7 | Navigator Group |
| Cl0p | — |
| Conti | — |
| DarkHotel | Tapaoux |
| Equation Group | NSA/GCHQ-linked |
| Gamaredon | Primitive Bear |
| Hive | — |
| Kimsuky | Thallium, Black Banshee |
| LockBit | — |
| MuddyWater | Static Kitten |
| NotPetya / Sandworm | GRU Unit 74455 |
| REvil / Sodinokibi | — |
| Ryuk | — |
| ShadowPad | APT41-linked |
| TA505 | Evil Corp-linked |
| Turla | Venomous Bear, Waterbug |
| WannaCry | Lazarus Group |
| Winnti Group | APT41 overlap |
| Wizard Spider | Ryuk / TrickBot operators |

### Plugin Tooltips

Hovering over any plugin in the tree shows a tooltip with:
- First line of the plugin's own docstring
- All MITRE technique IDs and names it maps to

### Technical Detail — Mapping Architecture

The mapping is implemented in three data structures at the top of `remora.py`:

```
MITRE_TECHNIQUES   Dict[str, str]         65 technique IDs → human-readable names
PLUGIN_MITRE_MAP   Dict[str, List[str]]   137 plugin name keys → technique ID lists
THREAT_ACTORS      Dict[str, List[str]]   26 actor names → technique ID sets
```

Plugin name keys are matched by splitting the full plugin name on `.` and comparing segments. For example, the key `"hashdump"` matches both `windows.hashdump` and `windows.registry.hashdump`. This means the mapping works automatically for aliases and nested registry plugins without requiring separate entries.

Plugins that are **forensic infrastructure** (`info`, `crashinfo`, `statistics`, `virtmap`, `poolscanner`, etc.) are intentionally absent from the map — they establish system state, not adversary behaviour.

---

## Plugin Configuration Panel

The centre panel auto-generates an argument form from each plugin's declared requirements.

### Field Types

| Requirement Type | Widget |
|---|---|
| Boolean | Checkbox |
| Integer | Spinner (full int range) |
| Choice | Dropdown populated with valid values |
| URI / file path | Text field + `…` browse button |
| List | Space-separated text field |
| String / other | Free text field with placeholder from description |

Required fields are prefixed with `*` in the label. Optional fields can be left blank.

### Output Directory

Below the arguments form, an **Output Directory** field accepts a path for plugins that dump files (`windows.dumpfiles`, `windows.pedump`, etc.). Files are written there, not alongside the evidence image. Blank means no output directory is passed.

---

## Running Plugins

### Standard Run

Click **▶ Run Plugin** in the configuration panel. The plugin executes in a background thread (`PluginRunnerThread`) via `vol.py --renderer json`, keeping the GUI responsive.

### Quick Run

Double-click any plugin in the browser to run it with default settings immediately, bypassing the configuration form.

### While Running

- The header bar shows `▶ pluginname` in amber
- A 2-pixel indeterminate progress bar runs across the bottom of the window
- The **■ Stop** button appears in the status bar — click it at any time to terminate the plugin process
- All stderr output from Volatility3 streams into the log panel in real time

### Running Multiple Plugins

Only one plugin runs at a time. If you attempt to run a second plugin while one is active, the GUI offers to stop the current one first.

---

## Results Tabs

Each completed plugin run opens in a new closeable, movable tab in the right panel.

### Tab Toolbar

```
[plugin · N rows · image.raw]    [Filter rows…]  [Columns ▾]  [Export ▾]
```

- **Filter rows** — full-text search across all columns; count updates live
- **Columns** — toggle individual column visibility; hidden columns are excluded from exports
- **Export** — opens the export format menu

### Table Features

- Alternating row colours
- Monospace font (`Cascadia Code` / `Fira Code` / `Consolas`)
- Click any column header to sort ascending/descending
- `true` / `yes` cells highlighted green; `false` / `no` cells highlighted red; `N/A` / `None` cells muted
- Right-click any cell for **Copy Cell**, **Copy Row (TSV)**, or direct export

### Managing Tabs

- Close individual tabs with the `✕` on each tab
- **Results > Close All Tabs** clears everything and returns to the welcome screen
- The Volshell tab (if open) is closed and the process is killed when its tab is closed

---

## Exporting Results

Every result tab can be exported in seven formats. Exports respect the active column visibility and row filter — only visible columns and rows are exported.

### All Exports Now Include MITRE Metadata

Every export format embeds:
- **MITRE technique IDs and names** for the plugin that produced the results
- **Threat actor names** whose technique sets overlap with this plugin's mapping

Format-specific implementation:

---

### CSV

```
# Plugin: windows.malfind.Malfind
# Image: memdump.raw
# Timestamp: 2026-04-10 14:32:19
# MITRE Techniques: T1055 – Process Injection; T1055.001 – DLL Injection; T1620 – Reflective Code Loading; ...
# Threat Actors: APT28 (Fancy Bear); APT29 (Cozy Bear); APT38 / Lazarus Group; ...

PID,Process,Start VPN,End VPN,Tag,Protection,CommitCharge,...
```

Comment lines (prefixed `#`) appear before the blank separator and the data header row. Importable into Excel / LibreOffice without issue — spreadsheet applications typically ignore `#` rows or display them without breaking the table.

---

### TSV

Same structure as CSV: MITRE comment header block, blank line, then tab-separated data. Suitable for `cut`, `awk`, and database imports.

---

### JSON

```json
{
  "plugin": "windows.malfind.Malfind",
  "image": "/cases/exhibit_001/memdump.raw",
  "timestamp": "2026-04-10 14:32:19",
  "mitre": {
    "techniques": [
      { "id": "T1055",     "name": "Process Injection" },
      { "id": "T1055.001", "name": "Process Injection: DLL Injection" },
      { "id": "T1055.002", "name": "Process Injection: Portable Executable Injection" },
      { "id": "T1055.012", "name": "Process Injection: Process Hollowing" },
      { "id": "T1620",     "name": "Reflective Code Loading" },
      { "id": "T1027.007", "name": "Obfuscated Files: Dynamic API Resolution" }
    ],
    "threat_actors": [
      "APT28 (Fancy Bear / Sofacy / Pawn Storm)",
      "APT29 (Cozy Bear / The Dukes)",
      "APT38 / Lazarus Group (Hidden Cobra)",
      "..."
    ]
  },
  "rows": [
    { "PID": "1234", "Process": "svchost.exe", ... },
    ...
  ]
}
```

The `"mitre"` block is machine-parseable and suitable for ingestion into SIEMs, case management tools, or threat intel platforms.

---

### TXT (Plain Text)

```
Plugin    : windows.malfind.Malfind
Image     : /cases/exhibit_001/memdump.raw
Timestamp : 2026-04-10 14:32:19
Rows      : 14
MITRE     : T1055 – Process Injection; T1055.001 – DLL Injection; T1620 – Reflective Code Loading
Actors    : APT28 (Fancy Bear); APT29 (Cozy Bear); APT38 / Lazarus Group; APT41 (Winnti)
            Carbanak / FIN7; Conti Ransomware; LockBit Ransomware; ...

PID       Process       Start VPN          End VPN            Tag    Protection
--------- ------------- ------------------ ------------------ ------ ----------
...
```

Actor names wrap onto continuation lines (indented) when there are more than four. Suitable for copy-paste into reports or attaching as exhibit documentation.

---

### HTML

A self-contained, dark-themed HTML report. remora adds a **MITRE badge section** above the data table:

```
┌─────────────────────────────────────────────────────────────────┐
│  MITRE ATT&CK   [T1055] [T1055.001] [T1055.002] [T1620] [...]  │
│  Threat Actors  [APT28] [APT29] [APT38] [Carbanak] [...]        │
└─────────────────────────────────────────────────────────────────┘
```

- Technique IDs render as dark-blue monospace chips; hovering shows the full technique name
- Threat actor names render as dark-red chips
- The badge section only appears if the plugin has at least one ATT&CK mapping
- Self-contained: no external CSS or JavaScript dependencies

---

### PDF

Rendered via Qt print support. v2 adds a small metadata table above the results grid:

```
windows.malfind.Malfind
/cases/exhibit_001/memdump.raw · 2026-04-10 14:32:19 · 14 rows

MITRE Techniques   T1055 – Process Injection; T1055.001 – DLL Injection; ...
Threat Actors      APT28 (Fancy Bear); APT29 (Cozy Bear); ...

PID    Process       Start VPN    ...
```

Requires `PyQt5.QtPrintSupport` (usually included in a standard PyQt5 installation).

---

### XLSX (Excel)

v2 adds two enhancements to the Excel export:

**1. Extended metadata header rows** in the main data sheet:

| Row | Label | Value |
|---|---|---|
| 1 | Plugin | `windows.malfind.Malfind` |
| 2 | Image | `/cases/exhibit_001/memdump.raw` |
| 3 | Timestamp | `2026-04-10 14:32:19` |
| 4 | Rows | `14` |
| 5 | MITRE Techniques | `T1055 – Process Injection; T1055.001 – ...` |
| 6 | Threat Actors | `APT28 (Fancy Bear); APT29 (Cozy Bear); ...` |
| 7 | *(blank)* | |
| 8+ | *(column headers + data)* | |

**2. A dedicated "MITRE Coverage" sheet** is added automatically when the plugin has ATT&CK mappings:

| Column A | Column B |
|---|---|
| Plugin | `windows.malfind.Malfind` |
| Timestamp | `2026-04-10 14:32:19` |
| *(blank)* | |
| Technique ID | Technique Name |
| T1055 | Process Injection |
| T1055.001 | Process Injection: DLL Injection |
| ... | |
| *(blank)* | |
| Threat Actors | |
| APT28 (Fancy Bear / Sofacy / Pawn Storm) | |
| APT29 (Cozy Bear / The Dukes) | |
| ... | |

Requires `pip install openpyxl`.

---

## MITRE Coverage Matrix

**Tools > MITRE Coverage Matrix…** (`Ctrl+Shift+M`)

Opens a standalone window showing every Volatility3 plugin that has an ATT&CK mapping, displayed as a grid against 10 ATT&CK tactic columns.

### What It Shows

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  MITRE ATT&CK COVERAGE MATRIX     ● H = primary   ◉ M = secondary   ○ L = circumstantial  │
│  [Filter plugins…]  [All Tactics ▾]  [All Confidence ▾]  [Export CSV ▾]             │
├──────────────────────────────┬─────────┬──────┬───────┬───────┬──────┬───────┬──────┤
│ Plugin                       │ OS      │ Exec │ Perst │ PrivE │ DefE │ Cred  │ Disc │
├──────────────────────────────┼─────────┼──────┼───────┼───────┼──────┼───────┼──────┤
│ windows.malfind.Malfind      │ Win     │      │       │ ● H   │ ◉ M  │       │      │
│ windows.hashdump.Hashdump    │ Win     │      │       │       │      │ ● H   │      │
│ windows.netscan.NetScan      │ Win     │      │       │       │      │       │ ● H  │
│ linux.check_syscall.Check_.. │ Linux   │      │       │       │ ● H  │       │      │
│ ...                          │ ...     │      │       │       │      │       │      │
└──────────────────────────────┴─────────┴──────┴───────┴───────┴──────┴───────┴──────┘
│ 181 plugins mapped                                                                   │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### Confidence Levels

Each cell shows the **highest confidence level** among the techniques the plugin maps to within that tactic column:

| Symbol | Level | Meaning |
|---|---|---|
| `● H` | High | Plugin was specifically engineered to detect this technique (e.g. `skeleton_key_check` → T1556.001, `malfind` → T1055) |
| `◉ M` | Medium | Strong secondary signal — the plugin reveals reliable evidence of this technique but it is not the primary purpose (e.g. `netscan` revealing C2 connections → T1071) |
| `○ L` | Low | Circumstantial or indirect evidence only (e.g. `strings` revealing C2 URIs → T1071) |
| *(blank)* | None | No mapping for this tactic |

### Tactic Columns

| Column | ATT&CK Tactic | Example High-Confidence Plugins |
|---|---|---|
| Execution | TA0002 | `cmdline`, `cmdscan`, `bash`, `direct_system_calls` |
| Persistence | TA0003 | `scheduled_tasks`, `svcscan`, `shimcachemem`, `callbacks` |
| Priv Escalation | TA0004 | `malfind`, `hollowprocesses`, `processghosting`, `privileges` |
| Def Evasion | TA0005 | `ssdt`, `etwpatch`, `check_idt`, `unhooked_system_calls` |
| Cred Access | TA0006 | `hashdump`, `cachedump`, `lsadump`, `skeleton_key_check` |
| Discovery | TA0007 | `netscan`, `pslist`, `filescan`, `hivelist` |
| Lat Movement | TA0008 | `netscan`, `netstat`, `sessions` |
| Collection | TA0009 | `dumpfiles`, `mftscan`, `pedump` |
| C2 | TA0011 | `netscan`, `netstat`, `mutantscan` |
| Impact | TA0040 | `truecrypt` |

### Filtering the Matrix

- **Text search** — filter by plugin name
- **Tactic dropdown** — show only plugins with coverage in a specific tactic; confidence filter applies only to that column
- **Confidence dropdown** — `High only` / `High + Medium` / `All Confidence`

All three filters combine with AND logic.

### Exporting the Matrix

Click **Export CSV ▾** to save the currently visible matrix as a CSV file. Cells contain raw `H`, `M`, `L`, or blank — not the display symbols — for easy downstream processing.

**Coverage summary** (from 197 discovered plugins):

| Tactic | Plugins Mapped |
|---|---|
| Defence Evasion | 92 |
| Discovery | 63 |
| Privilege Escalation | 43 |
| Execution | 25 |
| Credential Access | 16 |
| Persistence | 14 |
| Collection | 9 |
| C2 | 6 |
| Lateral Movement | 4 |
| Impact | 1 |

---

## Custom Symbol Tables (Linux & macOS)

Volatility3 requires ISF (Intermediate Symbol Format) JSON files to analyse Linux and macOS memory images. These must match the exact kernel version of the image being examined.

### Loading via the GUI

1. Open **Symbols > Linux Symbol Tables** or **Symbols > macOS Symbol Tables**
2. Choose **Add Symbol Table File(s)…** to select one or more `.json` / `.json.gz` / `.isf` / `.isf.gz` files, or **Add Symbol Table Directory…** to point at a folder
3. The menu updates to show how many paths are loaded (`Loaded: N path(s) — view…`)
4. All subsequent plugin runs automatically include `--symbols <path>` for each loaded path
5. Use **Clear Linux Symbols** / **Clear macOS Symbols** / **Clear All Custom Symbols** to remove paths

### Generating Symbol Tables

```bash
# Install dwarf2json
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json && go build

# Generate from a Linux kernel with debug symbols
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) \
    > linux-$(uname -r).json
```

Pre-built tables are also available from the [Volatility3 symbols repository](https://github.com/volatilityfoundation/volatility3-symbols).

---

## Embedded Volshell

**Tools > Open Volshell…** (`Ctrl+Shift+S`)

Opens an interactive Python REPL tab with direct access to Volatility3's layer, context, and symbol APIs against the loaded image.

### Requirements

- A memory image must be loaded before opening Volshell
- Only one Volshell tab can be open at a time; re-invoking the menu item switches to the existing tab

### Using Volshell

Type Python expressions in the `>>>` input bar and press **Enter** or click **Send**. Output streams into the display above.

```python
# List all running processes
for proc in context.modules["primary"].object_table:
    print(f"PID {proc.UniqueProcessId}  {proc.ImageFileName}")

# Inspect a specific PID
ps = next(p for p in context.modules["primary"].object_table
          if p.UniqueProcessId == 1234)
print(ps.ImageFileName, hex(ps.obj_offset))

# Access the kernel module directly
krnl = context.modules["kernel"]
```

**Command history:** Up / Down arrow keys in the input bar cycle through previously entered commands within the session.

**Controls in the tab toolbar:**

| Button | Action |
|---|---|
| **Restart** | Kills the current process and starts a fresh Volshell against the same image |
| **Kill** | Terminates the process without restarting |

Closing the Volshell tab kills the process automatically.

---

## Automatic Log Files

A log file is created the moment a memory image is loaded. No configuration required.

### File Naming and Location

```
<image_stem>_<YYYY-MM-DD>.log
```

Saved **next to the evidence image**:

| Image Path | Log Path |
|---|---|
| `/cases/exhibit_001/memdump.raw` | `/cases/exhibit_001/memdump_2026-04-10.log` |
| `/mnt/evidence/WIN10.vmem` | `/mnt/evidence/WIN10_2026-04-10.log` |

### Append Behaviour

If the same image is re-examined on the same date, entries are appended. Each session is delimited:

```
========================================================================
  Session started : 2026-04-10 09:14:22
  Image           : /cases/exhibit_001/memdump.raw
========================================================================
```

### Log Levels

| Level | When It Appears |
|---|---|
| `SUCCESS` | Plugin completed, image loaded |
| `INFO` | Plugin dispatched, status messages |
| `CMD` | Exact `vol.py` command executed |
| `WARNING` | Plugin stopped by user, non-fatal issues |
| `ERROR` | Volatility3 error output, process failures |
| `DEBUG` | Verbose Volatility3 stderr |

### Log Panel

The in-GUI log panel at the bottom of the window mirrors log entries in real time with colour-coded severity. **Results > Clear Log** clears the in-GUI display; the file on disk is not affected.

---

## Theme

The header bar **☀ Light mode / 🌙 Dark mode** button toggles between two palettes. The chosen theme persists between sessions via `QSettings`.

**Dark theme** (default): Deep blue-grey backgrounds modelled after JetBrains Darcula / VS Code One Dark Pro. High-contrast readable text throughout.

**Light theme**: Clean neutral white-grey. All semantic colours (success green, warning amber, error red) adjust automatically.

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+O` | Open memory image |
| `Ctrl+Q` | Exit |
| `Ctrl+Shift+S` | Open Volshell |
| `Ctrl+Shift+M` | Open MITRE Coverage Matrix |
| `F5` | Refresh plugin list |
| `↑` / `↓` | Cycle command history in Volshell input bar |

---

## Directory Structure

After setup your repository root will look like this:

```
volatility3/
├── vol.py                      ← Volatility3 CLI
├── volshell.py                 ← Volatility3 interactive shell
├── remora.py                  ← GUI frontend (this tool)
├── requirements.txt
├── setup.py
├── volatility3/
│   ├── framework/
│   ├── plugins/
│   │   ├── windows/            ← Windows plugins
│   │   ├── linux/              ← Linux plugins
│   │   └── mac/                ← macOS plugins
│   └── symbols/
│       ├── generic/
│       └── (your .json symbol files)
└── (case directory — logs written here, alongside evidence)
```

---

## Troubleshooting

### `ERROR: PyQt5 is required`

```bash
pip install PyQt5
```

### No plugins appear in the browser

Ensure you are running `remora.py` from inside the cloned `volatility3/` directory. The script inserts its own parent directory into `sys.path` at startup, but Volatility3 must be importable from your Python environment.

### Linux/macOS plugins fail with `No symbol table`

You need a matching ISF symbol file for the target kernel. Load it via **Symbols > Linux Symbol Tables > Add Symbol Table File(s)…**

### MITRE filter shows no plugins for a technique

A small number of techniques only map to a few plugins. Try the parent technique (e.g. select `T1003` rather than `T1003.001`). Also check that plugin discovery completed — press `F5` to refresh if the list is empty.

### MITRE Coverage Matrix is empty

Plugin discovery must complete before the matrix can be opened. Wait for the status bar to show the plugin count, then try again.

### PDF export button is greyed out

```bash
pip install PyQt5        # full install usually includes print support
# On some Linux distributions:
apt install python3-pyqt5.qtprintsupport
```

### XLSX export unavailable

```bash
pip install openpyxl
```

### Volshell tab shows `Failed to start volshell.py`

Confirm `volshell.py` exists in the same directory as `remora.py` and that Volatility3's dependencies are fully installed (`pip install -r requirements.txt`).

### Log file not created

The log file is written next to the evidence image. If that directory is read-only (e.g. a mounted ISO or write-protected share), log writes silently fail to avoid crashing the GUI. Copy the image to a writable location, or check permissions.

---

## MITRE ATT&CK Mapping — Design Notes

The mapping was built with the following principles:

**1. Map what the plugin detects, not what it is.**
A plugin like `netscan` is used by the analyst. What it *detects evidence of* is adversary network activity (T1049, T1071, T1021). The mapping reflects the adversary technique, not the analyst action.

**2. Forensic infrastructure has no mapping.**
Plugins like `windows.info`, `windows.crashinfo`, `windows.statistics`, and `windows.virtmap` establish ground truth about the system. They do not detect adversary behaviour. Mapping them to T1082 (System Information Discovery) would mean "the adversary ran remora.py", which is absurd. They are intentionally absent.

**3. Confidence levels are conservative.**
A plugin gets `High` only if it was specifically engineered for that detection — `skeleton_key_check` → T1556.001 is `High`; `strings` → T1071 is `Low` because finding a C2 URI in strings output is circumstantial. When in doubt, `Medium`.

**4. Parent technique selection cascades to subtechniques.**
Selecting T1003 in the filter reveals plugins mapped to T1003, T1003.001, T1003.002, T1003.004, and T1003.005. Selecting T1003.002 shows only SAM-specific plugins. This mirrors how ATT&CK itself is structured.

**5. Known gaps.**
The following techniques are detectable only with custom Volatility3 plugins or manual VAD analysis — no native plugin maps to them currently:
- T1055.013 (Process Doppelgänging)
- T1134.003/004/005 (token impersonation subtechniques)
- T1070.001 (Clear Windows Event Logs — the artefact is in the event log, not memory)

---

## License

`remora.py` is released under the same licence as Volatility3 — see [LICENSE](LICENSE) in the repository root.

Volatility3 is copyright the Volatility Foundation and contributors.

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Technique descriptions and actor profiles are derived from the publicly available ATT&CK knowledge base.

---

*Built to complement [Volatility3](https://github.com/volatilityfoundation/volatility3) — the world's leading open-source memory forensics framework.*
