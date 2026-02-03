# Ghost Dev Server Killer (Node.js Server Killer v2)

A lightweight Python tool to **detect and terminate “ghost” Node.js dev servers** (e.g. `npm run dev` processes left behind after closing VS Code, crashes, or failed hot reloads).

Unlike v1 (which scanned *all* Node processes), **v2 focuses on the real problem**: Node processes that are still **LISTENING on a port** (i.e. still running a dev server).

---

## What’s New in v2 

### ✅ Smarter detection (no more guessing ports)
v2 automatically finds Node processes that are **actively listening on network ports**, which is what causes the classic issues:

- `EADDRINUSE: address already in use`
- “Port 3000 / 5173 already in use”
- Dev server still accessible even after the terminal/editor was closed

You do **not** need to know what port the server was using — v2 detects it for you.

### ✅ Much safer than “kill all node”
v1 could kill unrelated Node processes (tooling, language servers, other projects).

v2 targets only:
- Node-ish processes (`node`, `node.exe`, `nodejs`)
- that have **LISTEN sockets** (server processes)

### ✅ Kills the whole process tree
`npm run dev` often spawns child processes. Killing only the parent PID can leave zombie workers behind.

v2 terminates:
- the target PID
- **all child processes (recursive)**

First it attempts graceful termination, then force kills remaining processes if needed.

### ✅ Better Windows support
v2 uses proper process inspection (including ports and process trees), making it much more reliable on Windows.

### ✅ Live monitoring improvements
Live mode continuously updates the list of detected listening Node processes, and supports instant kill commands.

### ✅ Self-contained dependency handling
v2 is still easy to run:
- it detects if `psutil` is installed at launch
- if missing, it **asks permission** to install it automatically via pip

---

## Features

- Detect Node.js dev servers by **LISTEN ports**
- Show PID + listening ports + command line
- Kill one process or all detected dev servers
- Kill **process trees** (prevents true ghost servers)
- Live monitoring mode with auto-refresh
- Cross-platform: **Windows + Linux**
- Self-contained installer prompt for dependency

---

## Installation

### Option A — Download
1. Download `stop_node_servers.py`
2. Ensure Python 3.x is installed
3. Run it

### Option B — Clone
```bash
git clone https://github.com/techcow2/<repo>.git
cd <repo>
python stop_node_servers.py
````

---

## Requirements

* Python 3.x

### Dependency (v2)

* `psutil`

> The script will prompt to install `psutil` automatically if it is missing.

Manual install:

```bash
pip install psutil
```

---

## Usage

```bash
python stop_node_servers.py
```

### Menu Options

* `1` Terminate **ALL listening Node processes** (ghost dev servers)
* `2` Terminate selected PIDs (from detected listening list)
* `3` Live monitoring mode
* `4` Exit

---

## Live Monitoring Commands

In live mode, type commands and press Enter:

* `k` → kill all detected listening Node processes
* `k <pid>` → kill one PID (must be listed)
* `r` → refresh immediately
* `h` → help
* `q` → quit live mode

---

## Why this tool exists

When developing with Node frameworks like:

* Vite
* Next.js / Nuxt
* Webpack / React scripts
* Astro / SvelteKit / Remix

it’s common for dev servers to get orphaned. This tool solves that cleanly by focusing on **what matters**: servers that are still listening.

---

## License

MIT — see `LICENSE`
