# Node.js Server Killer

A lightweight Python script to find and stop running Node.js servers (including orphaned processes) on Windows, macOS, and Linux.

## Features
- Scan all running Node.js processes
- Kill one or all processes (by PID)
- Live monitoring with auto-refresh + instant kill
- Simple number-based menu
- No dependencies (standard library only)

## Installation
1. Download `stop_node_servers.py`
2. Make sure Python 3.x is installed
3. (Optional) Add the script to your PATH

## Usage
```bash
python stop_node_servers.py
````

Menu:

* `1` Kill all Node.js processes
* `2` Kill selected PIDs
* `3` Live monitor (real-time view + kill options)
* `4` Exit

## Requirements

* Python 3.x

## License

MIT — see `LICENSE`
