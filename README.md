# Node.js Server Killer
A simple Python script to easily find and manage Node.js servers running on your system. Useful for developers who frequently start and stop local web servers and need to clean up orphaned processes.

## Features
- 🔍 **Scan** for all running Node.js processes
- 🎯 **Terminate** individual servers or all servers at once
- 🔄 **Refresh** the server list to see current status
- 📊 **Live Monitor** running Node.js servers in real-time with automatic updates and instant kill functionality
- 🌍 **Cross-platform** support (Windows, Linux, macOS)
- 📱 **Number-based menu** for easy navigation
- 🧹 **Clean up** orphaned processes that don't appear in your terminal

## Why Use This?
When developing with Node.js, you might frequently encounter situations where:
- Servers continue running after closing the terminal
- Multiple servers are running on different ports
- You get port conflicts when starting new servers
- You need to manually hunt down processes in Task Manager or Activity Monitor

This tool solves these problems by providing a simple interface to manage all your Node.js servers in one place.

## Installation
1. Download the `stop_node_servers.py` script
2. (Optional) Place it in a directory that's in your PATH for easy access
3. Ensure you have Python 3.x installed on your system

## Usage
1. Run the script:
   ```bash
   python stop_node_servers.py
   ```
2. Use the number-based menu:
   - `1` - Terminate all Node.js processes
   - `2` - Terminate specific processes (by PID)
   - `3` - Live monitor Node.js processes (real-time view with kill options)
   - `4` - Exit the program

## Example Output
```
Node.js Process Terminator
==========================
Found running Node.js processes:
PID      Command
--------------------------------------------------
1234     node server.js
5678     node /path/to/app.js --port=3000

Options:
1. Terminate all processes
2. Terminate specific processes (by PID)
3. Live monitor processes
4. Cancel

Enter your choice (1-4): 2
Enter PIDs to terminate (comma-separated): 1234
Terminating selected processes...
Terminated 1/1 processes successfully.
```

## Requirements
- Python 3.x
- No external dependencies (uses only standard libraries)

## License
MIT License - see LICENSE file for details
