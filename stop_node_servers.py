#!/usr/bin/env python3
"""
Ghost Dev Server Killer (Windows + Linux)

Purpose:
- Detect and kill "ghost" Node dev servers left behind by `npm run dev` (often still LISTENING on a port).
- The user does NOT need to know ports: we detect Node processes that have LISTEN sockets.
- Safer than "kill all node": we target only Node-ish processes that are actually servers (LISTEN).

Key improvements vs typical scripts:
- Uses psutil for reliable cross-platform process+port discovery and killing process trees.
- Self-contained: checks for psutil at launch; if missing, asks permission to install.
- Kills process tree (parent + children) to prevent lingering workers.
- Live monitoring uses a simple line-input thread (no raw key hacks), works well in normal terminals.
"""

import os
import sys
import time
import signal
import platform
import subprocess
import threading
import queue
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ----------------------------
# Optional dependency bootstrap
# ----------------------------

def _prompt_install_psutil() -> bool:
    print("\nThis script requires the 'psutil' package for reliable port/process detection.")
    print("It can install psutil using pip.")
    ans = input("Install psutil now? [y/N]: ").strip().lower()
    return ans in ("y", "yes")

def _install_psutil() -> bool:
    try:
        cmd = [sys.executable, "-m", "pip", "install", "psutil"]
        print("\nRunning:", " ".join(cmd))
        r = subprocess.run(cmd)
        return r.returncode == 0
    except Exception as e:
        print(f"Failed to run pip: {e}")
        return False

def ensure_psutil():
    global psutil
    try:
        import psutil  # type: ignore
        return psutil
    except ImportError:
        if not _prompt_install_psutil():
            print("\nCannot continue without psutil.")
            print("Install it manually with: pip install psutil")
            sys.exit(1)
        if not _install_psutil():
            print("\npsutil installation failed.")
            print("Try manually with: pip install psutil")
            sys.exit(1)
        # Try import again
        try:
            import psutil  # type: ignore
            return psutil
        except ImportError:
            print("\nInstalled psutil but import still failed.")
            print("Try: python -m pip install --upgrade psutil")
            sys.exit(1)

psutil = ensure_psutil()


# ----------------------------
# Color handling (TTY friendly)
# ----------------------------

def _enable_windows_ansi():
    # Best-effort enable ANSI escape sequences on Windows terminals.
    if platform.system() != "Windows":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE = -11
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass

_enable_windows_ansi()

USE_COLOR = sys.stdout.isatty()

class Colors:
    if USE_COLOR:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKCYAN = '\033[96m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
    else:
        HEADER = OKBLUE = OKCYAN = OKGREEN = WARNING = FAIL = ENDC = BOLD = UNDERLINE = ""


# ----------------------------
# Header / UI helpers
# ----------------------------

def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")

def display_header():
    content_lines = [
        "Ghost Dev Server Killer (Node LISTEN detectors)",
        "https://github.com/techcow2",
        "copyright 2025 MIT License"
    ]
    max_line_length = max(len(line) for line in content_lines)
    box_width = max(max_line_length + 10, 70)

    top_border = Colors.HEADER + "╔" + "═" * (box_width) + "╗" + Colors.ENDC
    bottom_border = Colors.HEADER + "╚" + "═" * (box_width) + "╝" + Colors.ENDC
    empty_line = Colors.HEADER + "║" + " " * (box_width) + "║" + Colors.ENDC

    content_box_lines = []
    for line in content_lines:
        padding = (box_width - len(line)) // 2
        padded_line = (
            Colors.HEADER + "║" +
            " " * padding +
            Colors.BOLD + Colors.OKCYAN + line + Colors.ENDC +
            Colors.HEADER + " " * (box_width - len(line) - padding) +
            "║" + Colors.ENDC
        )
        content_box_lines.append(padded_line)

    header = "\n".join([top_border, empty_line, *content_box_lines, empty_line, bottom_border])
    print(header)


# ----------------------------
# Core detection: Node processes that are LISTENING
# ----------------------------

DEV_HINTS = (
    "vite", "next", "nuxt", "webpack", "react-scripts", "astro",
    "sveltekit", "remix", "parcel", "dev", "serve"
)

@dataclass(frozen=True)
class ListeningProc:
    pid: int
    name: str
    cmdline: str
    ports: Tuple[int, ...]
    score: int

def _safe_cmdline(p) -> str:
    try:
        cmd = " ".join(p.cmdline() or [])
        return cmd or (p.name() or "")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ""

def _is_node_process(p) -> bool:
    try:
        name = (p.name() or "").lower()
        if name in ("node", "node.exe", "nodejs"):
            return True
        cmd = _safe_cmdline(p).lower()
        # fallback: cmdline may include node even if name is weird
        return "node" in cmd
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def _score_cmdline(cmdline: str) -> int:
    s = cmdline.lower()
    hint = any(h in s for h in DEV_HINTS)
    node_modules = "node_modules" in s
    pkgmgr = (" npm " in f" {s} ") or (" pnpm " in f" {s} ") or (" yarn " in f" {s} ")
    # Higher score = more likely a dev server
    return (3 if hint else 0) + (2 if node_modules else 0) + (1 if pkgmgr else 0)

def find_listening_node_processes() -> List[ListeningProc]:
    """
    Returns Node-ish processes that have LISTEN sockets, with the ports they listen on.
    This is the primary "ghost dev server" detector.
    """
    pid_to_ports: Dict[int, set] = {}

    # net_connections can be heavy; keep it simple and robust
    for c in psutil.net_connections(kind="inet"):
        if not c.pid or not c.laddr:
            continue
        if c.status != psutil.CONN_LISTEN:
            continue
        pid_to_ports.setdefault(c.pid, set()).add(c.laddr.port)

    results: List[ListeningProc] = []
    for pid, ports in pid_to_ports.items():
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            continue

        if not _is_node_process(p):
            continue

        name = p.name() or "unknown"
        cmdline = _safe_cmdline(p)
        score = _score_cmdline(cmdline)
        results.append(
            ListeningProc(
                pid=pid,
                name=name,
                cmdline=cmdline,
                ports=tuple(sorted(int(x) for x in ports)),
                score=score,
            )
        )

    # Highest scoring (most "dev server-ish") first, then by PID
    results.sort(key=lambda x: (x.score, -x.pid), reverse=True)
    return results


# ----------------------------
# Killing: terminate process tree (graceful -> force)
# ----------------------------

def kill_process_tree(pid: int, graceful_timeout: float = 2.0) -> Dict:
    """
    Terminates pid and its children. Attempts graceful termination, then force kills remaining.
    Returns a dict compatible with the termination report below.
    """
    try:
        root = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"pid": pid, "status": "already_terminated", "message": "Process already gone"}

    # Collect tree
    try:
        procs = [root] + root.children(recursive=True)
    except psutil.Error:
        procs = [root]

    # Graceful terminate
    for p in procs:
        try:
            p.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    gone, alive = psutil.wait_procs(procs, timeout=graceful_timeout)

    # Force kill remaining
    for p in alive:
        try:
            p.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    psutil.wait_procs(alive, timeout=graceful_timeout)

    # Final check
    still_alive = []
    for p in alive:
        try:
            if p.is_running():
                still_alive.append(p.pid)
        except psutil.NoSuchProcess:
            pass

    if still_alive:
        return {"pid": pid, "status": "failed", "message": f"Still running: {still_alive}"}

    status = "success_force" if len(alive) > 0 else "success"
    return {"pid": pid, "status": status, "message": "Terminated process tree"}


# ----------------------------
# Reporting
# ----------------------------

def display_termination_report(results: List[Dict]):
    if not results:
        print(f"{Colors.WARNING}No processes were terminated.{Colors.ENDC}")
        return

    print(f"\n{Colors.BOLD}{Colors.HEADER}=== TERMINATION REPORT ==={Colors.ENDC}")

    success_count = sum(1 for r in results if r.get("status") in ("success", "success_force"))
    failed_count = sum(1 for r in results if r.get("status") in ("failed", "error"))
    already_count = sum(1 for r in results if r.get("status") == "already_terminated")

    print(f"{Colors.OKCYAN}Total targets: {len(results)}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}Successfully terminated: {success_count}{Colors.ENDC}")
    print(f"{Colors.FAIL}Failed to terminate: {failed_count}{Colors.ENDC}")
    print(f"{Colors.WARNING}Already terminated: {already_count}{Colors.ENDC}")

    successful = [r for r in results if r.get("status") in ("success", "success_force")]
    if successful:
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}SUCCESSFULLY TERMINATED:{Colors.ENDC}")
        for r in successful:
            ports = r.get("ports")
            port_display = f" ports={list(ports)}" if ports else ""
            cmd_display = f" ({r.get('command')})" if r.get("command") else ""
            how = "gracefully" if r.get("status") == "success" else "forcefully"
            print(f"{Colors.OKGREEN}  PID {r.get('pid')}{port_display}{cmd_display} - terminated {how}{Colors.ENDC}")

    failed = [r for r in results if r.get("status") in ("failed", "error")]
    if failed:
        print(f"\n{Colors.BOLD}{Colors.FAIL}FAILED TO TERMINATE:{Colors.ENDC}")
        for r in failed:
            ports = r.get("ports")
            port_display = f" ports={list(ports)}" if ports else ""
            cmd_display = f" ({r.get('command')})" if r.get("command") else ""
            print(f"{Colors.FAIL}  PID {r.get('pid')}{port_display}{cmd_display} - {r.get('message')}{Colors.ENDC}")

    already = [r for r in results if r.get("status") == "already_terminated"]
    if already:
        print(f"\n{Colors.BOLD}{Colors.WARNING}ALREADY TERMINATED:{Colors.ENDC}")
        for r in already:
            ports = r.get("ports")
            port_display = f" ports={list(ports)}" if ports else ""
            cmd_display = f" ({r.get('command')})" if r.get("command") else ""
            print(f"{Colors.WARNING}  PID {r.get('pid')}{port_display}{cmd_display} - was already terminated{Colors.ENDC}")


# ----------------------------
# Live monitoring input (line-based, cross-platform)
# ----------------------------

class LineInputHandler:
    """
    Reads full lines in a background thread (portable).
    Commands are typed then Enter.
    """
    def __init__(self):
        self.q = queue.Queue()
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while self.running:
            try:
                line = sys.stdin.readline()
                if not line:
                    # stdin closed
                    self.running = False
                    break
                self.q.put(line.strip())
            except Exception:
                self.running = False
                break

    def start(self):
        self.thread.start()

    def stop(self):
        self.running = False

    def get_command(self) -> Optional[str]:
        try:
            return self.q.get_nowait()
        except queue.Empty:
            return None


# ----------------------------
# Live monitoring mode
# ----------------------------

def live_monitoring_mode():
    refresh_interval = 2.0
    last_refresh = 0.0
    message = ""
    message_time = 0.0

    input_handler = LineInputHandler()
    input_handler.start()

    known_pids = set()

    try:
        while True:
            now = time.time()
            cmd = input_handler.get_command()

            if cmd:
                if cmd == "q":
                    print(f"{Colors.WARNING}Exiting live monitoring mode.{Colors.ENDC}")
                    break
                elif cmd == "h":
                    message = (
                        f"{Colors.OKCYAN}Commands: k (kill all), k <pid>, r (refresh), h (help), q (quit){Colors.ENDC}"
                    )
                    message_time = now
                elif cmd == "r":
                    message = f"{Colors.OKBLUE}Refreshing...{Colors.ENDC}"
                    message_time = now
                    last_refresh = 0.0
                elif cmd == "k":
                    procs = find_listening_node_processes()
                    if not procs:
                        message = f"{Colors.WARNING}No listening Node processes found.{Colors.ENDC}"
                        message_time = now
                    else:
                        # Safety: require confirmation if many
                        if len(procs) >= 3:
                            print(f"\n{Colors.WARNING}About to kill {len(procs)} listening Node processes.{Colors.ENDC}")
                            confirm = input("Type KILL to confirm: ").strip()
                            if confirm != "KILL":
                                message = f"{Colors.WARNING}Cancelled.{Colors.ENDC}"
                                message_time = now
                                continue

                        results = []
                        for p in procs:
                            res = kill_process_tree(p.pid)
                            res["command"] = p.cmdline
                            res["ports"] = p.ports
                            results.append(res)
                            if res["status"] in ("success", "success_force", "already_terminated"):
                                known_pids.discard(p.pid)

                        clear_screen()
                        display_header()
                        print(f"\n{Colors.BOLD}{Colors.HEADER}=== LIVE MONITORING MODE ==={Colors.ENDC}")
                        display_termination_report(results)
                        print(f"\n{Colors.OKCYAN}Press Enter to continue monitoring...{Colors.ENDC}")
                        # Wait for a line (any) to continue
                        sys.stdin.readline()
                        last_refresh = 0.0
                        continue
                elif cmd.startswith("k "):
                    target = cmd[2:].strip()
                    try:
                        pid = int(target)
                    except ValueError:
                        message = f"{Colors.FAIL}Invalid PID: {target}{Colors.ENDC}"
                        message_time = now
                        continue

                    # Validate PID is in current listening list (safer)
                    procs = find_listening_node_processes()
                    pid_map = {p.pid: p for p in procs}
                    if pid not in pid_map:
                        message = f"{Colors.FAIL}PID {pid} is not a detected listening Node process right now.{Colors.ENDC}"
                        message_time = now
                        continue

                    p = pid_map[pid]
                    res = kill_process_tree(pid)
                    res["command"] = p.cmdline
                    res["ports"] = p.ports

                    clear_screen()
                    display_header()
                    print(f"\n{Colors.BOLD}{Colors.HEADER}=== LIVE MONITORING MODE ==={Colors.ENDC}")
                    display_termination_report([res])
                    print(f"\n{Colors.OKCYAN}Press Enter to continue monitoring...{Colors.ENDC}")
                    sys.stdin.readline()
                    last_refresh = 0.0
                    continue
                else:
                    message = f"{Colors.FAIL}Unknown command. Type 'h' for help.{Colors.ENDC}"
                    message_time = now

            if now - last_refresh >= refresh_interval:
                clear_screen()
                display_header()

                procs = find_listening_node_processes()
                current_pids = {p.pid for p in procs}

                new_pids = current_pids - known_pids
                gone_pids = known_pids - current_pids

                known_pids = current_pids

                print(f"\n{Colors.BOLD}{Colors.HEADER}=== LIVE MONITORING MODE ==={Colors.ENDC}")
                print(f"{Colors.OKCYAN}Detected {len(procs)} listening Node process(es){Colors.ENDC}")

                if message and (now - message_time) < 5:
                    print(f"\n{message}")

                if new_pids:
                    print(f"\n{Colors.BOLD}{Colors.OKGREEN}NEW LISTENING NODE PROCESSES:{Colors.ENDC}")
                    for pid in sorted(new_pids):
                        print(f"{Colors.OKGREEN}  PID {pid}{Colors.ENDC}")

                if gone_pids:
                    print(f"\n{Colors.BOLD}{Colors.FAIL}NO LONGER LISTENING / TERMINATED:{Colors.ENDC}")
                    for pid in sorted(gone_pids):
                        print(f"{Colors.FAIL}  PID {pid}{Colors.ENDC}")

                print(f"\n{Colors.BOLD}{Colors.OKBLUE}CURRENT LISTENING NODE PROCESSES:{Colors.ENDC}")
                print(f"{Colors.OKCYAN}{'PID':<8} {'Ports':<18} {'Score':<6} {'Command'}{Colors.ENDC}")
                print(f"{Colors.OKCYAN}{'-' * 90}{Colors.ENDC}")

                if not procs:
                    print(f"{Colors.WARNING}No listening Node processes found.{Colors.ENDC}")
                else:
                    for p in procs:
                        ports_str = ",".join(str(x) for x in p.ports)
                        cmd = p.cmdline
                        if len(cmd) > 60:
                            cmd = cmd[:60] + "..."
                        print(f"{Colors.OKCYAN}{p.pid:<8} {ports_str:<18} {p.score:<6} {cmd}{Colors.ENDC}")

                print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.ENDC}")
                print(f"{Colors.BOLD}{Colors.OKCYAN}COMMANDS:{Colors.ENDC}")
                print(f"{Colors.OKCYAN}  k           - {Colors.WARNING}Kill ALL listening Node processes (ghost dev servers){Colors.ENDC}")
                print(f"{Colors.OKCYAN}  k <pid>     - {Colors.WARNING}Kill ONE PID (must be listed){Colors.ENDC}")
                print(f"{Colors.OKCYAN}  r           - {Colors.OKBLUE}Refresh now{Colors.ENDC}")
                print(f"{Colors.OKCYAN}  h           - {Colors.OKBLUE}Help{Colors.ENDC}")
                print(f"{Colors.OKCYAN}  q           - {Colors.WARNING}Quit monitoring{Colors.ENDC}")
                print(f"{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.ENDC}")
                print(f"\n{Colors.BOLD}Enter command then press Enter: {Colors.ENDC}", end="", flush=True)

                last_refresh = now

            time.sleep(0.1)

    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Exiting live monitoring mode.{Colors.ENDC}")
    finally:
        input_handler.stop()


# ----------------------------
# Main menu
# ----------------------------

def main():
    clear_screen()
    display_header()

    print(f"\n{Colors.BOLD}{Colors.OKCYAN}Ghost Dev Server Killer{Colors.ENDC}")
    print(f"{Colors.OKCYAN}- Detects Node processes that are actually LISTENING (likely dev servers){Colors.ENDC}")
    print(f"{Colors.OKCYAN}- Kills process trees to eliminate true 'ghosts'{Colors.ENDC}")

    procs = find_listening_node_processes()

    if not procs:
        print(f"\n{Colors.WARNING}No listening Node processes found right now.{Colors.ENDC}")
    else:
        print(f"\n{Colors.BOLD}{Colors.OKBLUE}Listening Node processes (possible dev servers):{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{'PID':<8} {'Ports':<18} {'Score':<6} {'Command'}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{'-' * 90}{Colors.ENDC}")
        for p in procs:
            ports_str = ",".join(str(x) for x in p.ports)
            cmd = p.cmdline
            if len(cmd) > 60:
                cmd = cmd[:60] + "..."
            print(f"{Colors.OKCYAN}{p.pid:<8} {ports_str:<18} {p.score:<6} {cmd}{Colors.ENDC}")

    print(f"\n{Colors.BOLD}{Colors.HEADER}Options:{Colors.ENDC}")
    print(f"{Colors.OKCYAN}1. {Colors.WARNING}Terminate ALL listening Node processes (ghost dev servers){Colors.ENDC}")
    print(f"{Colors.OKCYAN}2. {Colors.WARNING}Terminate specific processes (by PID, from the list){Colors.ENDC}")
    print(f"{Colors.OKCYAN}3. {Colors.OKBLUE}Live monitoring mode{Colors.ENDC}")
    print(f"{Colors.OKCYAN}4. {Colors.WARNING}Cancel{Colors.ENDC}")

    choice = input(f"\n{Colors.BOLD}Enter your choice (1-4): {Colors.ENDC}").strip()

    if choice == "1":
        if not procs:
            print(f"\n{Colors.WARNING}No listening Node processes to terminate.{Colors.ENDC}")
            return

        # Safety confirmation if many targets
        if len(procs) >= 3:
            print(f"\n{Colors.WARNING}About to kill {len(procs)} listening Node processes.{Colors.ENDC}")
            confirm = input("Type KILL to confirm: ").strip()
            if confirm != "KILL":
                print(f"\n{Colors.WARNING}Cancelled.{Colors.ENDC}")
                return

        print(f"\n{Colors.WARNING}Terminating listening Node processes (process trees)...{Colors.ENDC}")
        results = []
        for p in procs:
            res = kill_process_tree(p.pid)
            res["command"] = p.cmdline
            res["ports"] = p.ports
            results.append(res)

        display_termination_report(results)

    elif choice == "2":
        if not procs:
            print(f"\n{Colors.WARNING}No listening Node processes to terminate.{Colors.ENDC}")
            return

        pid_map = {p.pid: p for p in procs}
        pids_input = input(f"\n{Colors.BOLD}Enter PID(s) to terminate (comma-separated): {Colors.ENDC}").strip()
        selected = [x.strip() for x in pids_input.split(",") if x.strip()]

        if not selected:
            print(f"{Colors.FAIL}No valid PIDs entered.{Colors.ENDC}")
            return

        results = []
        for s in selected:
            try:
                pid = int(s)
            except ValueError:
                results.append({"pid": s, "status": "error", "message": "Not an integer PID"})
                continue

            if pid not in pid_map:
                results.append({"pid": pid, "status": "not_found", "message": "PID not in current listening Node list"})
                continue

            p = pid_map[pid]
            res = kill_process_tree(pid)
            res["command"] = p.cmdline
            res["ports"] = p.ports
            results.append(res)

        display_termination_report(results)

    elif choice == "3":
        live_monitoring_mode()

    elif choice == "4":
        print(f"\n{Colors.WARNING}Operation cancelled.{Colors.ENDC}")
        return
    else:
        print(f"\n{Colors.FAIL}Invalid choice. Operation cancelled.{Colors.ENDC}")
        return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Operation cancelled by user.{Colors.ENDC}")
        sys.exit(0)
