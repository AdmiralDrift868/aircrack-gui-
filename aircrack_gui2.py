#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import subprocess
import threading
import os
import re
import time
import json
import tempfile
import shutil
import csv
import sys
from datetime import datetime

# Optional: Only import matplotlib if available
try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class AircrackGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Aircrack-ng GUI - Ethical Hacking Suite (Run as ROOT)")
        self.root.geometry("1150x900")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # State
        self.config_file = os.path.expanduser("~/.aircrack-ng-gui.json")
        self.scan_history_file = os.path.expanduser("~/.aircrack-ng-scans.json")
        self.load_config()
        self.active_processes = []  # List of (proc, description)
        self.proc_lock = threading.Lock()
        self.scan_dir = None
        self.packet_counts = {}
        self.capture_process = None
        self.capture_file_base = None

        # Main layout
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.notebook = notebook  # store reference for later use

        # Create tabs
        self.create_main_tab(notebook)
        self.create_networks_tab(notebook)
        self.create_clients_tab(notebook)
        self.create_wps_tab(notebook)
        if MATPLOTLIB_AVAILABLE:
            self.create_graphs_tab(notebook)
        self.create_telemetry_tab(notebook)

        # Status bar
        self.status_var = tk.StringVar(value="READY - Run as ROOT for full functionality")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=11, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))

        # Grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)

        self.load_saved_config()
        self.load_scan_history()

    # ======================
    # THREAD / UI HELPERS
    # ======================
    def run_on_main(self, func, *args, **kwargs):
        """Schedule a callable to run on the Tk main thread."""
        try:
            self.root.after(0, lambda: func(*args, **kwargs))
        except Exception:
            # As a fallback, try calling directly (should rarely happen)
            try:
                func(*args, **kwargs)
            except Exception as e:
                print("run_on_main error:", e, file=sys.stderr)

    def show_messagebox(self, kind, title, message):
        """Schedule a messagebox on the main thread."""
        def _show():
            try:
                if kind == "info":
                    messagebox.showinfo(title, message)
                elif kind == "warning":
                    messagebox.showwarning(title, message)
                elif kind == "error":
                    messagebox.showerror(title, message)
                else:
                    messagebox.showinfo(title, message)
            except Exception as e:
                # If messagebox fails (headless), fallback to printing
                print(f"{title}: {message} ({e})", file=sys.stderr)
        self.run_on_main(_show)

    # ======================
    # VALIDATION HELPERS
    # ======================
    def is_valid_interface(self, name):
        return name and re.match(r'^[a-zA-Z0-9@._:-]+$', name) and len(name) <= 64

    def is_valid_mac(self, mac):
        if not mac:
            return False
        return re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac.strip()) is not None

    def is_valid_channel(self, ch):
        if not ch:
            return False
        return ch.isdigit() and 1 <= int(ch) <= 165

    def is_valid_file_path(self, path):
        return bool(path and os.path.isfile(path))

    def is_valid_dir_path(self, path):
        return bool(path and os.path.isdir(path))

    def is_safe_path(self, path):
        """Prevent path traversal in exports. Ensure resolved path is contained in allowed roots."""
        try:
            resolved = os.path.realpath(path)
            allowed = [
                os.path.realpath(os.path.expanduser("~")),
                os.path.realpath("/tmp"),
                os.path.realpath("/root")
            ]
            for a in allowed:
                try:
                    if os.path.commonpath([resolved, a]) == a:
                        return True
                except ValueError:
                    continue
            return False
        except Exception:
            return False

    # ======================
    # CONFIG & HISTORY
    # ======================
    def load_config(self):
        default_config = {
            "interface": "",
            "wordlist": "",
            "capture_file": "",
            "output_dir": os.path.expanduser("~/aircrack-output")
        }
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.config = {**default_config, **config}
            except Exception:
                self.config = default_config
        else:
            self.config = default_config

    def save_config(self):
        config = {
            "interface": getattr(self, "interface_var", tk.StringVar()).get(),
            "wordlist": getattr(self, "wordlist_var", tk.StringVar()).get(),
            "capture_file": getattr(self, "capture_var", tk.StringVar()).get(),
            "output_dir": getattr(self, "outdir_var", tk.StringVar()).get()
        }
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass

    def load_scan_history(self):
        self.scan_history = []
        if os.path.exists(self.scan_history_file):
            try:
                with open(self.scan_history_file, 'r') as f:
                    self.scan_history = json.load(f)
            except Exception:
                pass

    def save_scan_history(self):
        try:
            with open(self.scan_history_file, 'w') as f:
                json.dump(self.scan_history, f, indent=2)
        except Exception:
            pass

    def add_to_scan_history(self, network):
        # Avoid unbounded duplicates: only append if new bssid or different timestamp
        if not any(n.get("bssid") == network.get("bssid") for n in self.scan_history[-100:]):
            network["timestamp"] = datetime.now().isoformat()
            self.scan_history.append(network)
            # keep history bounded
            self.scan_history = self.scan_history[-1000:]
            self.save_scan_history()

    def load_saved_config(self):
        # Ensure the UI variables exist
        try:
            self.interface_var.set(self.config["interface"])
            self.wordlist_var.set(self.config["wordlist"])
            self.capture_var.set(self.config["capture_file"])
            self.outdir_var.set(self.config["output_dir"])
        except Exception:
            pass

    def on_closing(self):
        self.stop_all_processes()
        if self.scan_dir and os.path.exists(self.scan_dir):
            shutil.rmtree(self.scan_dir, ignore_errors=True)
        self.save_config()
        self.root.destroy()

    def stop_all_processes(self):
        """Terminate all active subprocesses"""
        with self.proc_lock:
            procs = list(self.active_processes)
        for proc, desc in procs:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            # remove from active_processes
            with self.proc_lock:
                try:
                    self.active_processes.remove((proc, desc))
                except ValueError:
                    pass
        # Also try capture_process cleanup
        if self.capture_process:
            try:
                self.capture_process.terminate()
                self.capture_process.wait(timeout=2)
            except Exception:
                try:
                    self.capture_process.kill()
                except Exception:
                    pass
            self.capture_process = None
        self.status_var.set("READY")

    # ======================
    # TAB CREATION
    # ======================
    def create_main_tab(self, notebook):
        main_tab = ttk.Frame(notebook, padding="10")
        notebook.add(main_tab, text="Main")

        # Interface
        ttk.Label(main_tab, text="Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.interface_var = tk.StringVar()
        ttk.Entry(main_tab, textvariable=self.interface_var, width=20).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        ttk.Button(main_tab, text="Detect Interfaces", command=self.detect_interfaces).grid(row=0, column=2, padx=(5, 0))

        # BSSID
        ttk.Label(main_tab, text="Target BSSID:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.bssid_var = tk.StringVar()
        ttk.Entry(main_tab, textvariable=self.bssid_var, width=20).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))

        # Channel
        ttk.Label(main_tab, text="Channel:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.channel_var = tk.StringVar()
        ttk.Entry(main_tab, textvariable=self.channel_var, width=20).grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))

        # Wordlist
        ttk.Label(main_tab, text="Wordlist:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.wordlist_var = tk.StringVar()
        ttk.Entry(main_tab, textvariable=self.wordlist_var, width=50).grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        ttk.Button(main_tab, text="Browse", command=self.browse_wordlist).grid(row=3, column=2, padx=(5, 0))

        # Capture File
        ttk.Label(main_tab, text="Capture File:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.capture_var = tk.StringVar()
        ttk.Entry(main_tab, textvariable=self.capture_var, width=50).grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        ttk.Button(main_tab, text="Browse", command=self.browse_capture).grid(row=4, column=2, padx=(5, 0))

        # Output Dir
        ttk.Label(main_tab, text="Output Dir:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.outdir_var = tk.StringVar(value=os.path.expanduser("~/aircrack-output"))
        ttk.Entry(main_tab, textvariable=self.outdir_var, width=50).grid(row=5, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        ttk.Button(main_tab, text="Browse", command=self.browse_outdir).grid(row=5, column=2, padx=(5, 0))

        # NetworkManager Control
        nm_frame = ttk.LabelFrame(main_tab, text="NetworkManager Control", padding="5")
        nm_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        ttk.Button(nm_frame, text="Check Status", command=self.check_network_manager_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(nm_frame, text="Stop NM", command=self.stop_network_manager).pack(side=tk.LEFT, padx=5)
        ttk.Button(nm_frame, text="Start NM", command=self.start_network_manager).pack(side=tk.LEFT, padx=5)
        ttk.Button(nm_frame, text="Kill Conflicts", command=self.kill_conflicts).pack(side=tk.LEFT, padx=5)
        ttk.Button(nm_frame, text="Check Interface", command=self.check_interface_status).pack(side=tk.LEFT, padx=5)

        # Main Buttons
        btn_frame = ttk.Frame(main_tab)
        btn_frame.grid(row=7, column=0, columnspan=3, pady=10)
        ttk.Button(btn_frame, text="Monitor Mode", command=self.monitor_mode).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Stop Monitor", command=self.stop_monitor).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Scan Networks", command=self.scan_networks).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Deauth Attack", command=self.deauth_attack).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Stop Attack", command=self.stop_attack).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Crack WPA", command=self.crack_wpa).pack(side=tk.LEFT, padx=5)

        # Capture Control
        cap_frame = ttk.LabelFrame(main_tab, text="Capture Control", padding="5")
        cap_frame.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        ttk.Button(cap_frame, text="Start Capture", command=self.start_capture).pack(side=tk.LEFT, padx=5)
        ttk.Button(cap_frame, text="Stop Capture", command=self.stop_capture).pack(side=tk.LEFT, padx=5)
        self.capture_status_var = tk.StringVar(value="Not capturing")
        ttk.Label(cap_frame, textvariable=self.capture_status_var).pack(side=tk.LEFT, padx=10)

        # Advanced Options
        adv_frame = ttk.LabelFrame(main_tab, text="Advanced", padding="5")
        adv_frame.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        self.essid_var = tk.StringVar()
        ttk.Label(adv_frame, text="ESSID:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(adv_frame, textvariable=self.essid_var, width=20).grid(row=0, column=1, padx=5)
        self.target_ap_var = tk.StringVar()
        ttk.Label(adv_frame, text="AP MAC:").grid(row=0, column=2, sticky=tk.W)
        ap_entry = ttk.Entry(adv_frame, textvariable=self.target_ap_var, width=20)
        ap_entry.grid(row=0, column=3, padx=5)
        self.target_ap_var.trace('w', lambda *a: self.bssid_var.set(self.target_ap_var.get()))
        self.client_mac_var = tk.StringVar()
        ttk.Label(adv_frame, text="Client MAC:").grid(row=0, column=4, sticky=tk.W)
        ttk.Entry(adv_frame, textvariable=self.client_mac_var, width=20).grid(row=0, column=5, padx=5)

        # Output
        out_frame = ttk.LabelFrame(main_tab, text="Output", padding="5")
        out_frame.grid(row=10, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        self.output_text = scrolledtext.ScrolledText(out_frame, height=10, state=tk.DISABLED)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Button(main_tab, text="Clear Output", command=self.clear_output).grid(row=11, column=0, columnspan=3, pady=5)

        # Grid config
        main_tab.columnconfigure(1, weight=1)
        main_tab.rowconfigure(10, weight=1)
        out_frame.columnconfigure(0, weight=1)
        out_frame.rowconfigure(0, weight=1)

    def create_networks_tab(self, notebook):
        networks_tab = ttk.Frame(notebook, padding="10")
        notebook.add(networks_tab, text="Networks")

        # Search
        search_frame = ttk.Frame(networks_tab)
        search_frame.pack(fill=tk.X, pady=5)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.network_search_var = tk.StringVar()
        self.network_search_var.trace('w', self.filter_networks)
        ttk.Entry(search_frame, textvariable=self.network_search_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Treeview
        cols = ('BSSID', 'Channel', 'Power', 'Privacy', 'Cipher', 'Auth', 'ESSID')
        self.network_tree = ttk.Treeview(networks_tab, columns=cols, show='headings', height=12)
        widths = {'BSSID':130, 'Channel':60, 'Power':60, 'Privacy':80, 'Cipher':80, 'Auth':100, 'ESSID':180}
        for col in cols:
            self.network_tree.heading(col, text=col)
            self.network_tree.column(col, width=widths[col])

        v_scroll = ttk.Scrollbar(networks_tab, orient=tk.VERTICAL, command=self.network_tree.yview)
        h_scroll = ttk.Scrollbar(networks_tab, orient=tk.HORIZONTAL, command=self.network_tree.xview)
        self.network_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        self.network_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        # Buttons
        btn_frame = ttk.Frame(networks_tab)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="Select Network", command=self.select_network).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Export Selected", command=self.export_selected_networks).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Export All", command=self.export_all_networks).pack(side=tk.LEFT, padx=5)

    def create_clients_tab(self, notebook):
        clients_tab = ttk.Frame(notebook, padding="10")
        notebook.add(clients_tab, text="Clients")

        cols = ('Station MAC', 'Power', 'Packets', 'BSSID', 'Probed ESSIDs')
        self.client_tree = ttk.Treeview(clients_tab, columns=cols, show='headings', height=12)
        widths = {'Station MAC':130, 'Power':60, 'Packets':80, 'BSSID':130, 'Probed ESSIDs':200}
        for col in cols:
            self.client_tree.heading(col, text=col)
            self.client_tree.column(col, width=widths[col])

        v_scroll = ttk.Scrollbar(clients_tab, orient=tk.VERTICAL, command=self.client_tree.yview)
        h_scroll = ttk.Scrollbar(clients_tab, orient=tk.HORIZONTAL, command=self.client_tree.xview)
        self.client_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        self.client_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        ttk.Button(clients_tab, text="Select Client", command=self.select_client).pack(pady=5)

    def create_wps_tab(self, notebook):
        wps_tab = ttk.Frame(notebook, padding="10")
        notebook.add(wps_tab, text="WPS Attacks")

        reaver_installed = shutil.which("reaver") is not None
        bully_installed = shutil.which("bully") is not None

        # Target
        ttk.Label(wps_tab, text="Target BSSID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.wps_bssid_var = tk.StringVar()
        ttk.Entry(wps_tab, textvariable=self.wps_bssid_var, width=20).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(wps_tab, text="Interface:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.wps_interface_var = tk.StringVar()
        ttk.Entry(wps_tab, textvariable=self.wps_interface_var, width=20).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(wps_tab, text="Channel:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.wps_channel_var = tk.StringVar()
        ttk.Entry(wps_tab, textvariable=self.wps_channel_var, width=20).grid(row=2, column=1, padx=5, pady=5)

        # Options
        opt_frame = ttk.LabelFrame(wps_tab, text="Options", padding=5)
        opt_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        self.wps_delay_var = tk.IntVar(value=0)
        ttk.Checkbutton(opt_frame, text="Delay (1s)", variable=self.wps_delay_var).grid(row=0, column=0, sticky=tk.W)
        self.wps_pixie_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="Pixie-Dust", variable=self.wps_pixie_var).grid(row=0, column=1, sticky=tk.W)

        # Buttons
        btn_frame = ttk.Frame(wps_tab)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=10)
        if reaver_installed:
            ttk.Button(btn_frame, text="Reaver Attack", command=self.reaver_attack).pack(side=tk.LEFT, padx=5)
        else:
            ttk.Button(btn_frame, text="Reaver (Not Installed)", state=tk.DISABLED).pack(side=tk.LEFT, padx=5)
        if bully_installed:
            ttk.Button(btn_frame, text="Bully Attack", command=self.bully_attack).pack(side=tk.LEFT, padx=5)
        else:
            ttk.Button(btn_frame, text="Bully (Not Installed)", state=tk.DISABLED).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Stop WPS Attack", command=self.stop_wps_attack).pack(side=tk.LEFT, padx=5)

        # Output
        out_frame = ttk.LabelFrame(wps_tab, text="WPS Output", padding=5)
        out_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        self.wps_output = scrolledtext.ScrolledText(out_frame, height=12, state=tk.DISABLED)
        self.wps_output.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Button(out_frame, text="Clear", command=self.clear_wps_output).grid(row=1, column=0, pady=5)
        out_frame.columnconfigure(0, weight=1)
        out_frame.rowconfigure(0, weight=1)

        wps_tab.columnconfigure(1, weight=1)
        wps_tab.rowconfigure(5, weight=1)

    def create_graphs_tab(self, notebook):
        if not MATPLOTLIB_AVAILABLE:
            return
        graphs_tab = ttk.Frame(notebook, padding="10")
        notebook.add(graphs_tab, text="Packet Graphs")
        self.fig = Figure(figsize=(10, 6), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("Beacon Frames per Network (Last Scan)")
        self.ax.set_xlabel("BSSID")
        self.ax.set_ylabel("Packet Count")
        self.ax.tick_params(axis='x', rotation=45)
        self.canvas = FigureCanvasTkAgg(self.fig, graphs_tab)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def create_telemetry_tab(self, notebook):
        telemetry_tab = ttk.Frame(notebook, padding="10")
        notebook.add(telemetry_tab, text="Telemetry")
        btns = [
            ("Check Tools", self.check_aircrack_tools),
            ("Wireless Status", self.check_wireless_status),
            ("List Conflicts", self.list_conflicts),
            ("Monitor Mode", self.check_monitor_mode),
            ("System Info", self.system_info),
            ("Hardware Monitor", self.check_hardware_monitor),
            ("Driver Info", self.driver_info),
            ("Chipset Detect", self.chipset_detect),
        ]
        for i, (text, cmd) in enumerate(btns):
            ttk.Button(telemetry_tab, text=text, command=cmd).grid(row=i, column=0, sticky=tk.W, pady=2)

    # ======================
    # FILE OPERATIONS
    # ======================
    def browse_outdir(self):
        d = filedialog.askdirectory(initialdir=os.path.expanduser("~/"))
        if d: self.outdir_var.set(d)

    def browse_wordlist(self):
        f = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if f: self.wordlist_var.set(f)

    def browse_capture(self):
        f = filedialog.askopenfilename(filetypes=[("Capture files", "*.cap *.pcap"), ("All files", "*.*")])
        if f: self.capture_var.set(f)

    # ======================
    # SAFE COMMAND EXECUTION (NO PKEXEC)
    # ======================
    def run_command(self, args_list, description="Command", timeout=300, output_widget=None, capture_output=True):
        """Run command directly (app must be run as root). All UI updates are scheduled on the main thread."""
        if not isinstance(args_list, list):
            raise ValueError("args_list must be a list")

        def execute():
            proc = None
            try:
                self.run_on_main(self.status_var.set, f"Running: {description}...")
                stdout_pipe = subprocess.PIPE if capture_output else None
                stderr_pipe = subprocess.PIPE if capture_output else None
                text_mode = True if capture_output else False

                proc = subprocess.Popen(
                    args_list,
                    stdout=stdout_pipe,
                    stderr=stderr_pipe,
                    text=text_mode
                )
                with self.proc_lock:
                    self.active_processes.append((proc, description))

                if capture_output:
                    try:
                        stdout, stderr = proc.communicate(timeout=timeout)
                        returncode = proc.returncode
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        stdout, stderr = proc.communicate()
                        returncode = -1
                    finally:
                        # remove proc from active_processes
                        with self.proc_lock:
                            try:
                                self.active_processes.remove((proc, description))
                            except ValueError:
                                pass
                        self.run_on_main(self.status_var.set, "READY")

                    output = stdout if returncode == 0 else f"[ERROR] {stderr}"
                    # schedule write
                    self.run_on_main(self._write_output, output, output_widget)
                else:
                    # long-running process: set capture_process and spawn monitor to cleanup on exit
                    self.capture_process = proc
                    self.run_on_main(self.capture_status_var.set, f"Capturing to {self.capture_file_base}...")
                    # Monitor thread to wait for process exit and cleanup state
                    def monitor():
                        try:
                            proc.wait()
                        except Exception:
                            pass
                        # cleanup
                        with self.proc_lock:
                            try:
                                self.active_processes.remove((proc, description))
                            except ValueError:
                                pass
                        if self.capture_process is proc:
                            self.capture_process = None
                        self.run_on_main(self.capture_status_var.set, "Capture stopped")
                        self.run_on_main(self.status_var.set, "READY")
                        # attempt to auto-fill capture file on main thread
                        cap_file = None
                        try:
                            cap_file = self.capture_file_base + "-01.cap"
                            if cap_file and os.path.exists(cap_file):
                                self.run_on_main(self.capture_var.set, cap_file)
                                self.run_on_main(self._write_output, f"Capture saved to {cap_file}\n", None)
                        except Exception:
                            pass

                    threading.Thread(target=monitor, daemon=True).start()

            except Exception as e:
                self.run_on_main(self.status_var.set, "READY")
                msg = f"[EXCEPTION] {description}: {str(e)}\n"
                self.run_on_main(self._write_output, msg, output_widget)
                # ensure removal
                if proc:
                    with self.proc_lock:
                        try:
                            self.active_processes.remove((proc, description))
                        except ValueError:
                            pass

        threading.Thread(target=execute, daemon=True).start()

    def _write_output(self, text, output_widget=None):
        formatted = f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n"
        try:
            if output_widget:
                output_widget.config(state=tk.NORMAL)
                output_widget.insert(tk.END, formatted)
                output_widget.see(tk.END)
                output_widget.config(state=tk.DISABLED)
            else:
                self.output_text.config(state=tk.NORMAL)
                self.output_text.insert(tk.END, formatted)
                self.output_text.see(tk.END)
                self.output_text.config(state=tk.DISABLED)
        except Exception:
            # fallback print
            print(formatted)

    def update_output(self, text):
        # ensure UI update happens on main thread
        self.run_on_main(self._write_output, text, None)

    def clear_output(self):
        try:
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete(1.0, tk.END)
            self.output_text.config(state=tk.DISABLED)
        except Exception:
            pass

    def clear_wps_output(self):
        try:
            self.wps_output.config(state=tk.NORMAL)
            self.wps_output.delete(1.0, tk.END)
            self.wps_output.config(state=tk.DISABLED)
        except Exception:
            pass

    # ======================
    # EXPORT FUNCTIONALITY
    # ======================
    def export_selected_networks(self):
        selected = self.network_tree.selection()
        if not selected:
            self.show_messagebox("warning", "Export", "No networks selected.")
            return
        self._export_networks([self.network_tree.item(i, 'values') for i in selected], "selected_networks")

    def export_all_networks(self):
        all_items = self.network_tree.get_children()
        if not all_items:
            self.show_messagebox("warning", "Export", "No networks to export.")
            return
        data = [self.network_tree.item(i, 'values') for i in all_items]
        self._export_networks(data, "all_networks")

    def _export_networks(self, data, base_name):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"{base_name}_{timestamp}"

        # CSV
        csv_file = filedialog.asksaveasfilename(
            title="Save as CSV",
            defaultextension=".csv",
            initialfile=default_name,
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if csv_file and self.is_safe_path(csv_file):
            try:
                with open(csv_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['BSSID', 'Channel', 'Power', 'Privacy', 'Cipher', 'Authentication', 'ESSID'])
                    writer.writerows(data)
                self.update_output(f"Exported {len(data)} networks to {csv_file}\n")
            except Exception as e:
                self.show_messagebox("error", "Export Error", f"Failed to write CSV: {e}")

        # JSON
        json_file = filedialog.asksaveasfilename(
            title="Save as JSON",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if json_file and self.is_safe_path(json_file):
            try:
                json_data = [
                    {
                        "bssid": row[0], "channel": row[1], "power": row[2],
                        "privacy": row[3], "cipher": row[4], "auth": row[5], "essid": row[6]
                    }
                    for row in data
                ]
                with open(json_file, 'w') as f:
                    json.dump(json_data, f, indent=2)
                self.update_output(f"Exported {len(data)} networks to {json_file}\n")
            except Exception as e:
                self.show_messagebox("error", "Export Error", f"Failed to write JSON: {e}")

    # ======================
    # WPS ATTACKS
    # ======================
    def reaver_attack(self):
        self._run_wps_tool("reaver")

    def bully_attack(self):
        self._run_wps_tool("bully")

    def _run_wps_tool(self, tool):
        bssid = self.wps_bssid_var.get()
        interface = self.wps_interface_var.get()
        channel = self.wps_channel_var.get()

        if not (self.is_valid_mac(bssid) and self.is_valid_interface(interface) and self.is_valid_channel(channel)):
            self.show_messagebox("error", "Input Error", "Invalid BSSID, interface, or channel.")
            return

        mon_iface = self.get_monitor_interface(interface)
        if not mon_iface:
            self.show_messagebox("error", "Monitor Mode", "No monitor interface found for this device.")
            return

        cmd = [tool, '-i', mon_iface, '-b', bssid, '-c', channel, '-vv']
        if self.wps_delay_var.get():
            cmd += ['-d', '1']
        if self.wps_pixie_var.get() and tool == "reaver":
            cmd += ['-K', '1']

        self.run_command(cmd, f"{tool.upper()} Attack", timeout=3600, output_widget=self.wps_output)

    def stop_wps_attack(self):
        self.stop_attack(target_widget=self.wps_output)

    # ======================
    # MONITOR INTERFACE DETECTION
    # ======================
    def get_monitor_interface(self, base_interface):
        """Find the correct monitor interface for a given base interface.
        Robustly queries iw dev and iw dev <iface> info for type monitor and wiphy / phy info.
        """
        try:
            # Find base phy (wiphy) if possible
            base_phy = None
            try:
                res = subprocess.run(['iw', 'dev', base_interface, 'info'], capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    for ln in res.stdout.splitlines():
                        ln = ln.strip()
                        if ln.startswith('wiphy') or ln.startswith('phy#') or ln.startswith('phy'):
                            # take last token if numeric or 'phy0' style
                            tokens = ln.split()
                            if tokens:
                                base_phy = tokens[-1]
                                break
            except Exception:
                base_phy = None

            # Get list of interfaces from 'iw dev'
            res_all = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=5)
            if res_all.returncode != 0:
                return None
            out = res_all.stdout
            ifaces = re.findall(r'Interface\s+([^\s]+)', out)

            monitor_candidates = {}
            for iface in ifaces:
                try:
                    info = subprocess.run(['iw', 'dev', iface, 'info'], capture_output=True, text=True, timeout=2)
                    if info.returncode != 0:
                        continue
                    info_out = info.stdout
                    is_monitor = 'type monitor' in info_out
                    # attempt to extract wiphy/phy
                    phy = None
                    for ln in info_out.splitlines():
                        ln = ln.strip()
                        if ln.startswith('wiphy') or ln.startswith('phy#') or ln.startswith('phy'):
                            phy = ln.split()[-1]
                            break
                    if is_monitor:
                        monitor_candidates[iface] = phy
                except Exception:
                    continue

            # Prioritize monitor iface with same phy as base_interface
            if base_phy:
                for iface, phy in monitor_candidates.items():
                    if phy and phy == base_phy:
                        return iface

            # Fallback: return any monitor iface
            if monitor_candidates:
                return next(iter(monitor_candidates.keys()))

            # As last resort, if no monitor iface found, but base interface itself is in monitor mode, return it
            try:
                res_info = subprocess.run(['iw', 'dev', base_interface, 'info'], capture_output=True, text=True, timeout=2)
                if res_info.returncode == 0 and 'type monitor' in res_info.stdout:
                    return base_interface
            except Exception:
                pass

        except Exception as e:
            # Schedule UI-safe update
            self.run_on_main(self._write_output, f"Monitor detection error: {e}\n", None)
        return None

    # ======================
    # CAPTURE CONTROL
    # ======================
    def start_capture(self):
        bssid = self.bssid_var.get()
        channel = self.channel_var.get()
        interface = self.interface_var.get()

        if not (self.is_valid_mac(bssid) and self.is_valid_channel(channel) and self.is_valid_interface(interface)):
            self.show_messagebox("error", "Input Error", "Invalid BSSID, channel, or interface.")
            return

        mon_iface = self.get_monitor_interface(interface)
        if not mon_iface:
            self.show_messagebox("error", "Monitor Mode", "Enable monitor mode first.")
            return

        outdir = self.outdir_var.get()
        if not self.is_valid_dir_path(outdir):
            try:
                os.makedirs(outdir, exist_ok=True)
            except Exception:
                self.show_messagebox("error", "Output Dir", "Cannot create output directory.")
                return

        self.capture_file_base = os.path.join(outdir, f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        cmd = [
            'airodump-ng',
            '-c', channel,
            '--bssid', bssid,
            '-w', self.capture_file_base,
            mon_iface
        ]

        self.run_command(cmd, "Capture", timeout=None, capture_output=False)

    def stop_capture(self):
        if self.capture_process:
            try:
                self.capture_process.terminate()
                self.capture_process.wait(timeout=2)
            except Exception:
                try:
                    self.capture_process.kill()
                except Exception:
                    pass
            # capture_process cleanup occurs in monitor thread, but we force clear here
            self.capture_process = None
            self.capture_status_var.set("Capture stopped")
            # Auto-fill capture file
            cap_file = self.capture_file_base + "-01.cap" if self.capture_file_base else None
            if cap_file and os.path.exists(cap_file):
                self.capture_var.set(cap_file)
                self.update_output(f"Capture saved to {cap_file}\n")
        else:
            self.show_messagebox("info", "Capture", "No active capture to stop.")

    # ======================
    # ATTACK CONTROL
    # ======================
    def stop_attack(self, target_widget=None):
        with self.proc_lock:
            procs = list(self.active_processes)
        if procs:
            for proc, desc in procs:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                with self.proc_lock:
                    try:
                        self.active_processes.remove((proc, desc))
                    except ValueError:
                        pass
            self.status_var.set("READY")
            msg = "All attacks stopped.\n"
            if target_widget:
                try:
                    target_widget.config(state=tk.NORMAL)
                    target_widget.insert(tk.END, msg)
                    target_widget.config(state=tk.DISABLED)
                except Exception:
                    self.run_on_main(self._write_output, msg, None)
            else:
                self.update_output(msg)
        else:
            self.show_messagebox("info", "Stop Attack", "No active attacks running.")

    # ======================
    # GRAPH UPDATING
    # ======================
    def update_graphs(self):
        if not MATPLOTLIB_AVAILABLE or not self.packet_counts:
            return
        bssids = list(self.packet_counts.keys())
        counts = list(self.packet_counts.values())
        self.ax.clear()
        self.ax.bar(bssids, counts, color='skyblue')
        self.ax.set_title("Beacon Frames per Network (Last Scan)")
        self.ax.set_xlabel("BSSID")
        self.ax.set_ylabel("Packet Count")
        self.ax.tick_params(axis='x', rotation=45)
        self.fig.tight_layout()
        self.canvas.draw()

    # ======================
    # ENHANCED TELEMETRY
    # ======================
    def driver_info(self):
        interface = self.interface_var.get()
        if not self.is_valid_interface(interface):
            self.show_messagebox("warning", "Input", "Enter a valid interface.")
            return
        self.run_command(['ethtool', '-i', interface], "Driver Info")

    def chipset_detect(self):
        interface = self.interface_var.get()
        if not self.is_valid_interface(interface):
            self.show_messagebox("warning", "Input", "Enter a valid interface.")
            return
        self.run_command(['lspci', '-knn'], "Chipset Detection")

    # ======================
    # NETWORK MANAGER CONTROL
    # ======================
    def check_network_manager_status(self):
        self.run_command(['systemctl', 'is-active', 'NetworkManager'], "Check NetworkManager")

    def stop_network_manager(self):
        self.run_command(['systemctl', 'stop', 'NetworkManager'], "Stop NetworkManager")

    def start_network_manager(self):
        self.run_command(['systemctl', 'start', 'NetworkManager'], "Start NetworkManager")

    def kill_conflicts(self):
        self.run_command(['airmon-ng', 'check', 'kill'], "Kill Conflicts")

    def check_interface_status(self):
        interface = self.interface_var.get()
        if not self.is_valid_interface(interface):
            self.show_messagebox("warning", "Invalid Input", "Please enter a valid interface name.")
            return
        self.run_command(['ip', 'link', 'show', interface], f"Check {interface}")

    # ======================
    # TELEMETRY
    # ======================
    def check_aircrack_tools(self):
        tools = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "reaver", "bully"]
        self.update_output("Checking aircrack-ng tools...\n")
        for tool in tools:
            try:
                if shutil.which(tool):
                    self.update_output(f"✓ {tool} found\n")
                else:
                    self.update_output(f"✗ {tool} NOT FOUND\n")
            except Exception as e:
                self.update_output(f"✗ Error checking {tool}: {e}\n")

    def check_wireless_status(self):
        self.run_command(['iwconfig'], "Wireless Status")

    def list_conflicts(self):
        self.run_command(['airmon-ng', 'check'], "List Conflicts")

    def check_monitor_mode(self):
        interface = self.interface_var.get()
        if not self.is_valid_interface(interface):
            self.show_messagebox("warning", "Invalid Input", "Please enter a valid interface.")
            return
        mon_iface = self.get_monitor_interface(interface)
        if mon_iface:
            self.update_output(f"✓ Monitor interface: {mon_iface}\n")
            self.run_command(['iw', 'dev', mon_iface, 'info'], f"Monitor Info ({mon_iface})")
        else:
            self.update_output(f"✗ No monitor interface found for {interface}\n")

    def check_hardware_monitor(self):
        interface = self.interface_var.get()
        if not self.is_valid_interface(interface):
            self.show_messagebox("warning", "Invalid Input", "Please enter a valid interface.")
            return
        self.run_command(['iw', interface, 'info'], f"Hardware Monitor Check ({interface})")

    def system_info(self):
        self.run_command(['sh', '-c', 'uname -a && (lsb_release -a 2>/dev/null || cat /etc/os-release)'], "System Info")

    # ======================
    # MONITOR MODE
    # ======================
    def monitor_mode(self):
        interface = self.interface_var.get()
        if not self.is_valid_interface(interface):
            self.show_messagebox("warning", "Invalid Input", "Please enter a valid interface name (e.g., wlan0).")
            return

        self.update_output(f"Killing conflicts for {interface}...\n")
        self.kill_conflicts()
        # Wait then attempt to start monitor mode
        self.root.after(2000, lambda: self._finish_monitor_mode(interface))

    def _finish_monitor_mode(self, interface):
        try:
            result = subprocess.run(['iw', interface, 'info'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'type monitor' in result.stdout:
                self.update_output(f"Hardware monitor mode already active on {interface}\n")
                self.save_config()
                return
        except Exception:
            pass

        # Start airmon-ng in background
        self.run_command(['airmon-ng', 'start', interface], f"Enable Monitor Mode ({interface})")
        self.save_config()

    def stop_monitor(self):
        interface = self.interface_var.get()
        if not self.is_valid_interface(interface):
            self.show_messagebox("warning", "Invalid Input", "Please enter a valid interface.")
            return
        # airmon-ng stop works with base interface
        self.run_command(['airmon-ng', 'stop', interface], f"Stop Monitor ({interface})")

    # ======================
    # SCANNING & NETWORKS
    # ======================
    def scan_networks(self):
        interface = self.interface_var.get()
        if not self.is_valid_interface(interface):
            self.show_messagebox("warning", "Invalid Input", "Please enter a valid interface.")
            return

        mon_iface = self.get_monitor_interface(interface)
        if not mon_iface:
            # Try to enable monitor mode first
            self.update_output("No monitor interface found. Enabling monitor mode...\n")
            self.monitor_mode()
            self.root.after(5000, lambda: self._retry_scan(interface))
            return

        if self.scan_dir and os.path.exists(self.scan_dir):
            shutil.rmtree(self.scan_dir, ignore_errors=True)
        self.scan_dir = tempfile.mkdtemp(prefix="aircrack_scan_")
        scan_file = os.path.join(self.scan_dir, "scan")

        cmd = [
            'timeout', '15',
            'airodump-ng',
            mon_iface,
            '--output-format', 'csv',
            '--write', scan_file,
            '--band', 'abg'
        ]
        self.update_output(f"Scanning on {mon_iface} for 15 seconds...\n")
        self.run_command(cmd, "Network Scan", timeout=20)
        self.root.after(16000, lambda: self.update_network_and_client_lists(scan_file + "-01.csv"))

    def _retry_scan(self, interface):
        mon_iface = self.get_monitor_interface(interface)
        if mon_iface:
            self.scan_networks()
        else:
            self.update_output("Failed to enable monitor mode for scanning.\n")

    def update_network_and_client_lists(self, csv_file):
        self.update_network_list(csv_file)
        self.update_client_list(csv_file)
        if MATPLOTLIB_AVAILABLE:
            self.root.after(100, self.update_graphs)

    def update_network_list(self, csv_file):
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)
        self._parse_csv_section(csv_file, is_ap=True)

    def update_client_list(self, csv_file):
        for item in self.client_tree.get_children():
            self.client_tree.delete(item)
        self._parse_csv_section(csv_file, is_ap=False)

    def _parse_csv_section(self, csv_file, is_ap=True):
        try:
            if not os.path.exists(csv_file):
                return

            with open(csv_file, newline='', errors='ignore') as f:
                reader = csv.reader(f)
                rows = list(reader)

            if not rows:
                return

            # Find AP header row (contains 'BSSID') and client header row (contains 'Station MAC')
            ap_header_idx = None
            client_header_idx = None
            for i, row in enumerate(rows):
                if any(cell.strip().lower() == 'bssid' for cell in row if cell):
                    ap_header_idx = i
                if any(cell.strip().lower() == 'station mac' for cell in row if cell):
                    client_header_idx = i
                if ap_header_idx is not None and client_header_idx is not None:
                    break

            if is_ap and ap_header_idx is not None:
                self.packet_counts = {}
                headers = [h.strip() for h in rows[ap_header_idx]]
                header_map = {h.lower(): idx for idx, h in enumerate(headers if headers else [])}

                # Determine the indices we care about by header name with fallbacks
                bssid_idx = header_map.get('bssid', 0)
                chan_idx = header_map.get('channel', header_map.get('chnl', 3))
                power_idx = header_map.get('power', 2)
                priv_idx = header_map.get('privacy', header_map.get('enc', 5))
                cipher_idx = header_map.get('cipher', header_map.get('encpair', 6))
                auth_idx = header_map.get('authentication', header_map.get('auth', 7))
                essid_idx = header_map.get('essid', len(headers) - 1)
                # beacon header might be '# beacons' or 'beacons'
                beacon_idx = None
                for k in header_map.keys():
                    if 'beacon' in k:
                        beacon_idx = header_map[k]
                        break
                if beacon_idx is None:
                    beacon_idx = header_map.get('# beacons', header_map.get('beacons', None))
                if beacon_idx is None:
                    # fallback
                    beacon_idx = min(len(headers) - 1, 9)

                # Iterate rows after ap_header_idx until empty line or client header
                for row in rows[ap_header_idx + 1:]:
                    if not any(cell.strip() for cell in row if cell):
                        break
                    if client_header_idx is not None and rows.index(row) >= client_header_idx:
                        break
                    parts = [p.strip() for p in row]
                    if len(parts) <= bssid_idx:
                        continue
                    bssid = parts[bssid_idx]
                    if not self.is_valid_mac(bssid) or bssid == "00:00:00:00:00:00":
                        continue
                    try:
                        beacons = int(parts[beacon_idx]) if beacon_idx < len(parts) and parts[beacon_idx].isdigit() else 0
                    except Exception:
                        beacons = 0
                    self.packet_counts[bssid] = beacons
                    values = (
                        bssid,
                        parts[chan_idx] if chan_idx < len(parts) else '',
                        parts[power_idx] if power_idx < len(parts) else '',
                        parts[priv_idx] if priv_idx < len(parts) else '',
                        parts[cipher_idx] if cipher_idx < len(parts) else '',
                        parts[auth_idx] if auth_idx < len(parts) else '',
                        parts[essid_idx] if essid_idx < len(parts) else ''
                    )
                    self.network_tree.insert('', 'end', values=values)
                    network_data = {
                        "bssid": bssid,
                        "channel": parts[chan_idx] if chan_idx < len(parts) else '',
                        "essid": parts[essid_idx] if essid_idx < len(parts) else '',
                        "privacy": parts[priv_idx] if priv_idx < len(parts) else ''
                    }
                    self.add_to_scan_history(network_data)

            elif not is_ap and client_header_idx is not None:
                headers = [h.strip() for h in rows[client_header_idx]]
                header_map = {h.lower(): idx for idx, h in enumerate(headers)}
                station_idx = header_map.get('station mac', 0)
                power_idx = header_map.get('power', 2)
                packets_idx = header_map.get('# packets', header_map.get('packets', 3))
                bssid_idx = header_map.get('bssid', 4)
                probed_idx = header_map.get('probed essids', header_map.get('probed', len(headers) - 1))

                for row in rows[client_header_idx + 1:]:
                    if not any(cell.strip() for cell in row if cell):
                        break
                    parts = [p.strip() for p in row]
                    if len(parts) <= station_idx:
                        continue
                    station = parts[station_idx]
                    if not self.is_valid_mac(station):
                        continue
                    values = (
                        station,
                        parts[power_idx] if power_idx < len(parts) else '',
                        parts[packets_idx] if packets_idx < len(parts) else '',
                        parts[bssid_idx] if bssid_idx < len(parts) else '',
                        parts[probed_idx] if probed_idx < len(parts) else ''
                    )
                    self.client_tree.insert('', 'end', values=values)

        except Exception as e:
            self.run_on_main(self._write_output, f"CSV parse error: {e}\n", None)

    def filter_networks(self, *args):
        search = self.network_search_var.get().lower()
        children = self.network_tree.get_children()
        for item in children:
            self.network_tree.detach(item)
        for item in children:
            vals = self.network_tree.item(item, 'values')
            if any(search in str(v).lower() for v in vals):
                self.network_tree.move(item, '', 'end')

    def select_network(self):
        selected = self.network_tree.selection()
        if not selected:
            self.show_messagebox("warning", "No Selection", "Select a network first.")
            return
        vals = self.network_tree.item(selected[0], 'values')
        self.bssid_var.set(vals[0])
        self.channel_var.set(vals[1])
        self.essid_var.set(vals[6])
        self.target_ap_var.set(vals[0])
        # use stored notebook reference
        try:
            self.notebook.select(0)
        except Exception:
            pass
        self.show_messagebox("info", "Selected", f"Network: {vals[6]} ({vals[0]})")

    def select_client(self):
        selected = self.client_tree.selection()
        if not selected:
            self.show_messagebox("warning", "No Selection", "Select a client first.")
            return
        vals = self.client_tree.item(selected[0], 'values')
        self.client_mac_var.set(vals[0])
        try:
            self.notebook.select(0)
        except Exception:
            pass
        self.show_messagebox("info", "Selected", f"Client: {vals[0]}")

    # ======================
    # ATTACKS & CRACKING
    # ======================
    def deauth_attack(self):
        interface = self.interface_var.get()
        bssid = self.bssid_var.get()
        channel = self.channel_var.get()
        client = self.client_mac_var.get()

        if not self.is_valid_interface(interface):
            self.show_messagebox("error", "Invalid", "Interface name invalid.")
            return
        if not self.is_valid_mac(bssid):
            self.show_messagebox("error", "Invalid", "BSSID must be a valid MAC address.")
            return
        if not self.is_valid_channel(channel):
            self.show_messagebox("error", "Invalid", "Channel must be a number between 1-165.")
            return
        if client and not self.is_valid_mac(client):
            self.show_messagebox("error", "Invalid", "Client MAC is invalid.")
            return

        mon_iface = self.get_monitor_interface(interface)
        if not mon_iface:
            self.show_messagebox("error", "Monitor Mode", "Monitor interface not found.")
            return

        cmd = ['aireplay-ng', '--deauth', '0', '-a', bssid]
        if client:
            cmd += ['-c', client]
        # aireplay-ng doesn't use '--channel' flag after iface, channel should be managed via iwconfig/airmon
        cmd += [mon_iface]

        self.run_command(cmd, f"Deauth Attack on {bssid}", timeout=60)

    def crack_wpa(self):
        wordlist = self.wordlist_var.get()
        capture = self.capture_var.get()

        if not self.is_valid_file_path(wordlist):
            self.show_messagebox("error", "File Error", "Wordlist file not found or invalid.")
            return
        if not self.is_valid_file_path(capture):
            self.show_messagebox("error", "File Error", "Capture file not found or invalid.")
            return

        # Validate pcap header
        try:
            with open(capture, 'rb') as f:
                magic = f.read(4)
                if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
                    self.show_messagebox("warning", "File Warning", "Capture file may not be a valid pcap.")
        except Exception as e:
            self.run_on_main(self._write_output, f"Capture validation warning: {e}\n", None)

        self.run_command(['aircrack-ng', '-w', wordlist, capture], "WPA Cracking", timeout=3600)

    def detect_interfaces(self):
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
            interfaces = []
            for line in result.stdout.splitlines():
                if ': ' in line and 'state' in line:
                    name = line.split(':')[1].strip().split()[0]
                    # verify wireless
                    try:
                        res = subprocess.run(['iw', 'dev', name, 'info'], capture_output=True, text=True, timeout=2)
                        if res.returncode == 0:
                            interfaces.append(name)
                    except Exception:
                        continue
            # Prefer non-monitor interface if available
            chosen = None
            non_mon = [i for i in interfaces if not i.endswith('mon')]
            if non_mon:
                chosen = non_mon[0]
            elif interfaces:
                chosen = interfaces[0]
            if chosen:
                self.interface_var.set(chosen)
                self.update_output(f"Detected: {', '.join(interfaces)}\n")
            else:
                self.update_output("No wireless interfaces found.\n")
        except Exception as e:
            self.update_output(f"Interface detection error: {e}\n")


if __name__ == "__main__":
    # Create root early so messagebox can display reliably
    root = tk.Tk()
    root.withdraw()  # don't show main window yet

    # Check if running as root
    if os.geteuid() != 0:
        try:
            messagebox.showerror("Root Required", "This tool must be run as root (sudo).")
        except Exception:
            print("This tool must be run as root (sudo).", file=sys.stderr)
        sys.exit(1)

    # Continue with UI
    root.deiconify()
    app = AircrackGUI(root)
    root.mainloop()