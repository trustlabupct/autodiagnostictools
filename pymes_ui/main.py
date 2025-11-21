#!/usr/bin/env python3
"""
PYMEs Unified UI - Interface for TrusLAN, trusClamAV, and trustMITRE.

Author: Volodymyr Dubetskyy
Organization: TRUST Lab UPCT
(c) 2025 TRUST Lab UPCT

Provides a consolidated front-end with command history, tooltips, and enhanced
output management.
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import contextlib
import subprocess
import threading
import os
import sys
import json
import shlex
from pathlib import Path
from datetime import datetime
import platform
import re
import io
from collections import deque

# Status prefixes
STATUS_INFO = "[INFO]"
STATUS_OK = "[OK]"
STATUS_WARN = "[WARN]"
STATUS_ERROR = "[ERROR]"


def get_resource_path(*relative_parts: str) -> Path:
    """
    Resolve a path shipped with the application.

    When running under PyInstaller, assets are unpacked into the temporary
    sys._MEIPASS directory. During development we resolve paths relative to
    the repository root (parent of this file's directory).
    """
    if getattr(sys, "frozen", False):
        base_path = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))  # type: ignore[attr-defined]
    else:
        base_path = Path(__file__).resolve().parent.parent
    return base_path.joinpath(*relative_parts)


class StreamRedirect(io.TextIOBase):
    """Redirect stdout/stderr into a Tk text widget without blocking the UI."""

    def __init__(self, widget, root):
        super().__init__()
        self.widget = widget
        self.root = root

    def writable(self) -> bool:
        return True

    def write(self, data: str) -> int:  # type: ignore[override]
        if not data:
            return 0
        self.root.after(0, lambda d=data: (self.widget.insert(tk.END, d), self.widget.see(tk.END)))
        return len(data)

    def flush(self) -> None:  # type: ignore[override]
        return


class ModernTooltip:
    """Tooltip implementation"""
    def __init__(self, widget, text, delay=500):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.tooltip_window = None
        self.after_id = None
        self.widget.bind('<Enter>', self.schedule_show)
        self.widget.bind('<Leave>', self.hide)
        self.widget.bind('<Button>', self.hide)

    def schedule_show(self, event=None):
        self.after_id = self.widget.after(self.delay, self.show)

    def show(self, event=None):
        if self.tooltip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        label = ttk.Label(
            self.tooltip_window,
            text=self.text,
            justify=tk.LEFT,
            relief=tk.SOLID,
            borderwidth=1,
            font=("Helvetica", 9),
            padding=(8, 4)
        )
        label.pack()

    def hide(self, event=None):
        if self.after_id:
            self.widget.after_cancel(self.after_id)
            self.after_id = None
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None


class CommandHistory:
    """Manage command history with persistence"""
    def __init__(self, max_size=50):
        self.max_size = max_size
        self.history = deque(maxlen=max_size)
        self.history_file = Path.home() / ".pymes_ui_history.json"
        self.load()

    def add(self, tool, command, options):
        entry = {'tool': tool, 'command': command, 'options': options, 'timestamp': datetime.now().isoformat()}
        self.history.append(entry)
        self.save()

    def get_recent(self, tool=None, limit=10):
        items = list(self.history)
        if tool:
            items = [i for i in items if i['tool'] == tool]
        return list(reversed(items))[:limit]

    def save(self):
        try:
            with open(self.history_file, 'w') as f:
                json.dump(list(self.history), f, indent=2)
        except Exception:
            pass

    def load(self):
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    self.history = deque(json.load(f), maxlen=self.max_size)
        except Exception:
            pass


class EnhancedOutput(ttk.Frame):
    """Output widget with search, export, and color coding"""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X, side=tk.TOP, pady=(0, 2))

        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.highlight_search)
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=25)
        search_entry.pack(side=tk.LEFT, padx=(0, 5))
        ModernTooltip(search_entry, "Search in output")

        ttk.Button(toolbar, text="Copy", command=self.copy_output).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Export", command=self.export_output).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Clear", command=self.clear_output).pack(side=tk.LEFT, padx=2)

        self.text = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=('Consolas', 9), relief=tk.FLAT, borderwidth=1)
        self.text.pack(fill=tk.BOTH, expand=True)

        self.text.tag_config('error', foreground='#d00000')
        self.text.tag_config('warning', foreground='#f39c12')
        self.text.tag_config('success', foreground='#27ae60')
        self.text.tag_config('info', foreground='#2980b9')
        self.text.tag_config('command', foreground='#8e44ad', font=('Consolas', 9, 'bold'))
        self.text.tag_config('highlight', background='#f1c40f')
        self.text.tag_config('timestamp', foreground='#7f8c8d', font=('Consolas', 8))

    def insert(self, index, text, tags=None):
        self.text.insert(index, text)
        start_index = self.text.index(index)
        line_count = text.count('\n')
        
        current_line_num = int(start_index.split('.')[0])
        for i in range(line_count + 1):
            line_start = f"{current_line_num}.0"
            line_end = f"{current_line_num}.end"
            line_content = self.text.get(line_start, line_end)

            if not line_content:
                current_line_num += 1
                continue

            if re.search(r'\[ERROR\]|ERROR:|error:', line_content, re.IGNORECASE):
                self.text.tag_add('error', line_start, line_end)
            elif re.search(r'\[WARNING\]|WARNING:|warning:', line_content, re.IGNORECASE):
                self.text.tag_add('warning', line_start, line_end)
            elif re.search(r'\[OK\]|SUCCESS:|success:', line_content, re.IGNORECASE):
                self.text.tag_add('success', line_start, line_end)
            elif re.search(r'\[INFO\]|INFO:|info:', line_content, re.IGNORECASE):
                self.text.tag_add('info', line_start, line_end)
            elif line_content.startswith('Executing:') or line_content.startswith('Command:'):
                self.text.tag_add('command', line_start, line_end)
            elif re.search(r'\d{2}:\d{2}:\d{2}', line_content):
                self.text.tag_add('timestamp', line_start, line_end)
            
            current_line_num += 1

    def highlight_search(self, *args):
        self.text.tag_remove('highlight', '1.0', tk.END)
        search_text = self.search_var.get()
        if not search_text: return
        start = '1.0'
        while True:
            pos = self.text.search(search_text, start, tk.END, nocase=True)
            if not pos: break
            end = f"{pos}+{len(search_text)}c"
            self.text.tag_add('highlight', pos, end)
            start = end

    def copy_output(self):
        try:
            self.clipboard_clear()
            self.clipboard_append(self.text.get('1.0', tk.END))
            messagebox.showinfo("Success", "Output copied to clipboard.", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {str(e)}", parent=self)

    def export_output(self):
        try:
            filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
            if filename:
                with open(filename, 'w') as f: f.write(self.text.get('1.0', tk.END))
                messagebox.showinfo("Success", f"Output exported to:\\n{filename}", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}", parent=self)

    def clear_output(self): self.text.delete('1.0', tk.END)
    def see(self, index): self.text.see(index)
    def get(self, start, end): return self.text.get(start, end)


class PYMEsUnifiedUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TRUST Lab UPCT - Unified Security Toolkit")
        self.root.geometry("1200x800")
        
        try:
            icon_path = get_resource_path("assets", "icon.ico")
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
        except Exception:
            pass

        self.root.minsize(720, 500)

        self.history = CommandHistory()
        self.setup_styling()

        self.base_path = get_resource_path()
        self.work_root = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path.cwd()
        self.truslan_path = get_resource_path("truslan")
        self.trusclamav_path = get_resource_path("trusClamAV")
        self.trustmitre_path = get_resource_path("trusMITRE")

        self._inject_tool_paths()

        self.running_tasks = []
        self.task_lock = threading.Lock()
        self.argv_lock = threading.Lock()

        self.create_header()
        self.create_notebook()
        self.create_status_bar()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_styling(self):
        style = ttk.Style()
        if 'clam' in style.theme_names():
            style.theme_use('clam')
        
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0')
        style.configure('TButton', padding=(10, 5), font=('Helvetica', 9))
        style.configure('TCheckbutton', background='#f0f0f0')
        style.configure('TRadiobutton', background='#f0f0f0')
        style.configure('Header.TFrame', background='#333')
        style.configure('Header.TLabel', background='#333', foreground='white', font=('Helvetica', 14, 'bold'))
        style.configure('TLabelframe', padding=10, background='#f0f0f0')
        style.configure('TLabelframe.Label', font=('Helvetica', 10, 'bold'), background='#f0f0f0')
        style.configure('TNotebook', background='#f0f0f0', borderwidth=1)
        style.configure('TNotebook.Tab', padding=(15, 8), font=('Helvetica', 9, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', '#f0f0f0')], foreground=[('selected', '#0078d7')])

    def _inject_tool_paths(self):
        """Ensure local source trees are importable when running from source."""
        for candidate in [
            self.truslan_path / "src",
            self.trusclamav_path / "src",
            self.trustmitre_path / "src",
        ]:
            if candidate.exists():
                path_str = str(candidate.resolve())
                if path_str not in sys.path:
                    sys.path.insert(0, path_str)

    def create_header(self):
        header_frame = ttk.Frame(self.root, style='Header.TFrame', height=50)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        title_label = ttk.Label(header_frame, text="PYMEs Unified Security Toolkit", style='Header.TLabel')
        title_label.pack(side=tk.LEFT, padx=15, pady=10)


    def create_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.create_dashboard_tab()
        self.create_truslan_tab()
        self.create_trusclamav_tab()
        self.create_trustmitre_tab()

    def create_status_bar(self):
        self.status_frame = ttk.Frame(self.root, height=30, relief=tk.SUNKEN, borderwidth=1)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_frame.pack_propagate(False)
        self.status_label = ttk.Label(self.status_frame, text="Ready", anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=5)
        self.progress_bar = ttk.Progressbar(self.status_frame, mode='indeterminate', length=150)
        self.progress_bar.pack(side=tk.RIGHT, padx=10, pady=5)

    def update_status(self, message, status_type='info', show_progress=False):
        self.status_label.config(text=f"{datetime.now().strftime('%H:%M:%S')} - {message}")
        if show_progress: self.progress_bar.start(10)
        else: self.progress_bar.stop()
        self.root.update_idletasks()

    def create_dashboard_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Dashboard")

        main_frame = ttk.Frame(tab)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # Quick Actions
        actions_frame = ttk.Labelframe(main_frame, text="Quick Actions")
        actions_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=(0,5))
        
        ttk.Button(actions_frame, text="Scan Network (TrusLAN)", command=lambda: self.notebook.select(1)).pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(actions_frame, text="Scan for Malware (trusClamAV)", command=lambda: self.notebook.select(2)).pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(actions_frame, text="Analyze Logs (trustMITRE)", command=lambda: self.notebook.select(3)).pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(actions_frame, text="About This Application", command=self.show_about_window).pack(fill=tk.X, padx=10, pady=5)

        # System Info
        sys_frame = ttk.Labelframe(main_frame, text="System Information")
        sys_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        
        info = {
            "OS": platform.system(), "Platform": platform.platform(),
            "Python": platform.python_version(), "Directory": str(self.base_path)
        }
        for i, (label, value) in enumerate(info.items()):
            ttk.Label(sys_frame, text=f"{label}:", font=('Helvetica', 9, 'bold')).grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
            ttk.Label(sys_frame, text=value, wraplength=300, justify=tk.LEFT).grid(row=i, column=1, sticky=tk.W, padx=5, pady=2)

        # Recent History
        history_frame = ttk.Labelframe(main_frame, text="Recent Activity")
        history_frame.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(5, 0))
        
        self.history_text = scrolledtext.ScrolledText(history_frame, height=10, wrap=tk.NONE, font=('Consolas', 8))
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.refresh_dashboard_history()

        # Quickstart Guide
        quickstart_frame = ttk.Labelframe(main_frame, text="Quick Start Guide")
        quickstart_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(5,0))

        usage_text = (
            "1. Use the 'Doctor' command in each tool\'s tab to verify prerequisites.\n"
            "2. Adjust options in each tab before running scans or analysis jobs.\n"
            "3. Review results in the 'Output Console' and generated files in the tool\'s 'output' directory."
        )
        usage_label = ttk.Label(quickstart_frame, text=usage_text, justify=tk.LEFT)
        usage_label.pack(anchor=tk.W, padx=10, pady=5)

    def refresh_dashboard_history(self):
        self.history_text.config(state=tk.NORMAL)
        self.history_text.delete('1.0', tk.END)
        entries = self.history.get_recent(limit=20)
        if not entries:
            self.history_text.insert(tk.END, "No commands executed yet.")
        else:
            for entry in entries:
                ts = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M')
                self.history_text.insert(tk.END, f"[{ts}] {entry['tool']}: {entry['command']}\n")
        self.history_text.config(state=tk.DISABLED)


    def create_tool_tab(self, name, title):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text=name)

        main_pane = tk.PanedWindow(tab, orient=tk.VERTICAL, sashrelief=tk.RAISED)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # Top pane for controls
        controls_frame = ttk.Frame(main_pane, padding=5)
        controls_frame.columnconfigure(0, weight=1)
        controls_frame.rowconfigure(1, weight=1)
        main_pane.add(controls_frame, minsize=200)

        # Bottom pane for output
        output_frame = ttk.Labelframe(main_pane, text="Output Console", padding=5)
        main_pane.add(output_frame)

        # Title and command buttons
        title_frame = ttk.Frame(controls_frame)
        title_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(title_frame, text=title, font=('Helvetica', 12, 'bold')).pack(side=tk.LEFT)
        
        output_widget = EnhancedOutput(output_frame)
        output_widget.pack(fill=tk.BOTH, expand=True)

        return controls_frame, output_widget, title_frame

    def create_truslan_tab(self):
        controls_frame, self.truslan_output, title_frame = self.create_tool_tab("TrustLAN", "TrustLAN - Network Scanner")
        
        run_btn = ttk.Button(title_frame, text="Run", command=self.run_truslan)
        run_btn.pack(side=tk.RIGHT, padx=(0, 5))
        ModernTooltip(run_btn, "Execute the selected command")
        
        ttk.Button(title_frame, text="Open Output", command=lambda: self.open_folder(self.truslan_vars['output_dir'].get())).pack(side=tk.RIGHT, padx=5)

        options_pane = tk.PanedWindow(controls_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        options_pane.grid(row=1, column=0, sticky='nsew')

        # Command selection
        cmd_frame = ttk.Labelframe(options_pane, text="Command", padding=10)
        options_pane.add(cmd_frame, minsize=120)
        self.truslan_command = tk.StringVar(value="discover")
        commands = [("Discover", "discover"), ("Scan", "scan"), ("Report", "report"), ("All-in-One", "all"), ("List Scripts", "list-scripts")]
        for text, val in commands:
            ttk.Radiobutton(cmd_frame, text=text, variable=self.truslan_command, value=val, command=self.update_truslan_options).pack(anchor=tk.W, pady=2)

        # Options
        self.truslan_options_frame = ttk.Labelframe(options_pane, text="Options", padding=10)
        options_pane.add(self.truslan_options_frame)

        self.truslan_vars = {
            'cidr': tk.StringVar(value="192.168.1.0/24"), 'profile': tk.StringVar(value="safe"), 'mode': tk.StringVar(value="top"),
            'top_ports': tk.StringVar(value="1000"), 'ports': tk.StringVar(value="22,80,443,445,3389"), 'timing': tk.StringVar(value="T3"),
            'output_dir': tk.StringVar(value="./output"), 'auto_cidr': tk.BooleanVar(value=False), 'use_udp': tk.BooleanVar(value=False),
            'trust_discovery': tk.BooleanVar(value=False), 'save_xml': tk.BooleanVar(value=False), 'authorized': tk.BooleanVar(value=False),
            'json_file': tk.StringVar(value="")
        }
        self.update_truslan_options()

    def update_truslan_options(self):
        for widget in self.truslan_options_frame.winfo_children():
            widget.destroy()

        canvas = tk.Canvas(self.truslan_options_frame, borderwidth=0, background="#f0f0f0")
        scrollbar = ttk.Scrollbar(self.truslan_options_frame, orient="vertical", command=canvas.yview)
        frame = ttk.Frame(canvas)

        frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        command = self.truslan_command.get()

        if command in ["discover", "list-scripts"]:
            ttk.Label(frame, text="No options for this command.").pack(padx=5, pady=5)
            return

        row = 0
        if command in ["scan", "all"]:
            if command == "scan":
                self.create_option_row(frame, row, "Target CIDR:", self.truslan_vars['cidr'], 'entry', width=30)
                row += 1
            else:  # all
                ttk.Checkbutton(frame, text="Auto-discover networks", variable=self.truslan_vars['auto_cidr']).grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=2)
                row += 1
                self.create_option_row(frame, row, "Manual CIDR:", self.truslan_vars['cidr'], 'entry', width=30)
                row += 1

            self.create_option_row(frame, row, "Profile:", self.truslan_vars['profile'], 'radio', options=["safe", "standard", "aggressive"])
            row += 1
            self.create_option_row(frame, row, "Port Mode:", self.truslan_vars['mode'], 'radio', options=["top", "ports"])
            row += 1
            self.create_option_row(frame, row, "Top Ports:", self.truslan_vars['top_ports'], 'entry', width=10)
            row += 1
            self.create_option_row(frame, row, "Port List:", self.truslan_vars['ports'], 'entry', width=30)
            row += 1
            self.create_option_row(frame, row, "Timing:", self.truslan_vars['timing'], 'combo', options=[f"T{i}" for i in range(6)])
            row += 1

            checkbox_frame = ttk.Frame(frame)
            checkbox_frame.grid(row=row, column=0, columnspan=2, sticky='w')
            for i, (var, text) in enumerate([
                (self.truslan_vars['use_udp'], "Enable UDP scanning"),
                (self.truslan_vars['trust_discovery'], "Trust discovery (-Pn)"),
                (self.truslan_vars['save_xml'], "Save XML output"),
                (self.truslan_vars['authorized'], "I am authorized (for aggressive)")
            ]):
                ttk.Checkbutton(checkbox_frame, text=text, variable=var).pack(anchor=tk.W)
            row += 1

        elif command == "report":
            self.create_option_row(frame, row, "Scan JSON File:", self.truslan_vars['json_file'], 'file')
            row += 1

        if command in ["scan", "all", "report"]:
            self.create_option_row(frame, row, "Output Dir:", self.truslan_vars['output_dir'], 'directory')

    def run_truslan(self):
        command = self.truslan_command.get()
        args = [command]
        if command in ["scan", "all"]:
            if command == "all" and self.truslan_vars['auto_cidr'].get(): args.append("--auto-cidr")
            elif command == "scan" or not self.truslan_vars['auto_cidr'].get():
                if cidr := self.truslan_vars['cidr'].get().strip(): args.extend(["--cidr", cidr])
            args.extend(["--profile", self.truslan_vars['profile'].get()])
            args.extend(["--mode", self.truslan_vars['mode'].get()])
            if self.truslan_vars['mode'].get() == "top": args.extend(["--top", self.truslan_vars['top_ports'].get()])
            else: args.extend(["--ports", self.truslan_vars['ports'].get()])
            args.extend(["--timing", self.truslan_vars['timing'].get()])
            if self.truslan_vars['use_udp'].get(): args.append("--udp")
            if self.truslan_vars['trust_discovery'].get(): args.append("--trust-discovery")
            if self.truslan_vars['save_xml'].get(): args.append("--save-xml")
            if self.truslan_vars['authorized'].get(): args.append("--i-am-authorized")
            if out_dir := self.truslan_vars['output_dir'].get().strip(): args.extend(["--out", out_dir])
        elif command == "report":
            if not (json_file := self.truslan_vars['json_file'].get().strip()):
                messagebox.showerror("Error", "Please specify a JSON file"); return
            args.extend(["--from-json", json_file])
            if out_dir := self.truslan_vars['output_dir'].get().strip():
                args.extend(["--out-html", os.path.join(out_dir, "report.html"), "--out-csv", os.path.join(out_dir, "findings.csv")])

        self.history.add('truslan', command, {k: v.get() for k, v in self.truslan_vars.items()})
        self.history.add('truslan', command, {k: v.get() for k, v in self.truslan_vars.items()})
        # Always run in work_root so relative paths work as expected
        workdir = self.work_root
        self.run_tool_async("truslan", args, self.invoke_truslan, self.truslan_output, workdir)

    def create_trusclamav_tab(self):
        controls_frame, self.clamav_output, title_frame = self.create_tool_tab("TrustClamAV", "TrustClamAV - Malware Scanner")
        
        run_btn = ttk.Button(title_frame, text="Run", command=self.run_trusclamav)
        run_btn.pack(side=tk.RIGHT, padx=(0, 5))
        ModernTooltip(run_btn, "Execute the selected command")

        options_pane = tk.PanedWindow(controls_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        options_pane.grid(row=1, column=0, sticky='nsew')

        cmd_frame = ttk.Labelframe(options_pane, text="Command", padding=10)
        options_pane.add(cmd_frame, minsize=120)
        self.clamav_command = tk.StringVar(value="doctor")
        commands = [("Doctor", "doctor"), ("Install", "install"), ("Update", "update"), ("Scan", "scan"), ("Cleanup", "cleanup")]
        for text, val in commands:
            ttk.Radiobutton(cmd_frame, text=text, variable=self.clamav_command, value=val, command=self.update_clamav_options).pack(anchor=tk.W, pady=2)

        self.clamav_options_frame = ttk.Labelframe(options_pane, text="Options", padding=10)
        options_pane.add(self.clamav_options_frame)

        self.clamav_vars = {
            'targets': tk.StringVar(), 'exclude': tk.StringVar(), 'output_prefix': tk.StringVar(value="./output/trusclamav/scan"),
            'use_clamd': tk.BooleanVar(value=False), 'json_output': tk.BooleanVar(value=True), 'retries': tk.StringVar(value="3"),
            'timeout': tk.StringVar(value="300"), 'log_level': tk.StringVar(value="INFO")
        }
        self.update_clamav_options()

    def update_clamav_options(self):
        for widget in self.clamav_options_frame.winfo_children(): widget.destroy()
        command = self.clamav_command.get()
        frame = ttk.Frame(self.clamav_options_frame); frame.pack(fill=tk.BOTH, expand=True)
        row = 0

        if command == "doctor":
            ttk.Checkbutton(frame, text="JSON output format", variable=self.clamav_vars['json_output']).grid(row=row, column=0, sticky=tk.W, pady=2)
            row += 1
        elif command == "scan":
            self.create_option_row(frame, row, "Targets:", self.clamav_vars['targets'], 'directory', tooltip="Directories or files to scan (space-separated)")
            row += 1
            self.create_option_row(frame, row, "Exclusions:", self.clamav_vars['exclude'], 'entry', width=40, tooltip="Glob patterns to exclude")
            row += 1
            self.create_option_row(frame, row, "Output Prefix:", self.clamav_vars['output_prefix'], 'entry', width=40)
            row += 1
            ttk.Checkbutton(frame, text="Use ClamAV daemon (clamd)", variable=self.clamav_vars['use_clamd']).grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=2)
            row += 1
        elif command == "update":
            self.create_option_row(frame, row, "Retries:", self.clamav_vars['retries'], 'entry', width=10)
            row += 1
        
        self.create_option_row(frame, row, "Timeout (s):", self.clamav_vars['timeout'], 'entry', width=10)
        row += 1
        self.create_option_row(frame, row, "Log Level:", self.clamav_vars['log_level'], 'combo', options=["DEBUG", "INFO", "WARNING", "ERROR"])

    def run_trusclamav(self):
        command = self.clamav_command.get()
        args = []

        if timeout := self.clamav_vars['timeout'].get().strip(): args.extend(["--timeout", timeout])
        if log_level := self.clamav_vars['log_level'].get().strip(): args.extend(["--log-level", log_level])
        args.append(command)

        if command == "doctor":
            if self.clamav_vars['json_output'].get(): args.append("--json")
        elif command == "scan":
            if not (targets := shlex.split(self.clamav_vars['targets'].get())):
                messagebox.showerror("Error", "Specify at least one target."); return
            args.extend(["--targets", *targets])
            if exclude := shlex.split(self.clamav_vars['exclude'].get()): args.extend(["--exclude", *exclude])
            if output_prefix := self.clamav_vars['output_prefix'].get().strip(): args.extend(["--out", output_prefix])
            if self.clamav_vars['use_clamd'].get(): args.append("--use-clamd")
        elif command == "update":
            if retries := self.clamav_vars['retries'].get().strip(): args.extend(["--retries", retries])

        self.history.add('trusclamav', command, {k: v.get() for k, v in self.clamav_vars.items()})
        self.history.add('trusclamav', command, {k: v.get() for k, v in self.clamav_vars.items()})
        # Always run in work_root so relative paths work as expected
        workdir = self.work_root
        self.run_tool_async("trusClamAV", args, self.invoke_trusclamav, self.clamav_output, workdir)

    def create_trustmitre_tab(self):
        controls_frame, self.trustmitre_output, title_frame = self.create_tool_tab("TrustMITRE", "TrustMITRE - Threat Analytics Pipeline")

        run_btn = ttk.Button(title_frame, text="Run", command=self.run_trustmitre)
        run_btn.pack(side=tk.RIGHT, padx=(0, 5))
        ModernTooltip(run_btn, "Execute the selected command")
        # Fix: Open reports in the persistent output directory (work_root/output)
        ttk.Button(title_frame, text="Open Reports", command=lambda: self.open_folder(self.work_root / "output")).pack(side=tk.RIGHT, padx=5)

        options_pane = tk.PanedWindow(controls_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        options_pane.grid(row=1, column=0, sticky='nsew')

        # Left: Command selection
        cmd_frame = ttk.Labelframe(options_pane, text="Command")
        options_pane.add(cmd_frame)
        
        commands = [
            ("quickstart", "Quickstart (Run full pipeline)"),
            ("download", "Download/Update Analytics"),
            ("compile", "Compile Analytics"),
            ("ingest", "Ingest/Normalize Logs"),
            ("run", "Execute Analytics"),
            ("report", "Generate Reports"),
            ("clean", "Clean Artifacts"),
            ("validate-config", "Check Configuration"),
            ("schema", "Show Data Schema")
        ]
        
        self.trustmitre_command = tk.StringVar(value="quickstart")
        for cmd, desc in commands:
            rb = ttk.Radiobutton(cmd_frame, text=cmd, value=cmd, variable=self.trustmitre_command, command=self.update_trustmitre_options)
            rb.pack(anchor=tk.W, padx=5, pady=2)
            ModernTooltip(rb, desc)

        # Right: Options
        self.trustmitre_options_frame = ttk.Labelframe(options_pane, text="Options")
        options_pane.add(self.trustmitre_options_frame)

        # Fix: Default ingest path should be in persistent logs directory (work_root/logs)
        default_ingest = str((self.work_root / "logs" / "ingested.jsonl").resolve())
        self.trustmitre_vars = {
            'config': tk.StringVar(), 'inputs': tk.StringVar(), 'evtx': tk.StringVar(), 'output': tk.StringVar(value=default_ingest),
            'include': tk.StringVar(), 'exclude': tk.StringVar(), 'workers': tk.StringVar(), 'batch_size': tk.StringVar(),
            'force': tk.BooleanVar(value=False), 'live': tk.BooleanVar(value=False),
        }
        self.update_trustmitre_options()

    def update_trustmitre_options(self):
        for widget in self.trustmitre_options_frame.winfo_children(): widget.destroy()
        command = self.trustmitre_command.get()
        frame = ttk.Frame(self.trustmitre_options_frame); frame.pack(fill=tk.BOTH, expand=True)
        row = 0

        if command in {"quickstart", "download", "compile", "ingest", "run", "report", "clean", "validate-config"}:
            self.create_option_row(frame, row, "Config File:", self.trustmitre_vars['config'], 'file', tooltip="Optional trustmitre.toml override")
            row += 1
        if command in {"quickstart", "ingest", "run"}:
            self.create_option_row(frame, row, "Input Logs:", self.trustmitre_vars['inputs'], 'files', tooltip="Log files (space separated)")
            row += 1
        if command == "download":
            ttk.Checkbutton(frame, text="Force re-download", variable=self.trustmitre_vars['force']).grid(row=row, column=0, sticky=tk.W, pady=2)
            row += 1
        if command == "ingest":
            self.create_option_row(frame, row, "EVTX Archives:", self.trustmitre_vars['evtx'], 'files', tooltip="EVTX files to convert")
            row += 1
            ttk.Checkbutton(frame, text="Collect live Sysmon events (Windows)", variable=self.trustmitre_vars['live']).grid(row=row, column=0, sticky=tk.W, pady=2)
            row += 1
            self.create_option_row(frame, row, "Output JSONL:", self.trustmitre_vars['output'], 'save_file')
            row += 1
        if command == "run":
            self.create_option_row(frame, row, "Include Analytics:", self.trustmitre_vars['include'], 'entry', tooltip="Analytic IDs (space separated)")
            row += 1
            self.create_option_row(frame, row, "Exclude Analytics:", self.trustmitre_vars['exclude'], 'entry', tooltip="Analytic IDs (space separated)")
            row += 1
            self.create_option_row(frame, row, "Workers:", self.trustmitre_vars['workers'], 'entry', width=10)
            row += 1
            self.create_option_row(frame, row, "Batch Size:", self.trustmitre_vars['batch_size'], 'entry', width=10)
            row += 1
        if command == "schema":
            ttk.Label(frame, text="Displays detection schema in the console.").grid(row=row, column=0, sticky=tk.W, pady=5)
        if row == 0 and command not in ["schema"]:
            ttk.Label(frame, text="Using defaults from trustmitre.toml.", style='Italic.TLabel').grid(row=row, column=0, sticky=tk.W, pady=5)

    def run_trustmitre(self):
        command = self.trustmitre_command.get()
        args = []
        if config_path := self.trustmitre_vars['config'].get().strip():
            args.extend(["--config", config_path])
        args.append(command)
        if inputs := shlex.split(self.trustmitre_vars['inputs'].get()): args.extend(inputs)
        if command == "download" and self.trustmitre_vars['force'].get(): args.append("--force")
        if command == "ingest":
            if evtx_paths := shlex.split(self.trustmitre_vars['evtx'].get()): args.extend(["--evtx", *evtx_paths])
            if self.trustmitre_vars['live'].get(): args.append("--live")
            if output_path := self.trustmitre_vars['output'].get().strip(): args.extend(["--output", output_path])
        if command == "run":
            for item in shlex.split(self.trustmitre_vars['include'].get()): args.extend(["--include", item])
            for item in shlex.split(self.trustmitre_vars['exclude'].get()): args.extend(["--exclude", item])
            if workers := self.trustmitre_vars['workers'].get().strip(): args.extend(["--workers", workers])
            if batch_size := self.trustmitre_vars['batch_size'].get().strip(): args.extend(["--batch-size", batch_size])

        self.history.add('trustmitre', command, {k: v.get() for k, v in self.trustmitre_vars.items()})
        analytics_dir = get_resource_path("trusMITRE", "analytics")
        env_updates = {}
        if analytics_dir.exists():
            env_updates["TRUSTMITRE_ANALYTICS_DIR"] = str(analytics_dir)
        workdir = self.work_root
        self.run_tool_async("trustmitre", args, self.invoke_trustmitre, self.trustmitre_output, workdir, env_updates=env_updates or None)

    def show_about_window(self):
        about_win = tk.Toplevel(self.root)
        about_win.title("About PYMEs Toolkit")
        about_win.geometry("400x220")
        about_win.transient(self.root)
        about_win.grab_set()
        about_win.resizable(False, False)
        about_win.configure(background='#f0f0f0')

        content_frame = ttk.Frame(about_win, padding=15)
        content_frame.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(content_frame, text="PYMEs Unified Security Toolkit", font=('Helvetica', 14, 'bold'))
        title.pack(pady=(0, 10))

        info_texts = [
            "Version 1.0.0",
            "Author: Volodymyr Dubetskyy",
            "Organization: TRUST Lab UPCT"
        ]
        for text in info_texts:
            ttk.Label(content_frame, text=text).pack(pady=2)

        ttk.Separator(content_frame, orient='horizontal').pack(fill='x', pady=15)

        ok_button = ttk.Button(content_frame, text="OK", command=about_win.destroy)
        ok_button.pack()
        ok_button.focus_set()

        about_win.wait_window()

    def create_option_row(self, parent, row, label_text, variable, control_type, **kwargs):
        label = ttk.Label(parent, text=label_text)
        label.grid(row=row, column=0, sticky=tk.W, padx=(0, 10), pady=4)
        tooltip = kwargs.get('tooltip')

        if control_type == 'entry':
            widget = ttk.Entry(parent, textvariable=variable, width=kwargs.get('width', 35))
            widget.grid(row=row, column=1, sticky=tk.EW, pady=4)
        elif control_type == 'combo':
            widget = ttk.Combobox(parent, textvariable=variable, values=kwargs.get('options', []), width=kwargs.get('width', 33), state='readonly')
            if not variable.get() and kwargs.get('options'): widget.set(kwargs['options'][0])
            widget.grid(row=row, column=1, sticky=tk.EW, pady=4)
        elif control_type == 'radio':
            widget = ttk.Frame(parent)
            widget.grid(row=row, column=1, sticky=tk.W, pady=4)
            for option in kwargs.get('options', []):
                ttk.Radiobutton(widget, text=option, variable=variable, value=option).pack(side=tk.LEFT, padx=(0, 10))
        elif control_type in {'file', 'files', 'save_file', 'directory'}:
            widget = ttk.Entry(parent, textvariable=variable, width=kwargs.get('width', 30))
            widget.grid(row=row, column=1, sticky=tk.EW, pady=4)
            btn = ttk.Button(parent, text="...", command=lambda: self._handle_browse(control_type, variable), width=3)
            btn.grid(row=row, column=2, padx=(4, 0), pady=4)
            if tooltip: ModernTooltip(btn, f"Browse for {control_type}")
        else: return

        if tooltip: ModernTooltip(widget, tooltip)
        parent.columnconfigure(1, weight=1)

    def _handle_browse(self, control_type, variable):
        try:
            path = ""
            if control_type == 'directory': path = filedialog.askdirectory(parent=self.root)
            elif control_type == 'file': path = filedialog.askopenfilename(parent=self.root)
            elif control_type == 'save_file': path = filedialog.asksaveasfilename(parent=self.root)
            elif control_type == 'files': paths = filedialog.askopenfilenames(parent=self.root); path = " ".join(paths) if paths else ""
            if path: variable.set(path)
        except Exception as e: messagebox.showerror("Error", f"File dialog failed: {e}", parent=self.root)

    def open_folder(self, path):
        target = Path(path)
        if not target.is_absolute():
            target = (self.work_root / target).resolve()
        if not target.exists(): target.mkdir(parents=True, exist_ok=True)
        try:
            if platform.system() == "Windows": os.startfile(str(target))
            elif platform.system() == "Darwin": subprocess.Popen(["open", str(target)])
            else: subprocess.Popen(["xdg-open", str(target)])
        except Exception as e: messagebox.showerror("Error", f"Failed to open folder: {e}", parent=self.root)

    def show_history(self):
        self.refresh_dashboard_history()
        self.notebook.select(0)
        messagebox.showinfo("Command History", "Recent command history is shown on the dashboard.", parent=self.root)

    def invoke_truslan(self, args):
        import truslan.cli as truslan_cli
        with self.argv_lock:
            original_argv = sys.argv[:]
            sys.argv = ["truslan", *args]
            try:
                return truslan_cli.main()
            finally:
                sys.argv = original_argv

    def invoke_trusclamav(self, args):
        from trusClamAV import cli as clam_cli
        return clam_cli.main(args)

    def invoke_trustmitre(self, args):
        from trustmitre import cli as trustmitre_cli
        return trustmitre_cli.app(args=args)

    def _append_output(self, output_widget, text):
        self.root.after(0, lambda: (output_widget.insert(tk.END, text), output_widget.see(tk.END)))

    def run_tool_async(self, tool_name, args, runner, output_widget, workdir=None, env_updates=None):
        output_widget.clear_output()
        cmd_str = ' '.join(shlex.quote(str(c)) for c in ([tool_name] + args))
        workdir_display = str(workdir or Path.cwd())
        output_widget.insert(tk.END, f"Executing: {cmd_str}\nWorking Directory: {workdir_display}\n\n", 'command')
        self.update_status(f"Running {tool_name}...", 'running', show_progress=True)

        def worker():
            exit_code = 0
            prev_cwd = Path.cwd()
            env_snapshot = {k: os.environ.get(k) for k in (env_updates or {})}
            stream = StreamRedirect(output_widget, self.root)
            try:
                if workdir:
                    os.chdir(workdir)
                if env_updates:
                    for key, value in env_updates.items():
                        os.environ[key] = str(value)
                with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                    result = runner(args)
                    if isinstance(result, int):
                        exit_code = result
            except SystemExit as exc:
                exit_code = exc.code if isinstance(exc.code, int) else 1
            except Exception as exc:
                exit_code = 1
                self._append_output(output_widget, f"An unexpected error occurred: {exc}\n")
            finally:
                if env_updates is not None:
                    for key, original in env_snapshot.items():
                        if original is None:
                            os.environ.pop(key, None)
                        else:
                            os.environ[key] = original
                os.chdir(prev_cwd)
                status_text = "completed successfully" if exit_code == 0 else f"finished with code {exit_code}"
                self.root.after(0, lambda: self.update_status(f"{tool_name} {status_text}", 'success' if exit_code == 0 else 'error'))
                self.root.after(0, self.refresh_dashboard_history)
                with self.task_lock:
                    current = threading.current_thread()
                    if current in self.running_tasks:
                        self.running_tasks.remove(current)

        thread = threading.Thread(target=worker, daemon=True)
        with self.task_lock:
            self.running_tasks.append(thread)
        thread.start()

    def on_close(self):
        with self.task_lock:
            active = [t for t in self.running_tasks if t.is_alive()]
        if active:
            if messagebox.askyesno("Confirm Exit", "Tasks are still running. Exit anyway?", parent=self.root):
                self.root.destroy()
        else:
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PYMEsUnifiedUI(root)
    root.mainloop()
