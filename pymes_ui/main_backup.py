#!/usr/bin/env python3
"""
PYMEs Unified UI - Interface for TrusLAN, trusClamAV, and trustMITRE.

Author: Volodymyr Dubetskyy
Organization: Trust Lab UPCT
(c) 2025 Trust Lab UPCT

Provides a consolidated front-end with command history, tooltips, and enhanced
output management.
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
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
from collections import deque

# Status prefixes used across the toolkit
STATUS_INFO = "[INFO]"
STATUS_OK = "[OK]"
STATUS_WARN = "[WARN]"
STATUS_ERROR = "[ERROR]"


class ModernTooltip:
    """Modern tooltip implementation with styling"""
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

        label = tk.Label(
            self.tooltip_window,
            text=self.text,
            justify=tk.LEFT,
            background="#2d3436",
            foreground="#dfe6e9",
            relief=tk.SOLID,
            borderwidth=1,
            font=("Helvetica", 9),
            padx=10,
            pady=5
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
        """Add command to history"""
        entry = {
            'tool': tool,
            'command': command,
            'options': options,
            'timestamp': datetime.now().isoformat()
        }
        self.history.append(entry)
        self.save()

    def get_recent(self, tool=None, limit=10):
        """Get recent commands"""
        items = list(self.history)
        if tool:
            items = [i for i in items if i['tool'] == tool]
        return list(reversed(items))[:limit]

    def save(self):
        """Save history to file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(list(self.history), f, indent=2)
        except Exception:
            pass

    def load(self):
        """Load history from file"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    self.history = deque(data, maxlen=self.max_size)
        except Exception:
            pass


class EnhancedOutput(tk.Frame):
    """Enhanced output widget with search, export, and color coding"""
    def __init__(self, parent, **kwargs):
        super().__init__(parent)

        # Toolbar
        toolbar = tk.Frame(self, bg='#ecf0f1', height=35)
        toolbar.pack(fill=tk.X, side=tk.TOP)
        toolbar.pack_propagate(False)

        # Search
        tk.Label(toolbar, text="", bg='#ecf0f1', font=('Helvetica', 12)).pack(side=tk.LEFT, padx=(10, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.highlight_search)
        search_entry = tk.Entry(toolbar, textvariable=self.search_var, width=20, font=('Helvetica', 9))
        search_entry.pack(side=tk.LEFT, padx=(0, 10))
        ModernTooltip(search_entry, "Search in output (highlights matches)")

        # Buttons
        tk.Button(
            toolbar,
            text="Copy",
            command=self.copy_output,
            relief=tk.FLAT,
            bg='#ecf0f1',
            font=('Helvetica', 9),
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=2)

        tk.Button(
            toolbar,
            text="Export",
            command=self.export_output,
            relief=tk.FLAT,
            bg='#ecf0f1',
            font=('Helvetica', 9),
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=2)

        tk.Button(
            toolbar,
            text="Clear",
            command=self.clear_output,
            relief=tk.FLAT,
            bg='#ecf0f1',
            font=('Helvetica', 9),
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=2)

        # Text widget
        self.text = scrolledtext.ScrolledText(
            self,
            wrap=tk.WORD,
            font=('Consolas', 9),
            relief=tk.FLAT,
            borderwidth=0,
            **kwargs
        )
        self.text.pack(fill=tk.BOTH, expand=True)

        # Configure tags for syntax highlighting
        self.text.tag_config('error', foreground='#e74c3c', font=('Consolas', 9, 'bold'))
        self.text.tag_config('warning', foreground='#f39c12', font=('Consolas', 9, 'bold'))
        self.text.tag_config('success', foreground='#27ae60', font=('Consolas', 9, 'bold'))
        self.text.tag_config('info', foreground='#3498db', font=('Consolas', 9, 'bold'))
        self.text.tag_config('command', foreground='#9b59b6', font=('Consolas', 9, 'bold'))
        self.text.tag_config('highlight', background='#f1c40f')
        self.text.tag_config('timestamp', foreground='#95a5a6', font=('Consolas', 8))

    def insert(self, index, text, tags=None):
        """Insert text with automatic syntax highlighting"""
        self.text.insert(index, text)

        # Auto-detect log levels and apply tags
        lines = text.split('\n')
        current_line = float(index.split('.')[0]) if '.' in str(index) else 1.0

        for line in lines:
            line_start = f"{int(current_line)}.0"
            line_end = f"{int(current_line)}.end"

            if re.search(r'\[ERROR\]|ERROR:|error:', line, re.IGNORECASE):
                self.text.tag_add('error', line_start, line_end)
            elif re.search(r'\[WARNING\]|WARNING:|warning:', line, re.IGNORECASE):
                self.text.tag_add('warning', line_start, line_end)
            elif re.search(r'\[OK\]|SUCCESS:|success:', line, re.IGNORECASE):
                self.text.tag_add('success', line_start, line_end)
            elif re.search(r'\[INFO\]|INFO:|info:', line, re.IGNORECASE):
                self.text.tag_add('info', line_start, line_end)
            elif line.startswith('Executing:') or line.startswith('Command:'):
                self.text.tag_add('command', line_start, line_end)
            elif re.search(r'\d{2}:\d{2}:\d{2}', line):
                self.text.tag_add('timestamp', line_start, line_end)

            current_line += 1

    def highlight_search(self, *args):
        """Highlight search matches"""
        self.text.tag_remove('highlight', '1.0', tk.END)
        search_text = self.search_var.get()

        if not search_text:
            return

        start = '1.0'
        while True:
            pos = self.text.search(search_text, start, tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(search_text)}c"
            self.text.tag_add('highlight', pos, end)
            start = end

    def copy_output(self):
        """Copy all output to clipboard"""
        try:
            content = self.text.get('1.0', tk.END)
            self.clipboard_clear()
            self.clipboard_append(content)
            messagebox.showinfo("Success", "Output copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {str(e)}")

    def export_output(self):
        """Export output to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[
                    ("Text Files", "*.txt"),
                    ("Log Files", "*.log"),
                    ("All Files", "*.*")
                ]
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(self.text.get('1.0', tk.END))
                messagebox.showinfo("Success", f"Output exported to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def clear_output(self):
        """Clear all output"""
        self.text.delete('1.0', tk.END)

    def see(self, index):
        """Scroll to position"""
        self.text.see(index)

    def get(self, start, end):
        """Get text content"""
        return self.text.get(start, end)


class ModernCard(tk.Frame):
    """Modern card widget with shadow effect"""
    def __init__(self, parent, title=None, **kwargs):
        super().__init__(parent, **kwargs)

        # Configure card styling
        self.configure(bg='white', relief=tk.FLAT, borderwidth=0)

        # Add subtle shadow effect using a frame
        shadow = tk.Frame(parent, bg='#bdc3c7', relief=tk.FLAT)
        shadow.place(x=2, y=2, relwidth=1, relheight=1)
        self.lift()

        if title:
            header = tk.Frame(self, bg='#ecf0f1', height=40)
            header.pack(fill=tk.X, side=tk.TOP)
            header.pack_propagate(False)

            tk.Label(
                header,
                text=title,
                font=('Helvetica', 11, 'bold'),
                bg='#ecf0f1',
                fg='#2c3e50'
            ).pack(side=tk.LEFT, padx=15, pady=10)


class PYMEsUnifiedUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PYMEs Unified Security Toolkit")
        self.root.geometry("920x700")
        self.root.minsize(760, 560)

        # Command history
        self.history = CommandHistory()

        # Setup styling
        self.setup_styling()
        self.root.configure(bg=self.colors['bg'])

        # Determine base paths
        self.base_path = Path(__file__).parent.parent
        self.truslan_path = self.base_path / "truslan"
        self.trusclamav_path = self.base_path / "trusClamAV"
        self.trustmitre_path = self.base_path / "trusMITRE"

        # Store venv paths
        self.truslan_venv = self.truslan_path / ".venv"
        self.trusclamav_venv = self.trusclamav_path / ".venv"
        self.trustmitre_venv = self.trustmitre_path / ".venv"

        # Get Python executable
        self.python_executable = self.get_python_executable()

        # Running processes
        self.running_processes = []
        self.process_lock = threading.Lock()

        # Create UI
        self.create_header()
        self.create_quick_actions()
        self.create_notebook()
        self.create_status_bar()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    def setup_styling(self):
        """Setup modern Material Design styling"""
        style = ttk.Style()

        # Use clam as base theme
        available_themes = style.theme_names()
        if 'clam' in available_themes:
            style.theme_use('clam')
        elif 'alt' in available_themes:
            style.theme_use('alt')

        self.colors = {
            'primary': '#2980b9',
            'primary_dark': '#1f618d',
            'secondary': '#16a085',
            'success': '#27ae60',
            'danger': '#e74c3c',
            'warning': '#f39c12',
            'info': '#3498db',
            'light': '#ecf0f1',
            'dark': '#2c3e50',
            'bg': '#f5f6fa',
            'card': '#ffffff',
            'text': '#2c3e50',
            'text_secondary': '#7f8c8d',
            'border': '#bdc3c7',
            'header': '#34495e',
            'hover': '#3498db'
        }

        # Configure base styles
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['text'])
        style.configure('TButton', padding=(15, 8), font=('Helvetica', 10))
        style.configure('TCheckbutton', background=self.colors['bg'], foreground=self.colors['text'])
        style.configure('TRadiobutton', background=self.colors['bg'], foreground=self.colors['text'])

        # Header styles
        style.configure('Header.TFrame', background=self.colors['header'])
        style.configure('Header.TLabel', background=self.colors['header'],
                       foreground='white', font=('Helvetica', 22, 'bold'))
        style.configure('Subtitle.TLabel', background=self.colors['header'],
                       foreground='#95a5a6', font=('Helvetica', 11))

        # Card styles
        style.configure('Card.TFrame', background=self.colors['card'], relief=tk.FLAT)
        style.configure('CardTitle.TLabel', background=self.colors['card'],
                       foreground=self.colors['primary'], font=('Helvetica', 12, 'bold'))

        # Button styles
        style.configure('Action.TButton', padding=(20, 10), font=('Helvetica', 11, 'bold'))
        style.configure('Primary.TButton', background=self.colors['primary'])
        style.configure('Success.TButton', background=self.colors['success'])
        style.configure('Danger.TButton', background=self.colors['danger'])

        # Section styles
        style.configure('Section.TLabelframe', padding=20, background=self.colors['card'])
        style.configure('Section.TLabelframe.Label', font=('Helvetica', 12, 'bold'),
                       foreground=self.colors['primary'], background=self.colors['card'])

        # Notebook styles
        style.configure('TNotebook', background=self.colors['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', padding=(20, 12), font=('Helvetica', 10, 'bold'))

    def get_python_executable(self, tool_venv=None):
        """Get appropriate Python executable"""
        if tool_venv and tool_venv.exists():
            if platform.system() == "Windows":
                venv_python = tool_venv / "Scripts" / "python.exe"
            else:
                venv_python = tool_venv / "bin" / "python"
            if venv_python.exists():
                return str(venv_python)

        if self.trustmitre_venv.exists():
            if platform.system() == "Windows":
                venv_python = self.trustmitre_venv / "Scripts" / "python.exe"
            else:
                venv_python = self.trustmitre_venv / "bin" / "python"
            if venv_python.exists():
                return str(venv_python)

        return sys.executable

    def create_header(self):
        """Create modern header with branding"""
        header_frame = ttk.Frame(self.root, style='Header.TFrame', height=120)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        content_frame = ttk.Frame(header_frame, style='Header.TFrame')
        content_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        title_label = ttk.Label(
            content_frame,
            text="PYMEs Unified Security Toolkit",
            style='Header.TLabel'
        )
        title_label.pack(pady=(0, 5))

        subtitle = ttk.Label(
            content_frame,
            text="TrusLAN | trusClamAV | trustMITRE | Trust Lab UPCT",
            style='Subtitle.TLabel'
        )
        subtitle.pack()

    def create_quick_actions(self):
        """Create quick actions toolbar"""
        toolbar = tk.Frame(self.root, bg=self.colors['light'], height=50, relief=tk.FLAT)
        toolbar.pack(fill=tk.X, pady=(0, 0))
        toolbar.pack_propagate(False)

        # Left side - Quick actions
        left_frame = tk.Frame(toolbar, bg=self.colors['light'])
        left_frame.pack(side=tk.LEFT, padx=15, pady=10)

        actions = [
            ("Dashboard", self.show_dashboard, "View system status and recent activity"),
            ("History", self.show_history, "View command history"),
            ("Settings", self.show_settings, "Configure application settings"),
        ]

        for text, command, tooltip in actions:
            btn = tk.Button(
                left_frame,
                text=text,
                command=command,
                relief=tk.FLAT,
                bg=self.colors['light'],
                fg=self.colors['text'],
                font=('Helvetica', 9),
                cursor='hand2',
                padx=12,
                pady=5
            )
            btn.pack(side=tk.LEFT, padx=6)
            ModernTooltip(btn, tooltip)
            btn.bind('<Enter>', lambda e, b=btn: b.config(bg=self.colors['primary'], fg='white'))
            btn.bind('<Leave>', lambda e, b=btn: b.config(bg=self.colors['light'], fg=self.colors['text']))

        tk.Frame(toolbar, bg=self.colors['light']).pack(side=tk.RIGHT, padx=10)

    def create_notebook(self):
        """Create modern tabbed interface"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(10, 10))

        # Create tabs
        self.create_dashboard_tab()
        self.create_truslan_tab()
        self.create_trusclamav_tab()
        self.create_trustmitre_tab()
        self.create_about_tab()

    def create_status_bar(self):
        """Create modern status bar"""
        self.status_frame = tk.Frame(self.root, bg=self.colors['header'], height=40)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_frame.pack_propagate(False)

        # Status icon
        self.status_icon = tk.Label(
            self.status_frame,
            text=STATUS_OK,
            bg=self.colors['header'],
            fg=self.colors['success'],
            font=('Helvetica', 14, 'bold')
        )
        self.status_icon.pack(side=tk.LEFT, padx=(15, 5), pady=8)

        # Status text
        self.status_label = tk.Label(
            self.status_frame,
            text="Ready",
            bg=self.colors['header'],
            fg='white',
            font=('Helvetica', 10),
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=8)

        # Progress bar
        self.progress_bar = ttk.Progressbar(
            self.status_frame,
            mode='indeterminate',
            length=200
        )
        self.progress_bar.pack(side=tk.RIGHT, padx=15, pady=8)

        # Details button
        self.details_btn = tk.Button(
            self.status_frame,
            text="Details",
            command=self.show_status_details,
            relief=tk.FLAT,
            bg=self.colors['header'],
            fg='white',
            font=('Helvetica', 9),
            cursor='hand2',
            state=tk.DISABLED
        )
        self.details_btn.pack(side=tk.RIGHT, padx=5, pady=8)

    def update_status(self, message, status_type='info', show_progress=False):
        """Update status bar with enhanced feedback"""
        icons = {
            'info': STATUS_INFO,
            'success': STATUS_OK,
            'warning': STATUS_WARN,
            'error': STATUS_ERROR,
            'running': STATUS_INFO
        }

        colors = {
            'info': self.colors['info'],
            'success': self.colors['success'],
            'warning': self.colors['warning'],
            'error': self.colors['danger'],
            'running': self.colors['primary']
        }

        self.status_icon.config(
            text=icons.get(status_type, ''),
            fg=colors.get(status_type, self.colors['info'])
        )
        self.status_label.config(
            text=f"{datetime.now().strftime('%H:%M:%S')} - {message}"
        )

        if show_progress:
            self.progress_bar.start(10)
            self.details_btn.config(state=tk.NORMAL)
        else:
            self.progress_bar.stop()
            self.details_btn.config(state=tk.DISABLED)

        self.root.update_idletasks()

    def show_status_details(self):
        """Show detailed status information"""
        details = f"Running processes: {len(self.running_processes)}\n"
        details += f"Python: {self.python_executable}\n"
        details += f"Platform: {platform.platform()}\n"
        messagebox.showinfo("Status Details", details)

    # ==================== DASHBOARD TAB ====================

    def create_dashboard_tab(self):
        """Create modern dashboard with overview"""
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="Dashboard")

        content = tk.Frame(tab, bg=self.colors['bg'])
        content.pack(fill=tk.BOTH, expand=True)

        # Welcome section
        welcome_frame = tk.Frame(content, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        welcome_frame.pack(fill=tk.X, padx=20, pady=(20, 10))

        tk.Label(
            welcome_frame,
            text="Welcome to PYMEs Security Toolkit",
            font=('Helvetica', 16, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['primary']
        ).pack(anchor=tk.W, padx=20, pady=(20, 5))

        tk.Label(
            welcome_frame,
            text="Unified interface for network scanning, malware detection, and threat analytics",
            font=('Helvetica', 10),
            bg=self.colors['card'],
            fg=self.colors['text_secondary']
        ).pack(anchor=tk.W, padx=20, pady=(0, 20))

        # Quick start cards
        cards_frame = tk.Frame(content, bg=self.colors['bg'])
        cards_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        tools = [
            {
                'name': 'TrusLAN',
                'desc': 'Network Security Scanner',
                'action': 'Scan networks for vulnerabilities',
                'tab': 1
            },
            {
                'name': 'trusClamAV',
                'desc': 'Malware Detection',
                'action': 'Scan files for malware',
                'tab': 2
            },
            {
                'name': 'trustMITRE',
                'desc': 'Threat Analytics',
                'action': 'Analyze security logs',
                'tab': 3
            }
        ]

        for i, tool in enumerate(tools):
            card = tk.Frame(cards_frame, bg=self.colors['card'], relief=tk.RAISED, bd=1)
            card.grid(row=0, column=i, padx=10, pady=10, sticky='nsew')

            tk.Label(
                card,
                text=tool['name'],
                font=('Helvetica', 14, 'bold'),
                bg=self.colors['card'],
                fg=self.colors['primary']
            ).pack()

            tk.Label(
                card,
                text=tool['desc'],
                font=('Helvetica', 9),
                bg=self.colors['card'],
                fg=self.colors['text_secondary']
            ).pack(pady=(5, 15))

            btn = tk.Button(
                card,
                text=tool['action'],
                command=lambda t=tool['tab']: self.notebook.select(t),
                bg=self.colors['primary'],
                fg='white',
                font=('Helvetica', 9, 'bold'),
                relief=tk.FLAT,
                cursor='hand2',
                padx=20,
                pady=8
            )
            btn.pack(pady=(0, 20))

            btn.bind('<Enter>', lambda e, b=btn: b.config(bg=self.colors['primary_dark']))
            btn.bind('<Leave>', lambda e, b=btn: b.config(bg=self.colors['primary']))

        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)
        cards_frame.columnconfigure(2, weight=1)

        # System information
        sys_frame = tk.Frame(content, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        sys_frame.pack(fill=tk.X, padx=20, pady=(10, 20))

        tk.Label(
            sys_frame,
            text="System Information",
            font=('Helvetica', 12, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['primary']
        ).pack(anchor=tk.W, padx=20, pady=(15, 10))

        info_items = [
            ("Operating System", platform.system()),
            ("Platform", platform.platform()),
            ("Python Version", platform.python_version()),
            ("Working Directory", str(self.base_path))
        ]

        for label, value in info_items:
            row = tk.Frame(sys_frame, bg=self.colors['card'])
            row.pack(fill=tk.X, padx=20, pady=2)

            tk.Label(
                row,
                text=f"{label}:",
                font=('Helvetica', 9, 'bold'),
                bg=self.colors['card'],
                fg=self.colors['text'],
                width=20,
                anchor=tk.W
            ).pack(side=tk.LEFT)

            tk.Label(
                row,
                text=value,
                font=('Helvetica', 9),
                bg=self.colors['card'],
                fg=self.colors['text_secondary'],
                anchor=tk.W
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Frame(sys_frame, height=15, bg=self.colors['card']).pack()

    # ==================== TRUSLAN TAB ====================

    def create_truslan_tab(self):
        """Create enhanced TrusLAN tab"""
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="TrusLAN")

        # Create scrollable frame
        canvas = tk.Canvas(tab, highlightthickness=0, bg=self.colors['bg'])
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='TFrame')

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Info card
        info_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        info_card.pack(fill=tk.X, padx=20, pady=(15, 10))

        tk.Label(
            info_card,
            text="TrusLAN - Network Security Scanner",
            font=('Helvetica', 14, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['primary']
        ).pack(anchor=tk.W, padx=20, pady=(15, 5))

        tk.Label(
            info_card,
            text="Identifies security vulnerabilities across SMB, RDP, HTTP, TLS, SSH, UDP protocols.\n"
                 "Supports Safe, Standard, and Aggressive scanning profiles.",
            font=('Helvetica', 9),
            bg=self.colors['card'],
            fg=self.colors['text_secondary'],
            justify=tk.LEFT
        ).pack(anchor=tk.W, padx=20, pady=(0, 15))

        # Command selection
        cmd_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        cmd_card.pack(fill=tk.X, padx=20, pady=(0, 10))

        tk.Label(
            cmd_card,
            text="Select Command",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(15, 10))

        cmd_frame = tk.Frame(cmd_card, bg=self.colors['card'])
        cmd_frame.pack(fill=tk.X, padx=20, pady=(0, 15))

        self.truslan_command = tk.StringVar(value="discover")
        commands = [
            ("Discover", "discover", "Auto-detect networks"),
            ("Scan", "scan", "Security scan networks"),
            ("Report", "report", "Generate HTML/CSV reports"),
            ("All-in-One", "all", "Discovery + Scan + Report"),
            ("Scripts", "list-scripts", "List NSE scripts")
        ]

        for i, (text, value, tooltip) in enumerate(commands):
            rb = ttk.Radiobutton(
                cmd_frame,
                text=text,
                variable=self.truslan_command,
                value=value,
                command=self.update_truslan_options
            )
            rb.grid(row=0, column=i, padx=10, pady=5, sticky=tk.W)
            ModernTooltip(rb, tooltip)

        # Options frame
        self.truslan_options_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        self.truslan_options_card.pack(fill=tk.X, padx=20, pady=(0, 10))

        tk.Label(
            self.truslan_options_card,
            text="Options",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(15, 10))

        self.truslan_options_frame = tk.Frame(self.truslan_options_card, bg=self.colors['card'])
        self.truslan_options_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))

        # Initialize variables
        self.truslan_vars = {
            'cidr': tk.StringVar(value="192.168.1.0/24"),
            'profile': tk.StringVar(value="safe"),
            'mode': tk.StringVar(value="top"),
            'top_ports': tk.StringVar(value="1000"),
            'ports': tk.StringVar(value="22,80,443,445,3389"),
            'timing': tk.StringVar(value="T3"),
            'output_dir': tk.StringVar(value="./output"),
            'auto_cidr': tk.BooleanVar(value=False),
            'use_udp': tk.BooleanVar(value=False),
            'trust_discovery': tk.BooleanVar(value=False),
            'save_xml': tk.BooleanVar(value=False),
            'authorized': tk.BooleanVar(value=False),
            'json_file': tk.StringVar(value="")
        }

        self.update_truslan_options()

        # Output
        output_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        output_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))

        tk.Label(
            output_card,
            text="Output Console",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(15, 10))

        self.truslan_output = EnhancedOutput(output_card, height=15)
        self.truslan_output.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))

        # Action buttons
        btn_frame = tk.Frame(scrollable_frame, bg=self.colors['bg'])
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))

        run_btn = tk.Button(
            btn_frame,
            text="Run Command",
            command=self.run_truslan,
            bg=self.colors['success'],
            fg='white',
            font=('Helvetica', 11, 'bold'),
            relief=tk.FLAT,
            cursor='hand2',
            padx=25,
            pady=10
        )
        run_btn.pack(side=tk.LEFT, padx=(0, 10))
        run_btn.bind('<Enter>', lambda e: run_btn.config(bg='#229954'))
        run_btn.bind('<Leave>', lambda e: run_btn.config(bg=self.colors['success']))
        ModernTooltip(run_btn, "Execute the selected command")

        history_btn = tk.Button(
            btn_frame,
            text="History",
            command=lambda: self.show_tool_history('truslan'),
            bg=self.colors['info'],
            fg='white',
            font=('Helvetica', 10),
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=10
        )
        history_btn.pack(side=tk.LEFT, padx=(0, 10))
        history_btn.bind('<Enter>', lambda e: history_btn.config(bg='#2471a3'))
        history_btn.bind('<Leave>', lambda e: history_btn.config(bg=self.colors['info']))

        folder_btn = tk.Button(
            btn_frame,
            text="Open Output",
            command=lambda: self.open_folder(self.truslan_vars['output_dir'].get()),
            bg=self.colors['primary'],
            fg='white',
            font=('Helvetica', 10),
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=10
        )
        folder_btn.pack(side=tk.LEFT)
        folder_btn.bind('<Enter>', lambda e: folder_btn.config(bg=self.colors['primary_dark']))
        folder_btn.bind('<Leave>', lambda e: folder_btn.config(bg=self.colors['primary']))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def update_truslan_options(self):
        """Update TrusLAN options dynamically"""
        for widget in self.truslan_options_frame.winfo_children():
            widget.destroy()

        command = self.truslan_command.get()
        row = 0

        if command in ["discover", "list-scripts"]:
            tk.Label(
                self.truslan_options_frame,
                text="No additional options required for this command.",
                font=('Helvetica', 9, 'italic'),
                bg=self.colors['card'],
                fg=self.colors['text_secondary']
            ).grid(row=0, column=0, sticky=tk.W, pady=10)
            return

        if command in ["scan", "all"]:
            if command == "scan":
                self.create_option_row(self.truslan_options_frame, row, "Target Network (CIDR):",
                                     self.truslan_vars['cidr'], 'entry', width=40,
                                     tooltip="Network to scan (e.g., 192.168.1.0/24)")
                row += 1
            else:
                cb = ttk.Checkbutton(
                    self.truslan_options_frame,
                    text="Auto-discover network CIDRs",
                    variable=self.truslan_vars['auto_cidr']
                )
                cb.grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=8)
                ModernTooltip(cb, "Automatically detect local networks")
                row += 1

                self.create_option_row(self.truslan_options_frame, row, "Manual CIDR (if not auto):",
                                     self.truslan_vars['cidr'], 'entry', width=40,
                                     tooltip="Override auto-discovery with specific CIDR")
                row += 1

            # Profile
            self.create_option_row(self.truslan_options_frame, row, "Scan Profile:",
                                 self.truslan_vars['profile'], 'radio',
                                 options=["safe", "standard", "aggressive"],
                                 tooltip="Safe: Quick scan | Standard: Balanced | Aggressive: Deep scan (requires authorization)")
            row += 1

            # Mode
            self.create_option_row(self.truslan_options_frame, row, "Port Mode:",
                                 self.truslan_vars['mode'], 'radio',
                                 options=["top", "ports"],
                                 tooltip="Top: Scan most common ports | Ports: Scan specific port list")
            row += 1

            self.create_option_row(self.truslan_options_frame, row, "Top Ports (if mode=top):",
                                 self.truslan_vars['top_ports'], 'entry', width=15,
                                 tooltip="Number of most common ports to scan")
            row += 1

            self.create_option_row(self.truslan_options_frame, row, "Port List (if mode=ports):",
                                 self.truslan_vars['ports'], 'entry', width=40,
                                 tooltip="Comma-separated port numbers")
            row += 1

            self.create_option_row(self.truslan_options_frame, row, "Timing Template:",
                                 self.truslan_vars['timing'], 'combo',
                                 options=["T0", "T1", "T2", "T3", "T4", "T5"],
                                 tooltip="T0=Paranoid (slowest) to T5=Insane (fastest)")
            row += 1

            # Checkboxes
            for var, text, tip in [
                (self.truslan_vars['use_udp'], "Enable UDP scanning", "Scan UDP ports (requires elevated privileges)"),
                (self.truslan_vars['trust_discovery'], "Trust discovery (-Pn)", "Skip host discovery, assume all hosts are up"),
                (self.truslan_vars['save_xml'], "Save XML output", "Save raw Nmap XML files"),
                (self.truslan_vars['authorized'], "I am authorized (required for aggressive)", "Confirm authorization for aggressive scans")
            ]:
                cb = ttk.Checkbutton(self.truslan_options_frame, text=text, variable=var)
                cb.grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=6)
                ModernTooltip(cb, tip)
                row += 1

        elif command == "report":
            self.create_option_row(self.truslan_options_frame, row, "Scan JSON File:",
                                 self.truslan_vars['json_file'], 'file',
                                 tooltip="Previously generated scan.json file")
            row += 1

        if command in ["scan", "all", "report"]:
            self.create_option_row(self.truslan_options_frame, row, "Output Directory:",
                                 self.truslan_vars['output_dir'], 'directory',
                                 tooltip="Where to save results")

    def run_truslan(self):
        """Execute TrusLAN command"""
        command = self.truslan_command.get()
        python_exec = self.get_python_executable(self.truslan_venv)
        cmd = [python_exec, "-m", "truslan", command]

        if command in ["scan", "all"]:
            if command == "all" and self.truslan_vars['auto_cidr'].get():
                cmd.append("--auto-cidr")
            elif command == "scan" or not self.truslan_vars['auto_cidr'].get():
                cidr = self.truslan_vars['cidr'].get().strip()
                if cidr:
                    cmd.extend(["--cidr", cidr])

            cmd.extend(["--profile", self.truslan_vars['profile'].get()])
            cmd.extend(["--mode", self.truslan_vars['mode'].get()])

            if self.truslan_vars['mode'].get() == "top":
                cmd.extend(["--top", self.truslan_vars['top_ports'].get()])
            else:
                cmd.extend(["--ports", self.truslan_vars['ports'].get()])

            cmd.extend(["--timing", self.truslan_vars['timing'].get()])

            if self.truslan_vars['use_udp'].get():
                cmd.append("--udp")
            if self.truslan_vars['trust_discovery'].get():
                cmd.append("--trust-discovery")
            if self.truslan_vars['save_xml'].get():
                cmd.append("--save-xml")
            if self.truslan_vars['authorized'].get():
                cmd.append("--i-am-authorized")

            out_dir = self.truslan_vars['output_dir'].get().strip()
            if out_dir:
                cmd.extend(["--out", out_dir])

        elif command == "report":
            json_file = self.truslan_vars['json_file'].get().strip()
            if not json_file:
                messagebox.showerror("Error", "Please specify a JSON file")
                return
            cmd.extend(["--from-json", json_file])

            out_dir = self.truslan_vars['output_dir'].get().strip()
            if out_dir:
                cmd.extend(["--out-html", os.path.join(out_dir, "report.html")])
                cmd.extend(["--out-csv", os.path.join(out_dir, "findings.csv")])

        # Save to history
        self.history.add('truslan', command, dict(
            (k, v.get()) for k, v in self.truslan_vars.items()
        ))

        env = self.build_python_env(self.truslan_path)
        self.run_command_async(cmd, self.truslan_output, str(self.truslan_path), env=env)

    # ==================== TRUSCLAMAV TAB ====================

    def create_trusclamav_tab(self):
        """Create enhanced trusClamAV tab"""
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="trusClamAV")

        canvas = tk.Canvas(tab, highlightthickness=0, bg=self.colors['bg'])
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='TFrame')

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Info card
        info_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        info_card.pack(fill=tk.X, padx=20, pady=(15, 10))

        tk.Label(
            info_card,
            text="trusClamAV - Malware Detection",
            font=('Helvetica', 14, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['primary']
        ).pack(anchor=tk.W, padx=20, pady=(15, 5))

        tk.Label(
            info_card,
            text="Cross-platform ClamAV companion for malware scanning with structured reports.\n"
                 "Automatic installation, database updates, and real-time protection.",
            font=('Helvetica', 9),
            bg=self.colors['card'],
            fg=self.colors['text_secondary'],
            justify=tk.LEFT
        ).pack(anchor=tk.W, padx=20, pady=(0, 15))

        # Command selection
        cmd_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        cmd_card.pack(fill=tk.X, padx=20, pady=(0, 10))

        tk.Label(
            cmd_card,
            text="Select Command",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(15, 10))

        cmd_frame = tk.Frame(cmd_card, bg=self.colors['card'])
        cmd_frame.pack(fill=tk.X, padx=20, pady=(0, 15))

        self.clamav_command = tk.StringVar(value="doctor")
        commands = [
            ("Doctor", "doctor", "System diagnostics"),
            ("Install", "install", "Install ClamAV"),
            ("Update", "update", "Update virus database"),
            ("Scan", "scan", "Scan for malware"),
            ("Cleanup", "cleanup", "Remove temp files")
        ]

        for i, (text, value, tooltip) in enumerate(commands):
            rb = ttk.Radiobutton(
                cmd_frame,
                text=text,
                variable=self.clamav_command,
                value=value,
                command=self.update_clamav_options
            )
            rb.grid(row=0, column=i, padx=10, pady=5, sticky=tk.W)
            ModernTooltip(rb, tooltip)

        # Options
        self.clamav_options_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        self.clamav_options_card.pack(fill=tk.X, padx=20, pady=(0, 10))

        tk.Label(
            self.clamav_options_card,
            text="Options",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(15, 10))

        self.clamav_options_frame = tk.Frame(self.clamav_options_card, bg=self.colors['card'])
        self.clamav_options_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))

        self.clamav_vars = {
            'targets': tk.StringVar(value=""),
            'exclude': tk.StringVar(value=""),
            'output_prefix': tk.StringVar(value="./output/trusclamav/scan"),
            'use_clamd': tk.BooleanVar(value=False),
            'json_output': tk.BooleanVar(value=True),
            'retries': tk.StringVar(value="3"),
            'timeout': tk.StringVar(value="300"),
            'log_level': tk.StringVar(value="INFO")
        }

        self.update_clamav_options()

        # Output
        output_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        output_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))

        tk.Label(
            output_card,
            text="Output Console",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(15, 10))

        self.clamav_output = EnhancedOutput(output_card, height=15)
        self.clamav_output.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))

        # Buttons
        btn_frame = tk.Frame(scrollable_frame, bg=self.colors['bg'])
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))

        run_btn = tk.Button(
            btn_frame,
            text="Run Command",
            command=self.run_trusclamav,
            bg=self.colors['success'],
            fg='white',
            font=('Helvetica', 11, 'bold'),
            relief=tk.FLAT,
            cursor='hand2',
            padx=25,
            pady=10
        )
        run_btn.pack(side=tk.LEFT, padx=(0, 10))
        run_btn.bind('<Enter>', lambda e: run_btn.config(bg='#229954'))
        run_btn.bind('<Leave>', lambda e: run_btn.config(bg=self.colors['success']))

        history_btn = tk.Button(
            btn_frame,
            text="History",
            command=lambda: self.show_tool_history('trusclamav'),
            bg=self.colors['info'],
            fg='white',
            font=('Helvetica', 10),
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=10
        )
        history_btn.pack(side=tk.LEFT)
        history_btn.bind('<Enter>', lambda e: history_btn.config(bg='#2471a3'))
        history_btn.bind('<Leave>', lambda e: history_btn.config(bg=self.colors['info']))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def update_clamav_options(self):
        """Update trusClamAV options dynamically"""
        for widget in self.clamav_options_frame.winfo_children():
            widget.destroy()

        command = self.clamav_command.get()
        row = 0

        if command == "doctor":
            cb = ttk.Checkbutton(
                self.clamav_options_frame,
                text="JSON output format",
                variable=self.clamav_vars['json_output']
            )
            cb.grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=8)
            ModernTooltip(cb, "Output diagnostics in JSON format")
            row += 1

        elif command == "scan":
            self.create_option_row(self.clamav_options_frame, row, "Target Paths:",
                                 self.clamav_vars['targets'], 'directory',
                                 tooltip="Directories or files to scan (space-separated)")
            row += 1

            self.create_option_row(self.clamav_options_frame, row, "Exclude Patterns:",
                                 self.clamav_vars['exclude'], 'entry', width=40,
                                 tooltip="Glob patterns to exclude (e.g., *.log *.cache)")
            row += 1

            self.create_option_row(self.clamav_options_frame, row, "Output Prefix:",
                                 self.clamav_vars['output_prefix'], 'entry', width=40,
                                 tooltip="Base path for result files")
            row += 1

            cb = ttk.Checkbutton(
                self.clamav_options_frame,
                text="Use ClamAV daemon (clamd) - faster for repeated scans",
                variable=self.clamav_vars['use_clamd']
            )
            cb.grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=6)
            ModernTooltip(cb, "Use daemon mode for better performance")
            row += 1

        elif command == "update":
            self.create_option_row(self.clamav_options_frame, row, "Retry Attempts:",
                                 self.clamav_vars['retries'], 'entry', width=15,
                                 tooltip="Number of update retry attempts")
            row += 1

        # Common options
        self.create_option_row(self.clamav_options_frame, row, "Timeout (seconds):",
                             self.clamav_vars['timeout'], 'entry', width=15,
                             tooltip="Command timeout in seconds")
        row += 1

        self.create_option_row(self.clamav_options_frame, row, "Log Level:",
                             self.clamav_vars['log_level'], 'combo',
                             options=["DEBUG", "INFO", "WARNING", "ERROR"],
                             tooltip="Logging verbosity level")

    def run_trusclamav(self):
        """Execute trusClamAV command"""
        command = self.clamav_command.get()
        python_exec = self.get_python_executable(self.trusclamav_venv)
        cmd = [python_exec, "-m", "trusClamAV"]

        timeout = self.clamav_vars['timeout'].get().strip()
        if timeout:
            cmd.extend(["--timeout", timeout])

        log_level = self.clamav_vars['log_level'].get().strip()
        if log_level:
            cmd.extend(["--log-level", log_level])

        cmd.append(command)

        if command == "doctor":
            if self.clamav_vars['json_output'].get():
                cmd.append("--json")

        elif command == "scan":
            targets = shlex.split(self.clamav_vars['targets'].get())
            if not targets:
                messagebox.showerror("Error", "Specify at least one target to scan.")
                return
            cmd.extend(["--targets", *targets])

            exclude = shlex.split(self.clamav_vars['exclude'].get())
            if exclude:
                cmd.extend(["--exclude", *exclude])

            output_prefix = self.clamav_vars['output_prefix'].get().strip()
            if output_prefix:
                cmd.extend(["--out", output_prefix])

            if self.clamav_vars['use_clamd'].get():
                cmd.append("--use-clamd")

        elif command == "update":
            retries = self.clamav_vars['retries'].get().strip()
            if retries:
                cmd.extend(["--retries", retries])

        # Persist history
        self.history.add(
            'trusclamav',
            command,
            {k: v.get() for k, v in self.clamav_vars.items()}
        )

        env = self.build_python_env(self.trusclamav_path)
        self.run_command_async(cmd, self.clamav_output, str(self.trusclamav_path), env=env)

    # ==================== ABOUT TAB ====================

    def create_about_tab(self):
        """Create About tab with project information"""
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="About")

        canvas = tk.Canvas(tab, highlightthickness=0, bg=self.colors['bg'])
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='TFrame')

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Overview
        overview_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        overview_card.pack(fill=tk.X, padx=20, pady=(20, 10))

        tk.Label(
            overview_card,
            text="Trust Lab PYMEs Unified Security Toolkit",
            font=('Helvetica', 15, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['primary']
        ).pack(anchor=tk.W, padx=20, pady=(18, 6))

        tk.Label(
            overview_card,
            text=(
                "Integrated interface for TrusLAN, trusClamAV, and trustMITRE. "
                "Designed to accelerate endpoint hardening and incident response for small and mid-sized businesses."
            ),
            font=('Helvetica', 10),
            bg=self.colors['card'],
            fg=self.colors['text_secondary'],
            justify=tk.LEFT,
            wraplength=760
        ).pack(anchor=tk.W, padx=20, pady=(0, 16))

        # Capabilities section
        capabilities_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        capabilities_card.pack(fill=tk.X, padx=20, pady=(0, 10))

        tk.Label(
            capabilities_card,
            text="What You Can Do",
            font=('Helvetica', 12, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(16, 10))

        capability_points = [
            ("TrusLAN", "Discover exposed services and run profile-based network scans with structured reporting."),
            ("trusClamAV", "Automate ClamAV installation, updates, and scanning workflows with clean output directories."),
            ("trustMITRE", "Compile CAR analytics, ingest Windows/Linux telemetry, and generate MITRE-aligned detections.")
        ]

        for name, description in capability_points:
            frame = tk.Frame(capabilities_card, bg=self.colors['card'])
            frame.pack(fill=tk.X, padx=20, pady=6)
            tk.Label(
                frame,
                text=name,
                font=('Helvetica', 11, 'bold'),
                bg=self.colors['card'],
                fg=self.colors['primary']
            ).pack(anchor=tk.W)
            tk.Label(
                frame,
                text=description,
                font=('Helvetica', 9),
                bg=self.colors['card'],
                fg=self.colors['text_secondary'],
                justify=tk.LEFT,
                wraplength=760
            ).pack(anchor=tk.W, pady=(2, 0))

        # Getting started section
        start_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        start_card.pack(fill=tk.X, padx=20, pady=(0, 10))

        tk.Label(
            start_card,
            text="Quick Start Checklist",
            font=('Helvetica', 12, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(16, 10))

        checklist = [
            "Launch the toolkit with `sudo ./launch.sh` to ensure the virtual environments load correctly.",
            "Use the Doctor command inside each tab to verify platform-specific prerequisites.",
            "Adjust defaults in the Options panels before running long scans or analytics jobs.",
            "Review generated logs and reports under each module's output directory."
        ]

        for item in checklist:
            tk.Label(
                start_card,
                text=f"- {item}",
                font=('Helvetica', 9),
                bg=self.colors['card'],
                fg=self.colors['text_secondary'],
                justify=tk.LEFT,
                wraplength=760
            ).pack(anchor=tk.W, padx=24, pady=4)

        # Support section
        support_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        support_card.pack(fill=tk.X, padx=20, pady=(0, 20))

        tk.Label(
            support_card,
            text="Need Assistance?",
            font=('Helvetica', 12, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(16, 10))

        tk.Label(
            support_card,
            text=(
                "Documentation for each tool lives alongside its README and USAGE files. "
                "If a command fails, consult the Output console for tagged [ERROR]/[WARN] messages. "
                "Attach relevant logs when escalating to Trust Lab support."
            ),
            font=('Helvetica', 9),
            bg=self.colors['card'],
            fg=self.colors['text_secondary'],
            justify=tk.LEFT,
            wraplength=760
        ).pack(anchor=tk.W, padx=20, pady=(0, 18))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ==================== TRUSTMITRE TAB ====================

    def create_trustmitre_tab(self):
        """Create trustMITRE analytics tab"""
        tab = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(tab, text="trustMITRE")

        canvas = tk.Canvas(tab, highlightthickness=0, bg=self.colors['bg'])
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='TFrame')

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Info card
        info_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        info_card.pack(fill=tk.X, padx=20, pady=(15, 10))

        tk.Label(
            info_card,
            text="trustMITRE - Threat Analytics Pipeline",
            font=('Helvetica', 14, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['primary']
        ).pack(anchor=tk.W, padx=20, pady=(15, 5))

        tk.Label(
            info_card,
            text="Download CAR analytics, compile Sigma-like detectors, ingest security logs, and produce MITRE-aligned reports.",
            font=('Helvetica', 9),
            bg=self.colors['card'],
            fg=self.colors['text_secondary'],
            justify=tk.LEFT
        ).pack(anchor=tk.W, padx=20, pady=(0, 15))

        # Command selection
        cmd_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        cmd_card.pack(fill=tk.X, padx=20, pady=(0, 10))

        tk.Label(
            cmd_card,
            text="Select Command",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(15, 10))

        cmd_frame = tk.Frame(cmd_card, bg=self.colors['card'])
        cmd_frame.pack(fill=tk.X, padx=20, pady=(0, 15))

        self.trustmitre_command = tk.StringVar(value="quickstart")
        commands = [
            ("Quickstart", "quickstart", "Run download, compile, ingest, run, and report"),
            ("Download", "download", "Fetch analytics from remote source"),
            ("Compile", "compile", "Compile analytics into runnable modules"),
            ("Ingest", "ingest", "Normalize raw logs"),
            ("Run", "run", "Execute compiled analyzers"),
            ("Report", "report", "Regenerate detection reports"),
            ("Schema", "schema", "Display detection schema metadata"),
            ("Clean", "clean", "Remove generated artifacts"),
            ("Validate Config", "validate-config", "Show resolved configuration"),
        ]

        for i, (label, value, tooltip) in enumerate(commands):
            rb = ttk.Radiobutton(
                cmd_frame,
                text=label,
                variable=self.trustmitre_command,
                value=value,
                command=self.update_trustmitre_options
            )
            rb.grid(row=0, column=i, padx=8, pady=5, sticky=tk.W)
            ModernTooltip(rb, tooltip)

        # Options card
        self.trustmitre_options_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        self.trustmitre_options_card.pack(fill=tk.X, padx=20, pady=(0, 10))

        tk.Label(
            self.trustmitre_options_card,
            text="Options",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(15, 10))

        self.trustmitre_options_frame = tk.Frame(self.trustmitre_options_card, bg=self.colors['card'])
        self.trustmitre_options_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))

        default_ingest_target = str((self.trustmitre_path / "logs" / "ingested.jsonl").resolve())
        self.trustmitre_vars = {
            'config': tk.StringVar(value=""),
            'inputs': tk.StringVar(value=""),
            'evtx': tk.StringVar(value=""),
            'output': tk.StringVar(value=default_ingest_target),
            'include': tk.StringVar(value=""),
            'exclude': tk.StringVar(value=""),
            'workers': tk.StringVar(value=""),
            'batch_size': tk.StringVar(value=""),
            'force': tk.BooleanVar(value=False),
            'live': tk.BooleanVar(value=False),
        }

        self.update_trustmitre_options()

        # Output console
        output_card = tk.Frame(scrollable_frame, bg=self.colors['card'], relief=tk.FLAT, bd=1)
        output_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))

        tk.Label(
            output_card,
            text="Output Console",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        ).pack(anchor=tk.W, padx=20, pady=(15, 10))

        self.trustmitre_output = EnhancedOutput(output_card, height=15)
        self.trustmitre_output.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))

        # Action buttons
        btn_frame = tk.Frame(scrollable_frame, bg=self.colors['bg'])
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))

        run_btn = tk.Button(
            btn_frame,
            text="Run Command",
            command=self.run_trustmitre,
            bg=self.colors['success'],
            fg='white',
            font=('Helvetica', 11, 'bold'),
            relief=tk.FLAT,
            cursor='hand2',
            padx=25,
            pady=10
        )
        run_btn.pack(side=tk.LEFT, padx=(0, 10))
        run_btn.bind('<Enter>', lambda e: run_btn.config(bg='#229954'))
        run_btn.bind('<Leave>', lambda e: run_btn.config(bg=self.colors['success']))

        history_btn = tk.Button(
            btn_frame,
            text="History",
            command=lambda: self.show_tool_history('trustmitre'),
            bg=self.colors['info'],
            fg='white',
            font=('Helvetica', 10),
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=10
        )
        history_btn.pack(side=tk.LEFT, padx=(0, 10))
        history_btn.bind('<Enter>', lambda e: history_btn.config(bg='#2471a3'))
        history_btn.bind('<Leave>', lambda e: history_btn.config(bg=self.colors['info']))

        open_btn = tk.Button(
            btn_frame,
            text="Open Reports",
            command=lambda: self.open_folder(self.trustmitre_path / "output"),
            bg=self.colors['primary'],
            fg='white',
            font=('Helvetica', 10),
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=10
        )
        open_btn.pack(side=tk.LEFT)
        open_btn.bind('<Enter>', lambda e: open_btn.config(bg=self.colors['primary_dark']))
        open_btn.bind('<Leave>', lambda e: open_btn.config(bg=self.colors['primary']))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def update_trustmitre_options(self):
        """Update trustMITRE options dynamically"""
        for widget in self.trustmitre_options_frame.winfo_children():
            widget.destroy()

        command = self.trustmitre_command.get()
        row = 0

        common_tooltip = "If empty, trustMITRE will use defaults from trustmitre.toml."

        if command in {"quickstart", "download", "compile", "ingest", "run", "report", "clean", "validate-config"}:
            self.create_option_row(
                self.trustmitre_options_frame,
                row,
                "Configuration File:",
                self.trustmitre_vars['config'],
                'file',
                tooltip="Optional trustmitre.toml to override defaults."
            )
            row += 1

        if command in {"quickstart", "ingest", "run"}:
            self.create_option_row(
                self.trustmitre_options_frame,
                row,
                "Input Logs:",
                self.trustmitre_vars['inputs'],
                'files',
                tooltip="Optional list of log files (space separated). Leave blank to use defaults."
            )
            row += 1

        if command == "download":
            cb = ttk.Checkbutton(
                self.trustmitre_options_frame,
                text="Force re-download even when cached",
                variable=self.trustmitre_vars['force']
            )
            cb.grid(row=row, column=0, sticky=tk.W, pady=6)
            ModernTooltip(cb, "Re-fetch analytics even if ETag matches.")
            row += 1

        if command == "ingest":
            self.create_option_row(
                self.trustmitre_options_frame,
                row,
                "EVTX Archives:",
                self.trustmitre_vars['evtx'],
                'files',
                tooltip="Optional list of EVTX files to convert alongside inputs."
            )
            row += 1

            cb = ttk.Checkbutton(
                self.trustmitre_options_frame,
                text="Collect live Sysmon events (Windows only)",
                variable=self.trustmitre_vars['live']
            )
            cb.grid(row=row, column=0, sticky=tk.W, pady=6)
            ModernTooltip(cb, "Exports live Sysmon data. Requires Windows and administrative rights.")
            row += 1

            self.create_option_row(
                self.trustmitre_options_frame,
                row,
                "Output JSONL:",
                self.trustmitre_vars['output'],
                'save_file',
                tooltip="Destination JSONL file for normalized events."
            )
            row += 1

        if command == "run":
            self.create_option_row(
                self.trustmitre_options_frame,
                row,
                "Include Analytics:",
                self.trustmitre_vars['include'],
                'entry',
                tooltip="Filter to specific analytic IDs (space separated)."
            )
            row += 1

            self.create_option_row(
                self.trustmitre_options_frame,
                row,
                "Exclude Analytics:",
                self.trustmitre_vars['exclude'],
                'entry',
                tooltip="Exclude analytic IDs (space separated)."
            )
            row += 1

            self.create_option_row(
                self.trustmitre_options_frame,
                row,
                "Worker Processes:",
                self.trustmitre_vars['workers'],
                'entry',
                width=12,
                tooltip="Override worker count (defaults to config)."
            )
            row += 1

            self.create_option_row(
                self.trustmitre_options_frame,
                row,
                "Batch Size:",
                self.trustmitre_vars['batch_size'],
                'entry',
                width=12,
                tooltip="Override batch size for analyzer execution."
            )
            row += 1

        if command == "schema":
            tk.Label(
                self.trustmitre_options_frame,
                text="Displays the detection schema reference in the console.",
                font=('Helvetica', 9, 'italic'),
                bg=self.colors['card'],
                fg=self.colors['text_secondary']
            ).grid(row=row, column=0, sticky=tk.W, pady=6)
            row += 1

        if row == 0:
            tk.Label(
                self.trustmitre_options_frame,
                text=common_tooltip,
                font=('Helvetica', 9, 'italic'),
                bg=self.colors['card'],
                fg=self.colors['text_secondary']
            ).grid(row=row, column=0, sticky=tk.W, pady=6)

    def run_trustmitre(self):
        """Execute trustMITRE command"""
        command = self.trustmitre_command.get()
        python_exec = self.get_python_executable(self.trustmitre_venv)
        cmd = [python_exec, "-m", "trustmitre"]

        config_path = self.trustmitre_vars['config'].get().strip()
        if config_path:
            cmd.extend(["--config", config_path])

        cmd.append(command)

        inputs = shlex.split(self.trustmitre_vars['inputs'].get())
        if inputs:
            cmd.extend(inputs)

        if command == "download":
            if self.trustmitre_vars['force'].get():
                cmd.append("--force")

        if command == "ingest":
            evtx_paths = shlex.split(self.trustmitre_vars['evtx'].get())
            if evtx_paths:
                cmd.extend(["--evtx", *evtx_paths])
            if self.trustmitre_vars['live'].get():
                cmd.append("--live")
            output_path = self.trustmitre_vars['output'].get().strip()
            if output_path:
                cmd.extend(["--output", output_path])

        if command == "run":
            include_items = shlex.split(self.trustmitre_vars['include'].get())
            for item in include_items:
                cmd.extend(["--include", item])
            exclude_items = shlex.split(self.trustmitre_vars['exclude'].get())
            for item in exclude_items:
                cmd.extend(["--exclude", item])

            workers = self.trustmitre_vars['workers'].get().strip()
            if workers:
                cmd.extend(["--workers", workers])

            batch_size = self.trustmitre_vars['batch_size'].get().strip()
            if batch_size:
                cmd.extend(["--batch-size", batch_size])

        # Persist history
        self.history.add(
            'trustmitre',
            command,
            {k: v.get() for k, v in self.trustmitre_vars.items()}
        )

        env = self.build_python_env(self.trustmitre_path)
        self.run_command_async(cmd, self.trustmitre_output, str(self.trustmitre_path), env=env)

    # ==================== SHARED UTILITIES ====================

    def create_option_row(self, parent, row, label_text, variable, control_type, **kwargs):
        """Helper to add labelled inputs into option frames"""
        frame = tk.Frame(parent, bg=self.colors['card'])
        frame.grid(row=row, column=0, sticky=tk.EW, pady=6)
        frame.columnconfigure(1, weight=1)

        label = tk.Label(
            frame,
            text=label_text,
            font=('Helvetica', 10),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        label.grid(row=0, column=0, sticky=tk.W, padx=(0, 12))

        tooltip_text = kwargs.get('tooltip')
        control_width = kwargs.get('width', 32)

        if control_type == 'entry':
            entry = ttk.Entry(frame, textvariable=variable, width=control_width)
            entry.grid(row=0, column=1, sticky=tk.EW)
            if tooltip_text:
                ModernTooltip(entry, tooltip_text)
        elif control_type == 'combo':
            options = kwargs.get('options', [])
            combo = ttk.Combobox(
                frame,
                textvariable=variable,
                values=options,
                width=control_width,
                state='readonly' if options else 'normal'
            )
            combo.grid(row=0, column=1, sticky=tk.EW)
            if not variable.get() and options:
                combo.set(options[0])
            if tooltip_text:
                ModernTooltip(combo, tooltip_text)
        elif control_type == 'radio':
            options = kwargs.get('options', [])
            radio_frame = tk.Frame(frame, bg=self.colors['card'])
            radio_frame.grid(row=0, column=1, sticky=tk.W)
            for i, option in enumerate(options):
                rb = ttk.Radiobutton(
                    radio_frame,
                    text=option,
                    variable=variable,
                    value=option
                )
                rb.grid(row=0, column=i, padx=(0, 10))
                if tooltip_text:
                    ModernTooltip(rb, tooltip_text)
        elif control_type in {'file', 'files', 'save_file', 'directory'}:
            entry = ttk.Entry(frame, textvariable=variable, width=control_width)
            entry.grid(row=0, column=1, sticky=tk.EW)
            if tooltip_text:
                ModernTooltip(entry, tooltip_text)

            browse_btn = tk.Button(
                frame,
                text="Browse",
                command=lambda: self._handle_browse(control_type, variable),
                bg=self.colors['primary'],
                fg='white',
                font=('Helvetica', 9),
                relief=tk.FLAT,
                cursor='hand2',
                padx=10,
                pady=5
            )
            browse_btn.grid(row=0, column=2, padx=(8, 0))
            browse_btn.bind('<Enter>', lambda e: browse_btn.config(bg=self.colors['primary_dark']))
            browse_btn.bind('<Leave>', lambda e: browse_btn.config(bg=self.colors['primary']))
        else:
            raise ValueError(f"Unsupported control type: {control_type}")

    def _handle_browse(self, control_type, variable):
        """Route browse actions to the correct dialog"""
        try:
            if control_type == 'directory':
                path = filedialog.askdirectory()
                if path:
                    variable.set(path)
            elif control_type == 'file':
                path = filedialog.askopenfilename()
                if path:
                    variable.set(path)
            elif control_type == 'save_file':
                path = filedialog.asksaveasfilename(defaultextension=".jsonl")
                if path:
                    variable.set(path)
            elif control_type == 'files':
                paths = filedialog.askopenfilenames()
                if paths:
                    variable.set(" ".join(paths))
        except Exception as exc:  # pragma: no cover - Tk dialog errors rare
            messagebox.showerror("Error", f"Unable to open file dialog: {exc}")

    def open_folder(self, path):
        """Open a folder using the native file manager"""
        target = Path(path).expanduser()
        if not target.exists():
            messagebox.showerror("Error", f"Path does not exist:\n{target}")
            return

        try:
            if platform.system() == "Windows":
                os.startfile(str(target))  # type: ignore[attr-defined]
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", str(target)])
            else:
                subprocess.Popen(["xdg-open", str(target)])
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to open folder:\n{exc}")

    def show_dashboard(self):
        """Jump to dashboard tab"""
        self.notebook.select(0)

    def show_history(self):
        """Show recent command history"""
        entries = self.history.get_recent(limit=20)
        if not entries:
            messagebox.showinfo("Command History", "No commands executed yet.")
            return
        self._show_history_window(entries, "Recent Commands")

    def show_settings(self):
        """Display environment settings"""
        window = tk.Toplevel(self.root)
        window.title("Toolkit Settings")
        window.geometry("480x260")
        window.configure(bg=self.colors['bg'])

        info = tk.Label(
            window,
            text=(
                "Toolkit expects each module to have an active virtual environment under .venv.\n"
                "Use the Install/Doctor commands inside each tab to validate the environment.\n\n"
                "- trusLAN: network scanning defaults to ./output\n"
                "- trusClamAV: reports stored in ./output/trusclamav\n"
                "- trustMITRE: compiled assets in .compiled, reports in ./output\n\n"
                "Adjust trustmitre.toml or per-tool configuration files for advanced tuning."
            ),
            justify=tk.LEFT,
            wraplength=440,
            bg=self.colors['bg'],
            fg=self.colors['text']
        )
        info.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        tk.Button(
            window,
            text="Close",
            command=window.destroy,
            bg=self.colors['primary'],
            fg='white',
            font=('Helvetica', 10),
            relief=tk.FLAT,
            cursor='hand2',
            padx=20,
            pady=8
        ).pack(pady=(0, 20))

    def show_tool_history(self, tool):
        """Show history filtered by tool"""
        entries = self.history.get_recent(tool=tool, limit=15)
        if not entries:
            messagebox.showinfo("Command History", f"No history available for {tool}.")
            return
        self._show_history_window(entries, f"{tool} History")

    def _show_history_window(self, entries, title):
        """Render history entries inside a Toplevel window"""
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("720x360")

        columns = ("timestamp", "tool", "command", "options")
        tree = ttk.Treeview(window, columns=columns, show="headings")
        tree.heading("timestamp", text="Timestamp")
        tree.heading("tool", text="Tool")
        tree.heading("command", text="Command")
        tree.heading("options", text="Options")

        tree.column("timestamp", width=150, anchor=tk.W)
        tree.column("tool", width=100, anchor=tk.W)
        tree.column("command", width=120, anchor=tk.W)
        tree.column("options", width=320, anchor=tk.W)

        scrollbar = ttk.Scrollbar(window, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        for entry in entries:
            options = ", ".join(f"{k}={v}" for k, v in entry.get('options', {}).items())
            tree.insert("", tk.END, values=(entry.get('timestamp', ''), entry.get('tool', ''), entry.get('command', ''), options))

    def build_python_env(self, module_path):
        """Prepare environment with module src directory ahead of PYTHONPATH"""
        env = os.environ.copy()
        src_path = Path(module_path) / "src"
        if src_path.exists():
            current = env.get("PYTHONPATH", "")
            paths = [str(src_path)]
            if current:
                paths.append(current)
            env["PYTHONPATH"] = os.pathsep.join(paths)
        return env

    def run_command_async(self, cmd, output_widget, workdir, env=None):
        """Run a command on a background thread and stream output"""
        command_str = " ".join(str(part) for part in cmd)
        output_widget.insert(tk.END, f"Executing: {command_str}\n")
        output_widget.see(tk.END)
        self.update_status(f"Running command: {command_str}", status_type='running', show_progress=True)

        def worker():
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    cwd=workdir,
                    env=env,
                    text=True,
                    bufsize=1
                )
            except FileNotFoundError as exc:
                self.root.after(0, lambda: self._report_start_error(output_widget, command_str, f"Command not found: {exc}"))
                return
            except Exception as exc:  # pragma: no cover - unexpected errors
                self.root.after(0, lambda: self._report_start_error(output_widget, command_str, str(exc)))
                return

            with self.process_lock:
                self.running_processes.append(process)

            try:
                if process.stdout:
                    for line in iter(process.stdout.readline, ''):
                        if not line:
                            break
                        self.root.after(0, lambda l=line: self.append_output(output_widget, l))
            finally:
                returncode = process.wait()
                if process.stdout:
                    process.stdout.close()
                with self.process_lock:
                    if process in self.running_processes:
                        self.running_processes.remove(process)
                self.root.after(0, lambda: self.handle_command_completion(output_widget, command_str, returncode))

        threading.Thread(target=worker, daemon=True).start()

    def _report_start_error(self, output_widget, command_str, message):
        """Report startup failure to the user"""
        self.append_output(output_widget, f"{STATUS_ERROR} Failed to start: {message}\n")
        self.update_status("Failed to start command.", status_type='error', show_progress=False)

    def append_output(self, output_widget, text):
        """Append text to enhanced output on the UI thread"""
        output_widget.insert(tk.END, text)
        if not text.endswith('\n'):
            output_widget.insert(tk.END, '\n')
        output_widget.see(tk.END)

    def handle_command_completion(self, output_widget, command_str, returncode):
        """Handle command completion updates"""
        if returncode == 0:
            self.append_output(output_widget, f"{STATUS_OK} Command completed successfully (exit code: 0)")
            self.update_status("Command finished successfully.", status_type='success', show_progress=False)
        else:
            self.append_output(output_widget, f"{STATUS_ERROR} Command failed (exit code: {returncode})")
            self.update_status(f"Command failed (exit {returncode}).", status_type='error', show_progress=False)

    def stop_all_processes(self):
        """Terminate all running subprocesses"""
        with self.process_lock:
            processes = list(self.running_processes)

        for process in processes:
            if process.poll() is None:
                try:
                    process.terminate()
                except Exception:
                    continue

        for process in processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except Exception:
                    pass

        with self.process_lock:
            self.running_processes.clear()

    def on_close(self):
        """Graceful shutdown"""
        if self.running_processes:
            if not messagebox.askyesno(
                "Quit",
                "Commands are still running. Do you want to terminate them and exit?"
            ):
                return
        self.stop_all_processes()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = PYMEsUnifiedUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
