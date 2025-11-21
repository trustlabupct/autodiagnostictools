"""
GUI interface for trusClamAV.

Provides a graphical user interface with fallback to standard Tkinter
if CustomTkinter is not available.

Author: Volodymyr Dubetskyy
Date: October 13, 2025
"""

import subprocess
import threading
import time
import os
import sys
import ctypes
import logging
from pathlib import Path

from .config_schema import ClamAVConfig, resolve_output_prefix

logger = logging.getLogger(__name__)

_DEFAULT_PREFIX = resolve_output_prefix(ClamAVConfig().out)
DEFAULT_REPORT_TXT = _DEFAULT_PREFIX.with_suffix(".txt")
DEFAULT_REPORT_JSON = _DEFAULT_PREFIX.with_suffix(".json")
DEFAULT_REPORT_TXT_STR = str(DEFAULT_REPORT_TXT)
DEFAULT_REPORT_JSON_STR = str(DEFAULT_REPORT_JSON)

# Try to import GUI libraries with fallback
GUI_AVAILABLE = False
GUI_TYPE = None

try:
    import customtkinter as ctk
    GUI_AVAILABLE = True
    GUI_TYPE = "customtkinter"
    # Initialize CustomTkinter
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    logger.info("Using CustomTkinter for GUI")
except ImportError:
    try:
        import tkinter as tk
        from tkinter import ttk
        GUI_AVAILABLE = True
        GUI_TYPE = "tkinter"
        logger.info("Falling back to standard Tkinter")
    except ImportError:
        GUI_AVAILABLE = False
        logger.error("No GUI library available")


def is_admin():
    """Check if running with administrator privileges on Windows."""
    try:
        if sys.platform == 'win32':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            # Non-Windows, check if running as root
            return os.geteuid() == 0
    except:
        return False


def show_gui_error():
    """Show error message when GUI libraries are not available."""
    print("=" * 60)
    print("ERROR: GUI libraries not available")
    print("=" * 60)
    print()
    print("The GUI requires either CustomTkinter or standard Tkinter.")
    print()
    print("To install CustomTkinter (recommended):")
    print("  pip install customtkinter")
    print()
    print("Or ensure Tkinter is installed:")
    print("  - Windows: Usually included with Python")
    print("  - Ubuntu/Debian: sudo apt-get install python3-tk")
    print("  - Fedora: sudo dnf install python3-tkinter")
    print("  - macOS: Usually included with Python")
    print()
    print("Alternatively, use the CLI interface:")
    print("  python -m trusClamAV --help")
    print("=" * 60)


if GUI_TYPE == "customtkinter":
    # CustomTkinter implementation

    class MainApp(ctk.CTk):
        def __init__(self):
            super().__init__()
            self.geometry("800x500")
            self.title("ClamAV Module - Antivirus Scanner")

            # Configure rows and columns of the main window
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            if not is_admin() and sys.platform == 'win32':
                # Show only the admin message on Windows
                self.show_admin_message()
            else:
                # Create the pages normally
                self.page1 = Page1(self)
                self.page2 = Page2(self)
                self.show_page(self.page1)

        def show_admin_message(self):
            frame = ctk.CTkFrame(self)
            frame.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)

            message = ctk.CTkLabel(
                frame,
                text="This application requires administrator privileges.\nClick the button to restart with privileges.",
                font=("Helvetica", 16)
            )
            message.pack(pady=20)

            button = ctk.CTkButton(
                frame,
                text="Restart as Administrator",
                command=self.restart_as_admin,
                font=("Helvetica", 14)
            )
            button.pack(pady=20)

        def restart_as_admin(self):
            if sys.platform == 'win32':
                script_path = os.path.abspath(sys.argv[0])
                try:
                    ctypes.windll.shell32.ShellExecuteW(
                        None,
                        "runas",
                        sys.executable,
                        f'"{script_path}"',
                        None,
                        1
                    )
                    self.quit()  # Close current application
                except Exception as e:
                    logger.error(f"Failed to restart as admin: {e}")
                    print(f"Error restarting as administrator: {e}")

        def show_page(self, page):
            page.tkraise()


    class Page1(ctk.CTkFrame):
        def __init__(self, parent):
            super().__init__(parent)
            self.parent = parent
            self.grid(row=0, column=0, sticky="nsew")

            # Configure rows and columns to center the content
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            # Create a central frame
            central_frame = ctk.CTkFrame(self)
            central_frame.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)

            # Configure the frame to be centered
            for i in range(6):
                central_frame.grid_rowconfigure(i, weight=1)
            central_frame.grid_columnconfigure(0, weight=1)

            # Add a centered label in the frame
            self.label = ctk.CTkLabel(
                central_frame, text="ClamAV Scanner", font=("Helvetica", 30)
            )
            self.label.grid(row=0, column=0, padx=20, pady=20)

            # Add the "Install ClamAV" button
            self.install_button = ctk.CTkButton(
                central_frame,
                text="Install ClamAV",
                font=("Helvetica", 20),
                command=self.install_clamav
            )
            self.install_button.grid(row=1, column=0, padx=20, pady=20)

            # Add the "Scan Files" button
            self.scan_button = ctk.CTkButton(
                central_frame,
                text="Scan Files",
                font=("Helvetica", 20),
                command=self.start_scan,
                state=ctk.DISABLED  # Initially disabled until ClamAV is installed
            )
            self.scan_button.grid(row=2, column=0, padx=20, pady=20)

            # Add a label to display scan results
            self.result_label = ctk.CTkLabel(
                central_frame, text="", font=("Helvetica", 16), wraplength=500
            )
            self.result_label.grid(row=3, column=0, padx=20, pady=20)

            # Add a label to indicate scanning status
            self.scan_status_label = ctk.CTkLabel(
                central_frame, text="", font=("Helvetica", 16)
            )
            self.scan_status_label.grid(row=4, column=0, padx=20, pady=20)

            # Add the "Next Page" button
            self.next_scan_button = ctk.CTkButton(
                central_frame,
                text="View Details",
                font=("Helvetica", 20),
                command=self.go_to_next_scan_page,
                state=ctk.DISABLED
            )
            self.next_scan_button.grid(row=5, column=0, padx=20, pady=20)

            # Check if ClamAV is already installed
            self.check_clamav_status()

        def check_clamav_status(self):
            """Check if ClamAV is installed and enable scan button if it is."""
            def check_thread():
                try:
                    # Use new CLI doctor command to check status
                    result = subprocess.run(
                        [sys.executable, "-m", "trusClamAV", "doctor"],
                        capture_output=True,
                        text=True
                    )

                    if "Status: Found" in result.stdout:
                        self.scan_button.configure(state=ctk.NORMAL)
                        self.result_label.configure(text="ClamAV is installed and ready")
                except Exception as e:
                    logger.error(f"Failed to check ClamAV status: {e}")

            threading.Thread(target=check_thread, daemon=True).start()

        def install_clamav(self):
            self.install_button.configure(state=ctk.DISABLED)
            self.result_label.configure(text="Installing ClamAV...")

            def install_thread():
                try:
                    # Use new CLI install command
                    result = subprocess.run(
                        [sys.executable, "-m", "trusClamAV", "install"],
                        capture_output=True,
                        text=True
                    )

                    if result.returncode == 0:
                        self.result_label.configure(text="ClamAV installed successfully")
                        self.scan_button.configure(state=ctk.NORMAL)
                    else:
                        self.result_label.configure(text="Error: Failed to install ClamAV\nCheck logs for details")
                except Exception as e:
                    self.result_label.configure(text=f"Error: {str(e)}")
                finally:
                    self.install_button.configure(state=ctk.NORMAL)

            threading.Thread(target=install_thread, daemon=True).start()

        def start_scan(self):
            self.result_label.configure(text="")
            self.scan_status_label.configure(text="Scanning files...")
            self.scan_button.configure(state=ctk.DISABLED)

            scan_thread = threading.Thread(target=self.run_scan_script, daemon=True)
            scan_thread.start()

        def run_scan_script(self):
            try:
                # Use new CLI scan command
                result = subprocess.run(
                    [sys.executable, "-m", "trusClamAV", "scan"],
                    capture_output=True,
                    text=True
                )

                time.sleep(1)  # Brief pause for UI update
                self.display_scan_results()
            except Exception as e:
                self.result_label.configure(text=f"Error: {str(e)}")
            finally:
                self.scan_status_label.configure(text="")
                self.scan_button.configure(state=ctk.NORMAL)

        def display_scan_results(self):
            output_file = DEFAULT_REPORT_TXT

            if output_file.exists():
                with output_file.open("r", encoding="utf-8", errors="ignore") as f:
                    infected_files = [
                        line.strip() for line in f if "FOUND" in line
                    ]

                if infected_files:
                    self.result_label.configure(
                        text="Infected files found:\n" + "\n".join(infected_files[:5])
                    )
                else:
                    self.result_label.configure(
                        text="Scan complete. No infections found."
                    )
                self.next_scan_button.configure(state=ctk.NORMAL)
            else:
                self.result_label.configure(
                    text=f"Scan completed but output file not found at {DEFAULT_REPORT_TXT_STR}"
                )

        def go_to_next_scan_page(self):
            self.parent.show_page(self.parent.page2)


    class Page2(ctk.CTkFrame):
        def __init__(self, parent):
            super().__init__(parent)
            self.parent = parent
            self.grid(row=0, column=0, sticky="nsew")

            # Configure rows and columns to center the content
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            # Create a central frame
            central_frame = ctk.CTkFrame(self)
            central_frame.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)

            # Configure the frame to be centered
            central_frame.grid_rowconfigure((0,1,2), weight=1)
            central_frame.grid_columnconfigure(0, weight=1)

            # Add a centered label in the frame
            self.label = ctk.CTkLabel(
                central_frame, text="Scan Results", font=("Helvetica", 30)
            )
            self.label.grid(row=0, column=0, padx=20, pady=20)

            # Add scan details
            self.details_label = ctk.CTkLabel(
                central_frame,
                text=f"View detailed scan results in\n{DEFAULT_REPORT_TXT_STR}\nand {DEFAULT_REPORT_JSON_STR}.",
                font=("Helvetica", 16)
            )
            self.details_label.grid(row=1, column=0, padx=20, pady=20)

            # Back button
            self.back_button = ctk.CTkButton(
                central_frame,
                text="Back to Main",
                font=("Helvetica", 20),
                command=self.go_back
            )
            self.back_button.grid(row=2, column=0, padx=20, pady=20)

        def go_back(self):
            self.parent.show_page(self.parent.page1)


elif GUI_TYPE == "tkinter":
    # Standard Tkinter fallback implementation

    class MainApp(tk.Tk):
        def __init__(self):
            super().__init__()
            self.geometry("800x500")
            self.title("ClamAV Module - Antivirus Scanner")

            # Apply some basic styling
            self.configure(bg='#2b2b2b')

            # Style configuration for ttk widgets
            style = ttk.Style(self)
            style.theme_use('clam')
            style.configure('TButton', padding=10, font=('Helvetica', 12))
            style.configure('TLabel', background='#2b2b2b', foreground='white', font=('Helvetica', 12))

            if not is_admin() and sys.platform == 'win32':
                self.show_admin_message()
            else:
                self.create_main_interface()

        def show_admin_message(self):
            frame = tk.Frame(self, bg='#2b2b2b')
            frame.pack(expand=True, fill='both', padx=40, pady=40)

            message = tk.Label(
                frame,
                text="This application requires administrator privileges.\nClick the button to restart with privileges.",
                font=("Helvetica", 16),
                bg='#2b2b2b',
                fg='white'
            )
            message.pack(pady=20)

            button = ttk.Button(
                frame,
                text="Restart as Administrator",
                command=self.restart_as_admin
            )
            button.pack(pady=20)

        def restart_as_admin(self):
            if sys.platform == 'win32':
                script_path = os.path.abspath(sys.argv[0])
                try:
                    ctypes.windll.shell32.ShellExecuteW(
                        None,
                        "runas",
                        sys.executable,
                        f'"{script_path}"',
                        None,
                        1
                    )
                    self.quit()
                except Exception as e:
                    logger.error(f"Failed to restart as admin: {e}")

        def create_main_interface(self):
            # Main frame
            main_frame = tk.Frame(self, bg='#2b2b2b')
            main_frame.pack(expand=True, fill='both', padx=40, pady=40)

            # Title
            title_label = tk.Label(
                main_frame,
                text="ClamAV Scanner",
                font=("Helvetica", 24, 'bold'),
                bg='#2b2b2b',
                fg='white'
            )
            title_label.pack(pady=20)

            # Status label
            self.status_label = tk.Label(
                main_frame,
                text="Checking ClamAV status...",
                font=("Helvetica", 14),
                bg='#2b2b2b',
                fg='#cccccc'
            )
            self.status_label.pack(pady=10)

            # Buttons
            button_frame = tk.Frame(main_frame, bg='#2b2b2b')
            button_frame.pack(pady=20)

            self.install_button = ttk.Button(
                button_frame,
                text="Install ClamAV",
                command=self.install_clamav,
                state='disabled'
            )
            self.install_button.pack(pady=10)

            self.scan_button = ttk.Button(
                button_frame,
                text="Scan Files",
                command=self.start_scan,
                state='disabled'
            )
            self.scan_button.pack(pady=10)

            # Check ClamAV status
            self.check_clamav_status()

        def check_clamav_status(self):
            def check_thread():
                try:
                    result = subprocess.run(
                        [sys.executable, "-m", "trusClamAV", "doctor"],
                        capture_output=True,
                        text=True
                    )

                    if "Status: Found" in result.stdout:
                        self.status_label.config(text="ClamAV is installed and ready")
                        self.scan_button.config(state='normal')
                    else:
                        self.status_label.config(text="ClamAV not installed")
                        self.install_button.config(state='normal')
                except Exception as e:
                    self.status_label.config(text="Error checking ClamAV status")
                    self.install_button.config(state='normal')

            threading.Thread(target=check_thread, daemon=True).start()

        def install_clamav(self):
            self.install_button.config(state='disabled')
            self.status_label.config(text="Installing ClamAV...")

            def install_thread():
                try:
                    result = subprocess.run(
                        [sys.executable, "-m", "trusClamAV", "install"],
                        capture_output=True,
                        text=True
                    )

                    if result.returncode == 0:
                        self.status_label.config(text="ClamAV installed successfully")
                        self.scan_button.config(state='normal')
                    else:
                        self.status_label.config(text="Failed to install ClamAV")
                        self.install_button.config(state='normal')
                except Exception as e:
                    self.status_label.config(text=f"Error: {str(e)}")
                    self.install_button.config(state='normal')

            threading.Thread(target=install_thread, daemon=True).start()

        def start_scan(self):
            self.scan_button.config(state='disabled')
            self.status_label.config(text="Scanning files...")

            def scan_thread():
                try:
                    result = subprocess.run(
                        [sys.executable, "-m", "trusClamAV", "scan"],
                        capture_output=True,
                        text=True
                    )

                    if result.returncode in [0, 1]:  # 0=clean, 1=infected
                        if "infected files: 0" in result.stdout.lower():
                            self.status_label.config(text="Scan complete. No infections found.")
                        else:
                            self.status_label.config(
                                text=f"Scan complete. Check {DEFAULT_REPORT_TXT_STR} for results."
                            )
                    else:
                        self.status_label.config(text="Scan failed. Check logs.")
                except Exception as e:
                    self.status_label.config(text=f"Scan error: {str(e)}")
                finally:
                    self.scan_button.config(state='normal')

            threading.Thread(target=scan_thread, daemon=True).start()


def main():
    """Main entry point for GUI."""
    if not GUI_AVAILABLE:
        show_gui_error()
        return 1

    try:
        logger.info(f"Starting GUI with {GUI_TYPE}")
        app = MainApp()
        app.mainloop()
        return 0
    except Exception as e:
        logger.error(f"GUI failed: {e}")
        print(f"Error running GUI: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
