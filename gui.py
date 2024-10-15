import customtkinter as ctk
import threading
import time
from nmap_module.network_test import scan_all

# Initialize CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("800x500")
        self.title("Trust Lab Analysis Tool")

        # Configure rows and columns of the main window
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create pages
        self.page1 = Page1(self)
        self.page2 = Page2(self)
        self.page3 = Page3(self)

        # Display the first page on startup
        self.show_page(self.page1)

    def show_page(self, page):
        page.tkraise()  # Bring the page to the top

class Page1(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")

        # Configure rows and columns to center the content
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create a central frame that occupies 75% of the space
        central_frame = ctk.CTkFrame(self)
        central_frame.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)

        # Configure the frame to be centered
        central_frame.grid_rowconfigure(0, weight=1)
        central_frame.grid_columnconfigure(0, weight=1)

        # Add a centered label in the frame
        self.label = ctk.CTkLabel(central_frame, text="Type of Scan", font=("Helvetica", 30))
        self.label.grid(row=0, column=0, padx=20, pady=20)

        # Add a frame for buttons
        button_frame = ctk.CTkFrame(central_frame)
        button_frame.grid(row=1, column=0, padx=20, pady=20)

        # Configure the weight of the columns
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        button_frame.grid_columnconfigure(2, weight=1)

        # Add buttons with different scan functions
        self.create_button(button_frame, "Fast", 0, self.start_fast_scan, font=("Helvetica", 20))
        self.create_button(button_frame, "Medium", 1, self.start_medium_scan, font=("Helvetica", 20))
        self.create_button(button_frame, "Deep", 2, self.start_deep_scan, font=("Helvetica", 20))

    def create_button(self, parent, text, column, command, font=None):
        button = ctk.CTkButton(
            parent, 
            text=text, 
            command=command,  # Each button has its own command (function)
            font=font
        )
        button.grid(row=0, column=column, padx=10, pady=10, sticky="nsew")

    def start_fast_scan(self):
        self.parent.show_page(self.parent.page2)
        self.run_scan("1000", "100")

    def start_medium_scan(self):
        self.parent.show_page(self.parent.page2)
        self.run_scan("2000", "100")

    def start_deep_scan(self):
        self.parent.show_page(self.parent.page2)
        self.run_scan("3000", "200")

    def run_scan(self, port_range_tcp, port_range_udp):
        scan_thread = threading.Thread(target=self.perform_scan, args=(port_range_tcp, port_range_udp))
        scan_thread.start()

    def perform_scan(self, port_range_tcp, port_range_udp):
        self.parent.page2.progress.start()  # Start the progress bar animation
        start_time = time.time()

        # Call the scan_all function with specific TCP/UDP ranges
        active_hosts, tcp_results, udp_results = scan_all(port_range_tcp, port_range_udp)
        
        end_time = time.time()
        execution_time = end_time - start_time

        # Stop the progress bar and filled
        self.parent.page2.progress.stop()
        self.parent.page2.progress.configure(mode="determinate")
        self.parent.page2.progress.set(1)

        # Update page 2 with the results once the scan is completed
        self.parent.page2.update_results(active_hosts, tcp_results, udp_results, execution_time)

class Page2(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")

        # Configure rows and columns to center the content
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create a label to show loading
        self.loading_label = ctk.CTkLabel(self, text="Loading...", font=("Helvetica", 20))
        self.loading_label.grid(row=0, column=0, padx=20, pady=20)

        # Create a Progressbar from CustomTkinter
        self.progress = ctk.CTkProgressBar(self, mode="indeterminate", width=400)  # Width of the progress bar
        self.progress.grid(row=1, column=0, padx=20, pady=20)

        # Button to go to results page
        self.results_button = ctk.CTkButton(self, text="See Results", font=("Helvetica", 20), command=self.show_results, state="disabled")
        self.results_button.grid(row=2, column=0, pady=10)

    def update_results(self, active_hosts, tcp_results, udp_results, execution_time):
        # Build a string to display the results
        active_hosts_str = "\n".join(f"{host} : {status}" for host, status in active_hosts)

        tcp_results_str = "\n".join(f"{host}: {ports}" for host, ports in tcp_results.items())
        udp_results_str = "\n".join(f"{host}: {ports}" for host, ports in udp_results.items())

        results_display = (
            f"Execution time: {execution_time:.2f} seconds\n\n"  # Display execution time
            "Active hosts:\n" + active_hosts_str +
            "\n\nTCP Results:\n" + tcp_results_str +
            "\n\nUDP Results:\n" + udp_results_str
        )

        # Update the label with the scan results
        self.parent.page3.update_results(results_display)

        # Enable the results button after the scan is complete
        self.results_button.configure(state="normal")  # Use 'configure' instead of 'config'

    def show_results(self):
        self.parent.show_page(self.parent.page3)

class Page3(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")

        # Configure rows and columns to center the content
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Label to display the results
        self.results_label = ctk.CTkLabel(self, text="", font=("Helvetica", 16))
        self.results_label.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

    def update_results(self, results):
        # Update the label with the results
        self.results_label.configure(text=results)

# Launch the application
if __name__ == "__main__":
    app = MainApp()
    app.mainloop()


