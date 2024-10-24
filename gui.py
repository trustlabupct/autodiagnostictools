import customtkinter as ctk
import threading
import time
from nmap_module.network_test import scan_all
from functools import partial

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
        self.details_page = DetailsPage(self)
        self.page4 = Page4(self)

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

        # Create a central frame
        central_frame = ctk.CTkFrame(self)
        central_frame.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)

        # Configure the frame to be centered
        central_frame.grid_rowconfigure(0, weight=1)
        central_frame.grid_columnconfigure(0, weight=1)

        # Add a centered label in the frame
        self.label = ctk.CTkLabel(
            central_frame, text="Type of Scan", font=("Helvetica", 30)
        )
        self.label.grid(row=0, column=0, padx=20, pady=20)

        # Add a frame for buttons
        button_frame = ctk.CTkFrame(central_frame)
        button_frame.grid(row=1, column=0, padx=20, pady=20)

        # Configure the weight of the columns
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        button_frame.grid_columnconfigure(2, weight=1)

        # Add buttons with different scan functions
        self.create_button(
            button_frame, "Fast", 0, self.start_fast_scan, font=("Helvetica", 20)
        )
        self.create_button(
            button_frame, "Medium", 1, self.start_medium_scan, font=("Helvetica", 20)
        )
        self.create_button(
            button_frame, "Deep", 2, self.start_deep_scan, font=("Helvetica", 20)
        )

    def create_button(self, parent, text, column, command, font=None):
        button = ctk.CTkButton(
            parent,
            text=text,
            command=command,  # Each button has its own command (function)
            font=font,
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
        scan_thread = threading.Thread(
            target=self.perform_scan, args=(port_range_tcp, port_range_udp)
        )
        scan_thread.start()

    def perform_scan(self, port_range_tcp, port_range_udp):
        self.parent.page2.progress.start()  # Start the progress bar animation
        start_time = time.time()

        # Call the scan_all function with specific TCP/UDP ranges
        active_hosts, tcp_results, udp_results = scan_all(
            port_range_tcp, port_range_udp
        )

        end_time = time.time()
        execution_time = end_time - start_time

        # Stop the progress bar
        self.parent.page2.progress.stop()
        self.parent.page2.progress.configure(mode="determinate")
        self.parent.page2.progress.set(1)

        # Update page 2 with the results once the scan is completed
        self.parent.page2.update_results(active_hosts, tcp_results, udp_results)


class Page2(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")

        # Configure rows and columns to center the content
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create a label to show loading
        self.loading_label = ctk.CTkLabel(
            self, text="Scanning...", font=("Helvetica", 20)
        )
        self.loading_label.grid(row=0, column=0, padx=20, pady=20)

        # Create a Progressbar from CustomTkinter
        self.progress = ctk.CTkProgressBar(
            self, mode="indeterminate", width=400
        )  # Width of the progress bar
        self.progress.grid(row=1, column=0, padx=20, pady=20)

        # Button to go to results page
        self.results_button = ctk.CTkButton(
            self,
            text="See Results",
            font=("Helvetica", 20),
            command=self.show_results,
            state="disabled",
        )
        self.results_button.grid(row=2, column=0, pady=10)

    def update_results(self, active_hosts, tcp_results, udp_results):
        # Enable the results button after the scan is complete
        self.results_button.configure(state="normal")

        # Pass active_hosts and results to page 3
        self.parent.page3.update_results(active_hosts, tcp_results, udp_results)

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

        # Create a frame to hold the title and buttons with a scrollbar
        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=400, height=300)
        self.scrollable_frame.grid(row=0, column=0, padx=20, pady=10, sticky="nsew")

        # Label for the title "Active Hosts"
        self.active_hosts_label = ctk.CTkLabel(
            self.scrollable_frame, text="Active Hosts:", font=("Helvetica", 20)
        )
        self.active_hosts_label.pack(pady=10)

        # Create a warning message
        self.warning_message = (
            "Warning: Open TCP/UDP ports can pose a security risk because they create entry points for potential attackers. "
            "When a port is open, it means that the corresponding service or application is listening for incoming connections. "
            "If these services are not properly secured or are vulnerable, attackers may exploit them to gain unauthorized access to the system, "
            "steal data, or disrupt services. Additionally, open ports can be scanned by malicious actors using automated tools, "
            "making it easier for them to identify and target weaknesses in your network. "
            "Therefore, it's crucial to regularly monitor and manage open ports and ensure that only necessary services are exposed to the network."
        )

        # Create a label for the warning message
        self.warning_label = ctk.CTkLabel(
            self.scrollable_frame,
            text=self.warning_message,
            font=("Helvetica", 12),
            wraplength=400,
            justify="left",
        )
        self.warning_label.pack(pady=10)

        # Create a "Next" button to go to Page 4
        self.next_button = ctk.CTkButton(
            self, text="Next", command=lambda: self.parent.show_page(self.parent.page4)
        )
        self.next_button.grid(row=1, column=0, pady=20)

        # Bind the resize event to update the font size
        self.bind("<Configure>", self.update_font_size)

    def update_font_size(self, event):
        # Calculate new font size based on window width
        new_font_size = max(12, int(event.width / 40))  # Adjust the divisor as needed
        self.active_hosts_label.configure(font=("Helvetica", new_font_size))
        self.warning_label.configure(
            font=("Helvetica", int(new_font_size * 0.8))
        )  # Slightly smaller for the warning

    def update_results(self, active_hosts, tcp_results, udp_results):
        # Clear previous buttons
        for widget in self.scrollable_frame.winfo_children():
            if isinstance(widget, ctk.CTkButton):
                widget.destroy()

        # Create buttons for each active host with corresponding results
        for host in active_hosts:
            ip_address = host[0]  # Extract IP address
            tcp_ports = tcp_results.get(ip_address, {})  # Get TCP ports for this host
            udp_ports = udp_results.get(ip_address, {})  # Get UDP ports for this host

            # Debug: display each host and its ports
            # print(f"Hôte: {ip_address}, Ports TCP: {tcp_ports}, Ports UDP: {udp_ports}")

            # Create a button with a command that passes the ports and host
            button = ctk.CTkButton(
                self.scrollable_frame,
                text=f"{ip_address}",
                command=partial(self.show_details, ip_address, tcp_ports, udp_ports),
            )
            button.pack(pady=5)

    def show_details(self, host, tcp_ports, udp_ports):
        # print(f"Affichage des détails pour {host}")  # Debug message
        # print(f"Ports TCP: {tcp_ports}")             # Affiche les ports TCP pour déboguer
        # print(f"Ports UDP: {udp_ports}")             # Affiche les ports UDP pour déboguer

        self.parent.details_page.show_tcp_udp(host, tcp_ports, udp_ports)


class DetailsPage(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")

        # Configure rows and columns to center the content
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create a scrollable frame
        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=400, height=300)
        self.scrollable_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Label for the details page
        self.details_label = ctk.CTkLabel(
            self.scrollable_frame, text="Details", font=("Helvetica", 30)
        )
        self.details_label.pack(pady=20)

        # Labels to display TCP and UDP results with wraplength to handle long text
        self.tcp_label = ctk.CTkLabel(
            self.scrollable_frame,
            text="",
            font=("Helvetica", 20),
            wraplength=380,
            justify="left",
        )
        self.tcp_label.pack(pady=10)

        self.udp_label = ctk.CTkLabel(
            self.scrollable_frame,
            text="",
            font=("Helvetica", 20),
            wraplength=380,
            justify="left",
        )
        self.udp_label.pack(pady=10)

        # Back button
        self.back_button = ctk.CTkButton(
            self.scrollable_frame, text="Back", command=self.go_back
        )
        self.back_button.pack(pady=20)

        # Bind the resize event to update the font size
        self.bind("<Configure>", self.update_font_size)

    def update_font_size(self, event):
        # Calculate new font size based on window width
        new_font_size = max(12, int(event.width / 40))  # Adjust the divisor as needed
        self.details_label.configure(font=("Helvetica", new_font_size))
        self.tcp_label.configure(
            font=("Helvetica", int(new_font_size * 0.8))
        )  # Slightly smaller for TCP
        self.udp_label.configure(
            font=("Helvetica", int(new_font_size * 0.8))
        )  # Slightly smaller for UDP

    def show_tcp_udp(self, ip_address, tcp_ports, udp_ports):
        # Show the results for the selected host with line wrapping
        self.tcp_label.configure(
            text=f"TCP Ports: {', '.join(f'{port}: {service}' for port, service in tcp_ports.items()) if tcp_ports else 'No open TCP ports.'}"
        )
        self.udp_label.configure(
            text=f"UDP Ports: {', '.join(f'{port}: {service}' for port, service in udp_ports.items()) if udp_ports else 'No open UDP ports.'}"
        )
        self.parent.show_page(self)

    def go_back(self):
        self.parent.show_page(self.parent.page3)  # Go back to the active hosts page


class Page4(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")

        # Configure rows and columns to center the content
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create a label for Page 4
        self.page4_label = ctk.CTkLabel(self, text="Next tools", font=("Helvetica", 30))
        self.page4_label.pack(pady=20)

        # Add a button to go back to Page 1
        self.back_button = ctk.CTkButton(
            self, text="Back", command=lambda: self.parent.show_page(self.parent.page3)
        )
        self.back_button.pack(pady=20)


if __name__ == "__main__":
    app = MainApp()
    app.mainloop()
