# Copyright (c) [2023] [Peyman Kinz]
#
# Hiermit wird unentgeltlich jeder Person, die eine Kopie der Software und der zugehörigen Dokumentationen (die "Software") erhält, die Erlaubnis erteilt, sie uneingeschränkt zu nutzen, einschließlich und ohne Ausnahme mit dem Recht, sie zu verwenden, zu kopieren, zu ändern, zusammenzuführen, zu verlegen, zu verbreiten, zu unterlizenzieren und/oder zu verkaufen, und Personen, denen diese Software überlassen wird, diese Rechte zu verschaffen, unter den folgenden Bedingungen:

# Bedingung 1: Urheberrechtsvermerk
# Der obige Urheberrechtsvermerk und dieser Erlaubnisvermerk sind in allen Kopien oder Teilkopien der Software beizufügen.

# Bedingung 2: Keine Gewährleistung
# DIE SOFTWARE WIRD OHNE JEDE AUSDRÜCKLICHE ODER IMPLIZIERTE GARANTIE BEREITGESTELLT, EINSCHLIESSLICH DER GARANTIE ZUR BENUTZUNG FÜR DEN VORGESEHENEN ODER EINEM BESTIMMTEN ZWECK SOWIE JEGLICHER RECHTSVERLETZUNG, JEDOCH NICHT DARAUF BESCHRÄNKT.

# Bedingung 3: Haftungsausschluss
# IN KEINEM FALL SIND DIE AUTOREN ODER COPYRIGHT-INHABER FÜR JEGLICHEN SCHADEN ODER SONSTIGE ANSPRÜCHE HAFTBAR ZU MACHEN, OB INFOLGE DER ERFÜLLUNG VON EINEM VERTRAG, EINER UNERLAUBTEN HANDLUNG ODER ANDERWEITIG, DIE AUS ODER IM ZUSAMMENHANG MIT DER SOFTWARE ODER DER BENUTZUNG ODER ANDEREN EINSATZ DER SOFTWARE ENTSTEHEN.

# Bedingung 4: Verbreitung
# Bei der Verbreitung der Software ist es erforderlich, den obigen Urheberrechtsvermerk und diesen Erlaubnisvermerk in der Dokumentation und auf angemessene Weise im Zusammenhang mit der Software beizufügen.

from PIL import Image, ImageTk
import tkinter as tk
from tkinter import ttk
import socket
import threading
import http.client
import subprocess
import requests
import whois
from scapy.all import sniff
import ipaddress
import pyshark
import nmap
from scapy.all import sniff, IP, TCP


scan_cancelled = False

user_credentials = {
    "user1": "password1",
    "user2": "password2",
    "user3": "password3",
    "user4": "password4",
    "user5": "password5",
}


# Globale Variable, um den Zugriff auf das Tool zu steuern
access_granted = False
def login():
    global access_granted
    username = username_entry.get()
    password = password_entry.get()
    
    if username in user_credentials and user_credentials[username] == password:
        access_granted = True
        # Wenn die Anmeldung erfolgreich ist, öffnen Sie ein Willkommensfenster
        open_welcome_window()
    else:
        error_label.config(text="Falsche Anmeldeinformationen")

def open_welcome_window():
    # Ein neues Willkommensfenster erstellen
    welcome_window = tk.Toplevel()
    welcome_window.title("Willkommen!")

    # Hier können Sie Widgets (Label, Text, Buttons usw.) für das Willkommensfenster hinzufügen
    welcome_label = ttk.Label(welcome_window, text="Willkommen im Port Scanner Tool!", font=("Helvetica", 16))
    welcome_label.pack(padx=20, pady=20)

def open_tool():
    if access_granted:
        tool_window = tk.Tk()
        tool_window.title("PortWhisper")

def register():
    username = register_username_entry.get()
    password = register_password_entry.get()

    # Registriere den Benutzer
    user_credentials[username] = password
    registration_success_label.config(text="Registrierung erfolgreich!")

# Erstelle das Hauptfenster (Login und Registrierung)
main_window = tk.Tk()
main_window.title("Registration")

notebook = ttk.Notebook(main_window)
notebook.pack(fill="both", expand=True)

# Login-Seite
login_frame = ttk.Frame(notebook)
notebook.add(login_frame, text="Login")

login_frame.grid(row=0, column=0, padx=20, pady=20)
frame = ttk.Frame(login_frame)
frame.grid(row=0, column=0)

# Benutzername und Passwort Eingabefelder für das Login
username_label = ttk.Label(frame, text="Benutzername:")
username_label.grid(row=0, column=0, sticky="w")
username_entry = ttk.Entry(frame)
username_entry.grid(row=0, column=1)

password_label = ttk.Label(frame, text="Passwort:")
password_label.grid(row=1, column=0, sticky="w")
password_entry = ttk.Entry(frame, show="*")  # Passwortfeld, zeigt Sternchen
password_entry.grid(row=1, column=1)

login_button = ttk.Button(frame, text="Anmelden", command=login)
login_button.grid(row=2, column=0, columnspan=2)

error_label = ttk.Label(frame, text="", foreground="red")
error_label.grid(row=3, column=0, columnspan=2)

# Registrierungsseite
# Registrierungsseite
register_frame = ttk.Frame(notebook)
notebook.add(register_frame, text="Registration")

register_frame.grid(row=0, column=0, padx=20, pady=20)
frame = ttk.Frame(register_frame)
frame.grid(row=0, column=0)

# Benutzername und Passwort Eingabefelder für die Registrierung
register_username_label = ttk.Label(frame, text="Benutzername:", font=("Helvetica", 14))
register_username_label.grid(row=0, column=0, sticky="w")
register_username_entry = ttk.Entry(frame, font=("Helvetica", 12))
register_username_entry.grid(row=0, column=1)

register_password_label = ttk.Label(frame, text="Passwort:", font=("Helvetica", 14))
register_password_label.grid(row=1, column=0, sticky="w")
register_password_entry = ttk.Entry(frame, show="*", font=("Helvetica", 12))  # Passwortfeld, zeigt Sternchen
register_password_entry.grid(row=1, column=1)

register_button = ttk.Button(frame, text="Registrieren", command=register, style="C.TButton")
register_button.grid(row=2, column=0, columnspan=2)

registration_success_label = ttk.Label(frame, text="", font=("Helvetica", 14))
registration_success_label.grid(row=3, column=0, columnspan=2)

# Erstelle einen neuen Stil (Style) für die Schaltfläche
style = ttk.Style()
style.configure("C.TButton", foreground="white", background="blue", font=("Helvetica", 12))

main_window.mainloop()

# Funktion zum Abbrechen des Scans
def cancel_scan():
    global scan_cancelled
    scan_cancelled = True
    result_text.insert(tk.END, "Scan beendet.\n")

# Funktion zum Scannen der Ports
def check_vulnerabilities(target_ip, port):
    vulnerabilities = {
        22: "SSH Vulnerability Description",
        80: "HTTP Vulnerability Description",
        # Fügen Sie hier weitere Schwachstellen und die entsprechenden Ports hinzu
    }
    
    if port in vulnerabilities:
        result_text.insert(tk.END, f"Potential Vulnerability Found on Port {port}: {vulnerabilities[port]}\n", "vulnerable")
    else:
        result_text.insert(tk.END, f"No Vulnerabilities Found on Port {port}\n", "safe")

# Funktion zum Scannen der Ports
def scan_ports():
    global scan_cancelled
    scan_cancelled = False
    
    # Ziel-IP-Adresse aus dem Eingabefeld abrufen
    target = entry.get()
    result_text.delete("1.0", tk.END)
    
    # Portbereich aus dem Eingabefeld abrufen und aufteilen
    port_range = port_entry.get().split('-')

    try:
        # Hostname in IP-Adresse auflösen
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        result_text.insert(tk.END, "Ungültiger Hostname")
        return

    # Funktion zum Durchführen des Scans für einen Port
    def do_scan(port, scan_type):
        try:
            if scan_type == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
            elif scan_type == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                result = sock.connect_ex((target_ip, port))
            elif scan_type == "HTTP":
                conn = http.client.HTTPConnection(target_ip, port, timeout=1)
                conn.request("GET", "/")
                response = conn.getresponse()
                result = response.status
                conn.close()
            else:
                result_text.insert(tk.END, "Ungültiger Scan-Typ")
                return

            if result == 0:
                result_text.insert(tk.END, f"(Port {port} ist offen.)\n", "open")
                check_vulnerabilities(target_ip, port)
            elif result == 200:
                result_text.insert(tk.END, f"(Port {port} ist ein HTTP-Server und geöffnet.)\n", "open")
                check_vulnerabilities(target_ip, port)
            else:
                result_text.insert(tk.END, f"(Port {port} ist geschlossen.)\n", "closed")
        except socket.timeout:
            if not scan_cancelled:
                result_text.insert(tk.END, f"(Port {port} hat nicht geantwortet.)\n", "timeout")

        # Ergebnisse des Scans auf der Traceroute-Seite anzeigen
        traceroute_result_text.insert(tk.END, f"Port {port}: {result}\n")
        # Ergebnisse des Scans auf der Traceroute-Seite anzeigen
        traceroute_result_text.insert(tk.END, f"Port {port}: {result}\n")

    # Start- und Endport aus dem Portbereich abrufen
    start_port = int(port_range[0])
    end_port = int(port_range[1]) if len(port_range) > 1 else start_port

    # Ausgewählten Scantyp abrufen
    selected_scan = scan_type_var.get()
    scan_name = scan_types[selected_scan]

    # Schleife zum Durchführen des Scans für jeden Port im Bereich
    for port in range(start_port, end_port + 1):
        if scan_cancelled:
            break
        
        # Thread erstellen und den Scan für den Port ausführen
        thread = threading.Thread(target=do_scan, args=(port, scan_name))
        thread.start()

# Funktion zum Auflösen eines Hostnamens in eine IP-Adresse
def resolve_hostname():
    hostname = entry.get()
    try:
        ip_address = socket.gethostbyname(hostname)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"Die IP-Adresse für {hostname} ist {ip_address}\n")
    except socket.gaierror:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, "Ungültiger Hostname\n")

# Funktion zum Abrufen von Hostinformationen
def get_host_info():
    hostname = entry.get()
    try:
        host_info = subprocess.check_output(["nslookup", hostname], text=True)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, host_info)
    except subprocess.CalledProcessError:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, "Fehler beim Abrufen von Hostinformationen\n")

# Funktion zur Durchführung einer WHOIS-Abfrage
def perform_whois_query():
    domain = whois_entry.get()
    try:
        whois_info = whois.whois(domain)
        whois_result_text.delete("1.0", tk.END)
        whois_result_text.insert(tk.END, str(whois_info))
    except Exception as e:
        whois_result_text.delete("1.0", tk.END)
        whois_result_text.insert(tk.END, f"Fehler bei der WHOIS-Abfrage: {str(e)}")

def start_traffic_capture():
    target_ip = ip_entry.get()
    traffic_result_text.delete("1.0", tk.END)

    def packet_handler(packet):
        traffic_result_text.insert(tk.END, packet.show(dump=True))

    sniff(count=10, filter=f"host {target_ip}", prn=packet_handler)

root = tk.Tk()
root.title("PortWhisper")
root.geometry("800x600")

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

style = ttk.Style()
style.configure("TLabel",  background="gray")
style.configure("open.TLabel", foreground="gray")
style.configure("closed.TLabel", foreground="gray")

style = ttk.Style()
style.configure("Main.TFrame", background="#c0c0c0")  # Hier können Sie die gewünschte Hintergrundfarbe definieren

main_frame = ttk.Frame(notebook, style="Main.TFrame")  # Weisen Sie dem Frame den definierten Stil zu
notebook.add(main_frame, text="Port Reconnaissance")
traffic_route_frame = ttk.Frame(notebook)
notebook.add(traffic_route_frame, text="Traffic Route")

host_info_frame = ttk.Frame(notebook)
notebook.add(host_info_frame, text="Host Infos")

traceroute_frame = ttk.Frame(notebook)
notebook.add(traceroute_frame, text="Traceroute")

whois_frame = ttk.Frame(notebook)
notebook.add(whois_frame, text="WHOIS Abfrage")

settings_frame = ttk.Frame(notebook)
notebook.add(settings_frame, text="Einstellungen")

whois_label = tk.Label(whois_frame, text="Domain eingeben:", font=("Helvetica", 14))
whois_label.pack(padx=20, pady=10)
whois_entry = tk.Entry(whois_frame, font=("Helvetica", 12))
whois_entry.pack(padx=20, pady=10)

whois_button = tk.Button(whois_frame, text="WHOIS Abfrage starten", command=perform_whois_query, bg="blue", fg="white")
whois_button.pack(padx=20, pady=10)

whois_result_text = tk.Text(whois_frame, font=("Helvetica", 14))
whois_result_text.pack(padx=20, pady=20, fill='both', expand=True)

# Label und Eingabefeld für die IP-Adresse
label = tk.Label(main_frame, text="IP address + port range :",  font=("Helvetica Bold", 12))
label.pack(pady=20)
entry = tk.Entry(main_frame,  font=("Helvetica Bold", 12))
entry.pack(padx=20, pady=10)

# Label und Eingabefeld für den Portbereich
port_label = tk.Label(main_frame, text="port range (example 80-100):",   font=("Inconsolata", 12))
port_entry = tk.Entry(main_frame,  font=("Helvetica Bold", 12))
port_entry.pack(padx=20, pady=10)

# Buttons für den Port-Scan
button_frame = tk.Frame(main_frame)
button_frame.pack(pady=10)
scan_button = tk.Button(button_frame, text="Scan starten", command=scan_ports, bg="blue", fg="white", font=("Helvetica Bold", 10, "bold"))
scan_button.pack(side=tk.LEFT, padx=10)
cancel_button = tk.Button(button_frame, text="Scan beenden", command=cancel_scan, bg="blue", fg="white", font=("Helvetica Bold", 10, "bold"))
cancel_button.pack(side=tk.LEFT, padx=10)
resolve_button = tk.Button(button_frame, text="Hostname auflösen", command=resolve_hostname, bg="blue", fg="white", font=("Helvetica Bold", 10, "bold"))
resolve_button.pack(side=tk.LEFT, padx=10)

# Textfeld für die Ergebnisse des Port-Scans
result_text = tk.Text(main_frame, font=("Helvetica Bold", 12))
result_text.pack(padx=20, pady=20, fill='both', expand=True)
result_text.tag_configure("open", foreground="green")  # Farbe für offene Ports
result_text.tag_configure("closed", foreground="red")  # Farbe für geschlossene Ports
result_text.tag_configure("timeout", foreground="orange")  # Farbe für nicht antwortende Ports

# Einstellungsframe für den Scan-Typ
settings_label = tk.Label(settings_frame, text="Einstellungen", font=("Helvetica", 24))
settings_label.pack(pady=20)

# Radiobuttons für den Scan-Typ
scan_type_var = tk.IntVar()
scan_type_var.set(0)  # Standard: TCP-Scan
scan_types = {0: "TCP", 1: "UDP", 2: "HTTP"}
scan_type_label = tk.Label(settings_frame, text="Scan-Typ:", font=("Helvetica", 14))
scan_type_label.pack(padx=20, pady=10)
tcp_scan_radio = tk.Radiobutton(settings_frame, text="TCP", variable=scan_type_var, value=0)
udp_scan_radio = tk.Radiobutton(settings_frame, text="UDP", variable=scan_type_var, value=1)
http_scan_radio = tk.Radiobutton(settings_frame, text="HTTP", variable=scan_type_var, value=2)
tcp_scan_radio.pack(padx=20, pady=5, anchor="w")
udp_scan_radio.pack(padx=20, pady=5, anchor="w")
http_scan_radio.pack(padx=20, pady=5, anchor="w")

# Hostinformationsframe
host_info_label = tk.Label(host_info_frame, text="Host Informationen", font=("Helvetica", 24))
host_info_label.pack(pady=20)

# Button zum Abrufen von Hostinformationen
host_info_button = tk.Button(host_info_frame, text="Host Informationen abrufen", command=get_host_info, bg="blue", fg="white")
host_info_button.pack(padx=20, pady=10)

# Textfeld für Hostinformationen
host_info_text = tk.Text(host_info_frame, font=("Helvetica", 12))
host_info_text.pack(padx=20, pady=20, fill='both', expand=True)

# Textfeld für das Traceroute-Ergebnis
traceroute_result_text = tk.Text(traceroute_frame, font=("Helvetica", 14))
traceroute_result_text.pack(padx=20, pady=20, fill='both', expand=True)

# Eingabefeld für die IP-Adresse im Tab "Traffic Route"
ip_label = tk.Label(traffic_route_frame, text="IP-Adresse eingeben:", font=("Helvetica", 14))
ip_label.pack(padx=20, pady=10)
ip_entry = tk.Entry(traffic_route_frame, font=("Helvetica", 12))
ip_entry.pack(padx=20, pady=10)

# Button zum Starten des Capture-Vorgangs im Tab "Traffic Route"
capture_button = tk.Button(traffic_route_frame, text="Capture starten", command=start_traffic_capture, bg="blue", fg="white")
capture_button.pack(padx=20, pady=10)

# Textfeld für die Ergebnisse des Traffic Captures
traffic_result_text = tk.Text(traffic_route_frame, font=("Helvetica", 10))
traffic_result_text.pack(padx=20, pady=20, fill='both', expand=True)


def subnet_scan(subnet):
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, f"Scanne Subnetz {subnet}...\n")

    # Scannen der IP-Adressen im Subnetz
    for ip in ipaddress.IPv4Network(subnet, strict=False):
        if scan_cancelled:
            break
        target_ip = str(ip)
        try:
            # Hier kannst du den Portscan oder andere Netzwerkscans durchführen
            # Zum Beispiel: scan_ports(target_ip)
            result_text.insert(tk.END, f"Scanne IP {target_ip}...\n")

        except Exception as e:
            result_text.insert(tk.END, f"Fehler beim Scannen von {target_ip}: {str(e)}\n")

help_frame = ttk.Frame(notebook)
notebook.add(help_frame, text="Help")

# Text explaining the tool
help_text = tk.Text(help_frame, font=("Helvetica", 12))
help_text.tag_configure("red", foreground="red")  # Define a "red" tag for red color


# Text explaining the tool
help_text = tk.Text(help_frame, font=("Helvetica", 12))
help_text.tag_configure("red", foreground="red")  # Define a "red" tag for red color

# Introduction to the Port Scanner Tool
help_text.insert(tk.END, "Welcome to the Port Scanner Tool!\n\n", "red")
help_text.insert(tk.END, "The Port Scanner Tool is a versatile utility for network and security professionals. It allows you to perform various network-related tasks, including port scanning, hostname resolution, WHOIS queries, traceroutes, and traffic captures.\n", "red")
help_text.insert(tk.END, "\n", "red")

# Explanation for Port Scanning
help_text.insert(tk.END, "Port Scanning:\n", "red")
help_text.insert(tk.END, "Port scanning is the process of examining a target host for open or closed ports. Open ports can represent potential vulnerabilities, and identifying them is essential for network security and administration.\n", "red")
help_text.insert(tk.END, "1. Enter the target IP address and port range in the 'Scan Ports' tab.\n", "red")
help_text.insert(tk.END, "2. Choose the scan type (TCP, UDP, HTTP) in the 'Settings' tab.\n", "red")
help_text.insert(tk.END, "3. Click the 'Scan starten' button to initiate the scan.\n", "red")
help_text.insert(tk.END, "4. View the scan results in the text box below.\n", "red")
help_text.insert(tk.END, "\n", "red")

# Explanation for Resolving Hostname to IP
help_text.insert(tk.END, "Resolving Hostname to IP:\n", "red")
help_text.insert(tk.END, "Hostname resolution is the process of converting a human-readable hostname into an IP address. This feature is useful for identifying the IP address associated with a domain or host.\n", "red")
help_text.insert(tk.END, "1. Enter a hostname in the 'Host Infos' tab.\n", "red")
help_text.insert(tk.END, "2. Click the 'Host Informationen abrufen' button to resolve the hostname to an IP address.\n", "red")
help_text.insert(tk.END, "3. View the resolved IP address in the text box below.\n", "red")
help_text.insert(tk.END, "\n", "red")

# Explanation for WHOIS Query
help_text.insert(tk.END, "WHOIS Query:\n", "red")
help_text.insert(tk.END, "The WHOIS query is a protocol used to obtain information about domains and IP addresses. It provides details about domain ownership, registration, and contact information.\n", "red")
help_text.insert(tk.END, "1. Enter a domain in the 'WHOIS Abfrage' tab.\n", "red")
help_text.insert(tk.END, "2. Click the 'WHOIS Abfrage starten' button to perform a WHOIS query for the domain.\n", "red")
help_text.insert(tk.END, "3. View the WHOIS information in the text box below.\n", "red")
help_text.insert(tk.END, "\n", "red")

# Explanation for Traceroute
help_text.insert(tk.END, "Traceroute:\n", "red")
help_text.insert(tk.END, "Traceroute is a diagnostic tool used to visualize the path packets take from your device to a target IP address. It displays the route and delays for each hop along the way.\n", "red")
help_text.insert(tk.END, "1. Enter a target IP address in the 'Scan Ports' tab.\n", "red")
help_text.insert(tk.END, "2. Click the 'Traceroute starten' button to perform a traceroute to the target IP address.\n", "red")
help_text.insert(tk.END, "3. View the traceroute results in the text box below.\n", "red")
help_text.insert(tk.END, "\n", "red")

# Explanation for Traffic Capture
help_text.insert(tk.END, "Traffic Capture:\n", "red")
help_text.insert(tk.END, "Traffic capture is the process of intercepting and logging data traffic between devices on a network. It is a valuable tool for network analysis and troubleshooting.\n", "red")
help_text.insert(tk.END, "1. Enter a target IP address in the 'Traffic Route' tab.\n", "red")
help_text.insert(tk.END, "2. Click the 'Capture starten' button to initiate a traffic capture for the target IP address.\n", "red")
help_text.insert(tk.END, "3. View the captured traffic results in the text box below.\n", "red")
help_text.insert(tk.END, "\n", "red")

# Security Guidelines and Disclaimer
help_text.insert(tk.END, "Security Guidelines and Recommendations:\n", "red")
help_text.insert(tk.END, "1. Only scan networks and ports for which you have authorization.\n", "red")
help_text.insert(tk.END, "2. Respect the privacy and security of others.\n", "red")
help_text.insert(tk.END, "3. Comply with the legal regulations and laws of your country.\n", "red")
help_text.insert(tk.END, "4. Use this application responsibly and ethically.\n", "red")
help_text.insert(tk.END, "Enjoy using the Port Scanner tool responsibly!\n", "red")

help_text.pack(padx=20, pady=20, fill='both', expand=True)
# Funktion zum Network Mapping
def perform_network_mapping():
    target = ip_entry.get()
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, f"Network Mapping für {target} wird durchgeführt...\n")

    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-F')  # -F führt einen schnellen Scan durch

    for host in nm.all_hosts():
        result_text.insert(tk.END, f"Host: {host}\n")
        result_text.insert(tk.END, f"State: {nm[host].state()}\n")
        for proto in nm[host].all_protocols():
            result_text.insert(tk.END, f"Protocol: {proto}\n")
            port_list = nm[host][proto].keys()
            for port in port_list:
                result_text.insert(tk.END, f"Port: {port} - Status: {nm[host][proto][port]['state']}\n")

style.theme_use("default")

nip_entry = tk.Entry(traffic_route_frame, font=("Helvetica", 12))
ip_entry.pack_forget()

network_mapping_frame = ttk.Frame(notebook)
notebook.add(network_mapping_frame, text="Network Mapping")

# Add a new text widget for live traffic monitoring results
live_traffic_result_text = tk.Text(network_mapping_frame, font=("Helvetica", 12))
live_traffic_result_text.pack(padx=20, pady=20, fill='both', expand=True)


# Modify the live_traffic_monitor function to take the target IP as a parameter
def live_traffic_monitor(target_ip):
    def packet_handler(packet):
        if IP in packet and TCP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            live_traffic_result_text.insert(tk.END, f"Source IP: {source_ip}, Source Port: {source_port}\n")
            live_traffic_result_text.insert(tk.END, f"Destination IP: {destination_ip}, Destination Port: {destination_port}\n")
            live_traffic_result_text.insert(tk.END, "--------------------------\n")

    live_traffic_result_text.delete("1.0", tk.END)
    live_traffic_result_text.insert(tk.END, f"Live Traffic Monitoring for {target_ip}...\n")
    sniff(filter=f"host {target_ip}", prn=packet_handler, store=0)


# Add an entry field for the target IP in the "Network Mapping" tab
target_ip_label = tk.Label(network_mapping_frame, text="Ziel-IP-Adresse eingeben:", font=("Helvetica", 14))
target_ip_label.pack(padx=20, pady=10)

target_ip_entry = tk.Entry(network_mapping_frame, font=("Helvetica", 12))
target_ip_entry.pack(padx=20, pady=10)

# Modify the button to pass the target IP to the live_traffic_monitor function
network_mapping_button = tk.Button(network_mapping_frame, text="Start Live Traffic Monitor", command=lambda: live_traffic_monitor(target_ip_entry.get()), bg="blue", fg="white")
network_mapping_button.pack(padx=20, pady=10)

root.mainloop()
