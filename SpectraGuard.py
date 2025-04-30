import os
import sys
import threading
import subprocess
import json
import socket
import ctypes
import customtkinter as ctk
from tkinter import messagebox, filedialog
from fpdf import FPDF
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import psutil
import re
import winreg
import requests
import tempfile
import zipfile
import time
import random
import itertools

# --- Ensure running as administrator on Windows ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# --- Configuration ---
APP_VERSION = "2.1.0"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "your_email@gmail.com"
SMTP_PASSWORD = "your_smtp_password"
RISKY_PORTS = [21, 22, 23, 25, 80, 135, 139, 445, 3389, 5985, 5986]

class ScannerUI:
    def __init__(self, frame):
        self.frame = frame
        self.messages = [
            "🔍 Probing system security...",
            "⚡ Analyzing network vulnerabilities...",
            "🛡️ Checking defense mechanisms...",
            "🔒 Scanning encryption status...",
            "📡 Monitoring network traffic...",
            "⚠️ Detecting potential threats...",
            "🔐 Validating security protocols...",
            "🌐 Mapping network topology...",
            "💻 Inspecting system configuration...",
            "🚨 Checking for suspicious activity..."
        ]
        self.scan_icons = itertools.cycle(["⚡", "🔍", "🛡️", "🔒", "📡", "⚠️"])
        self.setup_ui()

    def setup_ui(self):
        # Title with animation
        self.title = ctk.CTkLabel(
            self.frame, 
            text="System Security Analysis", 
            font=ctk.CTkFont(size=32, weight="bold")
        )
        self.title.pack(pady=(30,20))

        # Progress frame with glass effect
        self.progress_frame = ctk.CTkFrame(self.frame, fg_color="#1a1f36")
        self.progress_frame.pack(pady=20, padx=50, fill="x")

        # Animated icon
        self.icon_label = ctk.CTkLabel(
            self.progress_frame, 
            text="⚡", 
            font=ctk.CTkFont(size=48)
        )
        self.icon_label.pack(pady=10)

        # Status with colorful text
        self.status_label = ctk.CTkLabel(
            self.progress_frame,
            text="Initializing scan...",
            font=ctk.CTkFont(size=18)
        )
        self.status_label.pack(pady=5)

        # Progress bar
        self.progress = ctk.CTkProgressBar(self.progress_frame, width=600)
        self.progress.pack(pady=15)
        self.progress.set(0)

        # Details frame
        self.details_frame = ctk.CTkFrame(self.frame, fg_color="#1a1f36")
        self.details_frame.pack(pady=20, padx=50, fill="both", expand=True)

        # Log display
        self.log = ctk.CTkTextbox(
            self.details_frame,
            width=800,
            height=300,
            font=ctk.CTkFont(size=14)
        )
        self.log.pack(padx=20, pady=20, fill="both", expand=True)

    def update(self, progress, section):
        self.progress.set(progress)
        self.icon_label.configure(text=next(self.scan_icons))
        message = random.choice(self.messages)
        self.status_label.configure(text=f"{message}\nScanning: {section}")
        
        # Add color-coded log entry
        self.log.configure(state="normal")
        timestamp = time.strftime("%H:%M:%S")
        self.log.insert("end", f"[{timestamp}] ")
        self.log.insert("end", f"🔍 Analyzing {section}...\n")
        self.log.see("end")
        self.log.configure(state="disabled")
        self.frame.update()

def download_file(url, filename):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception as e:
        print(f"Download error: {e}")
        return False

def install_nmap():
    try:
        # Download Nmap installer
        nmap_url = "https://nmap.org/dist/nmap-7.94-setup.exe"
        temp_dir = tempfile.gettempdir()
        installer_path = os.path.join(temp_dir, "nmap_setup.exe")
        
        if download_file(nmap_url, installer_path):
            # Run the installer silently
            subprocess.run([installer_path, "/S"], shell=True)
            time.sleep(5)  # Wait for installation
            
            # Add Nmap to PATH if needed
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Nmap", 0, winreg.KEY_READ)
                nmap_path = winreg.QueryValueEx(key, "InstallDir")[0]
                winreg.CloseKey(key)
                
                if nmap_path not in os.environ['PATH']:
                    os.environ['PATH'] = nmap_path + os.pathsep + os.environ['PATH']
                return True
            except WindowsError:
                return False
    except Exception as e:
        print(f"Installation error: {e}")
        return False
    finally:
        # Cleanup
        if os.path.exists(installer_path):
            try:
                os.remove(installer_path)
            except:
                pass
    return False

def run_powershell(command):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"

def get_network_topology():
    import json as _json
    G = nx.DiGraph()
    hostname = socket.gethostname()
    G.add_node(hostname, type="host")
    adapters_json = run_powershell("Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4'} | Select-Object InterfaceAlias,IPAddress | ConvertTo-Json")
    try:
        adapters = _json.loads(adapters_json)
        if isinstance(adapters, dict):
            adapters = [adapters]
        adapter_nodes = []
        for adapter in adapters[:2]:
            alias = adapter.get("InterfaceAlias", "Unknown")
            ip = adapter.get("IPAddress", "")
            node = f"{alias}\n{ip}"
            G.add_node(node, type="adapter")
            G.add_edge(hostname, node)
            adapter_nodes.append(node)
    except Exception:
        adapter_nodes = []
    ports_json = run_powershell("Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Select-Object LocalPort | Sort-Object LocalPort | ConvertTo-Json")
    try:
        ports = _json.loads(ports_json)
        if isinstance(ports, dict):
            ports = [ports]
        port_count = 0
        for port in ports:
            p = str(port.get("LocalPort", ""))
            if p and adapter_nodes:
                port_node = f"Port {p}"
                G.add_node(port_node, type="port")
                G.add_edge(adapter_nodes[0], port_node)
                port_count += 1
                if port_count >= 5:
                    break
    except Exception:
        pass
    return G, hostname

def get_os_info():
    return run_powershell("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime | Format-List")

def get_uptime():
    return run_powershell("(get-date) - (gcim Win32_OperatingSystem).LastBootUpTime | Select Days,Hours,Minutes | Format-List")

def get_installed_hotfixes():
    return run_powershell("Get-HotFix | Select-Object HotFixID,InstalledOn | Format-Table -AutoSize")

def get_antivirus_status():
    return run_powershell("Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled | Format-List")

def get_firewall_status():
    return run_powershell("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize")

def get_users():
    return run_powershell("Get-LocalUser | Select-Object Name,Enabled,LastLogon | Format-Table -AutoSize")

def get_admins():
    return run_powershell("Get-LocalGroupMember -Group Administrators | Select-Object Name,PrincipalSource | Format-Table -AutoSize")

def get_password_policy():
    return run_powershell("net accounts")

def get_running_services():
    return run_powershell("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName | Format-Table -AutoSize")

def get_startup_programs():
    return run_powershell("Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | Format-Table -AutoSize")

def get_open_ports():
    ps = """
    Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} |
    Select-Object LocalPort,OwningProcess,@{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |
    Sort-Object LocalPort | Format-Table -AutoSize
    """
    return run_powershell(ps)

def get_network_adapters():
    return run_powershell("Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,AddressFamily | Format-Table -AutoSize")

def get_bitlocker_status():
    return run_powershell("Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus,VolumeStatus | Format-Table -AutoSize")

def get_uac_status():
    return run_powershell("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | Select-Object EnableLUA")

def get_exploit_protection():
    return run_powershell("Get-ProcessMitigation -System")

def get_event_logs():
    ps = """
    try {
        Get-WinEvent -LogName Security -MaxEvents 20 | 
        Select-Object TimeCreated,Id,LevelDisplayName,Message | Format-Table -AutoSize
    } catch {
        Get-EventLog -LogName Security -Newest 20 | 
        Format-Table TimeGenerated,EntryType,Source,EventID,Message -AutoSize
    }
    """
    return run_powershell(ps)

def get_resource_usage():
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    return f"CPU: {cpu}% | RAM: {mem}% | Disk: {disk}%"

def get_dotnet_versions():
    # Try multiple methods to detect .NET versions
    commands = [
        # Method 1: Basic registry query
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full' -Name Version -ErrorAction SilentlyContinue | Select-Object Version",
        
        # Method 2: WMI query
        "Get-WmiObject -Query \"SELECT * FROM Win32_Product WHERE Name LIKE '%NET Framework%'\" | Select-Object Name, Version",
        
        # Method 3: Direct directory check
        "Get-ChildItem 'C:\\Windows\\Microsoft.NET\\Framework64' -Name | Where-Object { $_ -match 'v\\d' }",
        
        # Method 4: PowerShell check
        "$PSVersionTable.CLRVersion"
    ]
    
    results = []
    for cmd in commands:
        try:
            output = run_powershell(cmd)
            if output and "Error" not in output:
                results.append(output)
        except:
            continue
    
    if not results:
        # Fallback method: Direct file version check
        try:
            system32_path = os.path.join(os.environ['SystemRoot'], 'System32')
            clr_path = os.path.join(system32_path, 'clr.dll')
            if os.path.exists(clr_path):
                version_info = subprocess.check_output(['powershell', '(Get-Item "%s").VersionInfo.FileVersion' % clr_path], text=True)
                results.append(f"CLR Version (from clr.dll): {version_info.strip()}")
        except:
            pass
    
    return "\n".join(results) if results else "Unable to detect .NET versions"

def get_audit_policy():
    return run_powershell("AuditPol /get /category:*")

def get_rdp_settings():
    ps = r"""
    $rdp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    if ($rdp.fDenyTSConnections -eq 0) {"RDP Enabled"} else {"RDP Disabled"}
    """
    return run_powershell(ps)

def get_windows_update_status():
    ps = r"""
    (New-Object -ComObject Microsoft.Update.AutoUpdate).Results | 
    Select-Object LastSearchSuccessDate, LastInstallationSuccessDate, UpdatesAvailable
    """
    return run_powershell(ps)

def get_boot_config():
    return run_powershell("bcdedit /enum")

def get_dns_cache():
    return run_powershell("Get-DnsClientCache | Select-Object Entry, Data | Format-Table -AutoSize")

def get_arp_table():
    return run_powershell("arp -a")

def get_rpc_endpoints():
    return run_powershell("Get-WmiObject Win32_Service | Where-Object {$_.Name -like '*rpc*'} | Select-Object Name, State | Format-Table -AutoSize")

def get_vlan_info():
    return run_powershell("Get-NetAdapter | Select-Object Name, VlanID | Format-Table -AutoSize")

def get_summary_risk_score(report):
    score = 0
    for line in report.splitlines():
        if "Warning" in line or "Critical" in line or "Vulnerable" in line:
            score += 1
    return min(score * 10, 100)

def format_nmap_output(raw_output):
    try:
        formatted = "NMAP SCAN SUMMARY:\n"
        lines = raw_output.split('\n')
        ports_found = []
        services_found = []
        
        for line in lines:
            if '/tcp' in line or '/udp' in line:
                ports_found.append(line.strip())
            if 'Service Info:' in line:
                services_found.append(line.strip())
                
        formatted += "\nOpen Ports and Services:\n"
        formatted += '\n'.join(ports_found) if ports_found else "No open ports found"
        formatted += "\n\nService Information:\n"
        formatted += '\n'.join(services_found) if services_found else "No service information available"
        return formatted
    except:
        return raw_output

def add_recommendations(report_data):
    recs = []
    if "Minimum password length:                              0" in report_data.get("Password Policy", ""):
        recs.append("Warning: Set minimum password length to at least 8.")
    open_ports = report_data.get("Open Ports", "")
    for port in [str(p) for p in RISKY_PORTS]:
        if f" {port} " in open_ports or f"{port} " in open_ports:
            recs.append(f"Warning: Restrict or close risky port {port} if not needed.")
    if "BitLocker" in report_data and "ProtectionStatus" in report_data["BitLocker Status"]:
        if "0" in report_data["BitLocker Status"]:
            recs.append("Warning: Enable BitLocker on system drive for disk encryption.")
    if "EnableLUA" in report_data.get("UAC Status", "") and "0" in report_data["UAC Status"]:
        recs.append("Warning: Enable UAC (User Account Control) for better security.")
    if "False" in report_data.get("Firewall Status", ""):
        recs.append("Warning: Enable Windows Firewall on all profiles.")
    admins = report_data.get("Admin Accounts", "")
    if admins.count("Local") > 2:
        recs.append("Warning: Reduce the number of local admin accounts.")
    if "NOTSET" in report_data.get("Exploit Protection", ""):
        recs.append("Warning: Review and enable Windows Exploit Protection mitigations.")
    av = report_data.get("Antivirus/Defender Status", "")
    if "False" in av:
        recs.append("Warning: Ensure antivirus and real-time protection are enabled and up-to-date.")
    if "Opera" in report_data.get("Startup Programs", "") or "Unknown" in report_data.get("Startup Programs", ""):
        recs.append("Warning: Review startup programs for unknown or unnecessary entries.")
    if "Error:" in report_data.get("Recent Security Events", ""):
        recs.append("Warning: Run scanner as administrator to access all event logs.")
    
    # Add Nmap-specific recommendations
    nmap_results = report_data.get("Nmap Scan Results", "")
    if "21/tcp" in nmap_results:
        recs.append("Warning: FTP port 21 is open. Consider using SFTP instead.")
    if "23/tcp" in nmap_results:
        recs.append("Critical: Telnet port 23 is open. This is insecure, use SSH instead.")
    if "3389/tcp" in nmap_results:
        recs.append("Warning: RDP port 3389 is open. Limit access if not needed.")
    if "445/tcp" in nmap_results:
        recs.append("Warning: SMB port 445 is open. Ensure it's properly secured.")
    
    report_data["Recommendations"] = "\n".join(recs) if recs else "No critical recommendations."

def save_report(data, filename):
    with open(filename, 'w', encoding="utf-8") as file:
        for section, content in data.items():
            file.write(f"{section}:\n{content}\n\n")

def save_json(data, filename):
    with open(filename, 'w', encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def generate_pdf(data, filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    for section, content in data.items():
        pdf.set_font("Arial", style="B", size=12)
        pdf.cell(0, 10, txt=section, ln=True)
        pdf.set_font("Arial", size=10)
        for line in str(content).splitlines():
            pdf.multi_cell(0, 8, txt=line)
        pdf.ln(2)
    pdf.output(filename)

def send_email(subject, body, to_email, attachments=None):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    if attachments:
        for attachment in attachments:
            try:
                with open(attachment, "rb") as attach_file:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attach_file.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename= {os.path.basename(attachment)}")
                msg.attach(part)
            except Exception as e:
                print(f"Error attaching file: {e}")
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)

def check_nmap_installed():
    try:
        result = subprocess.run(["nmap", "-V"], capture_output=True, text=True)
        return True if result.returncode == 0 else False
    except FileNotFoundError:
        return False

def run_nmap_scan(target="127.0.0.1"):
    if not check_nmap_installed():
        message = "Nmap is not installed. Would you like to install it now?"
        if messagebox.askyesno("Nmap Required", message):
            if install_nmap():
                messagebox.showinfo("Success", "Nmap has been installed successfully.")
            else:
                return "Error: Failed to install Nmap. Please install it manually from https://nmap.org/"
        else:
            return "Error: Nmap is required for network scanning."
        
    # Check again after potential installation
    if not check_nmap_installed():
        return "Error: Nmap is not available."
        
    try:
        # Run a more comprehensive scan
        result = subprocess.run(
            ["nmap", "-sV", "T4", "-A", target], 
            capture_output=True, 
            text=True
        )
        return format_nmap_output(result.stdout)
    except Exception as e:
        return f"Nmap scan error: {str(e)}"

class ModernVulnScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title(f"Vulnerability Scanner v{APP_VERSION}")
        self.geometry("1100x750")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # State for dashboard stats
        self.last_scan_time = "Never"
        self.last_risk_score = "N/A"
        self.last_recommend_count = "N/A"
        self.last_os_info = "Unknown"

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=260, fg_color="#232946")
        self.sidebar.pack(side="left", fill="y", padx=(0, 0), pady=(0, 0))
        ctk.CTkLabel(self.sidebar, text="🔒", font=ctk.CTkFont(size=48)).pack(pady=(36, 8))
        ctk.CTkLabel(self.sidebar, text="SpectraGuard", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(0, 24))

        # Separator line
        ctk.CTkFrame(self.sidebar, height=2, fg_color="#1a1a1a").pack(fill="x", padx=18, pady=(0, 18))

        self.dashboard_btn = ctk.CTkButton(self.sidebar, text="Dashboard", command=self.show_dashboard, width=180)
        self.dashboard_btn.pack(pady=(0, 14))
        self.scan_btn = ctk.CTkButton(self.sidebar, text="Scan", command=self.start_scan_from_sidebar, width=180)
        self.scan_btn.pack(pady=(0, 14))
        self.report_btn = ctk.CTkButton(self.sidebar, text="Report", command=self.show_report, width=180)
        self.report_btn.pack(pady=(0, 14))
        self.topo_btn = ctk.CTkButton(self.sidebar, text="Network Map", command=self.show_topology, width=180)
        self.topo_btn.pack(pady=(0, 14))
        self.export_btn = ctk.CTkButton(self.sidebar, text="Export Report", command=self.export_json, width=180)
        self.export_btn.pack(pady=(0, 14))
        self.email_btn = ctk.CTkButton(self.sidebar, text="Send Email", command=self.send_email_report, width=180)
        self.email_btn.pack(pady=(0, 14))

        # Add stretchable space before status label
        ctk.CTkLabel(self.sidebar, text="").pack(expand=True, fill="both")

        self.status_label = ctk.CTkLabel(self.sidebar, text="Ready.", font=ctk.CTkFont(size=12))
        self.status_label.pack(side="bottom", pady=24)

        # Main content
        self.content = ctk.CTkFrame(self, fg_color="#121629")
        self.content.pack(side="right", fill="both", expand=True)
        self.dashboard_frame = None
        self.scan_frame = None
        self.report_frame = None
        self.topology_frame = None
        self.show_dashboard()

    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def show_dashboard(self):
        self.clear_content()
        frame = ctk.CTkFrame(self.content, fg_color="#121629")
        frame.pack(fill="both", expand=True, padx=30, pady=30)

        # Cards row
        cards_frame = ctk.CTkFrame(frame, fg_color="#232946")
        cards_frame.pack(fill="x", pady=(0, 30))

        # Card: Last Scan Time
        card1 = ctk.CTkFrame(cards_frame, fg_color="#2b2b2b", width=200, height=100, corner_radius=16)
        card1.pack(side="left", padx=20, pady=20, expand=True, fill="both")
        ctk.CTkLabel(card1, text="Last Scan", font=ctk.CTkFont(size=14)).pack(pady=(16, 0))
        ctk.CTkLabel(card1, text=self.last_scan_time, font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(8, 16))

        # Card: Last Risk Score
        card2 = ctk.CTkFrame(cards_frame, fg_color="#2b2b2b", width=200, height=100, corner_radius=16)
        card2.pack(side="left", padx=20, pady=20, expand=True, fill="both")
        ctk.CTkLabel(card2, text="Last Risk Score", font=ctk.CTkFont(size=14)).pack(pady=(16, 0))
        ctk.CTkLabel(card2, text=self.last_risk_score, font=ctk.CTkFont(size=18, weight="bold"), text_color="#ffbb33" if self.last_risk_score != "N/A" and int(str(self.last_risk_score).split('/')[0]) > 50 else "#00C851").pack(pady=(8, 16))

        # Card: Recommendations
        card3 = ctk.CTkFrame(cards_frame, fg_color="#2b2b2b", width=200, height=100, corner_radius=16)
        card3.pack(side="left", padx=20, pady=20, expand=True, fill="both")
        ctk.CTkLabel(card3, text="Recommendations", font=ctk.CTkFont(size=14)).pack(pady=(16, 0))
        ctk.CTkLabel(card3, text=self.last_recommend_count, font=ctk.CTkFont(size=18, weight="bold"), text_color="#ff4444" if self.last_recommend_count != "N/A" and int(self.last_recommend_count) > 0 else "#00C851").pack(pady=(8, 16))

        # Card: OS Info
        card4 = ctk.CTkFrame(cards_frame, fg_color="#2b2b2b", width=300, height=100, corner_radius=16)
        card4.pack(side="left", padx=20, pady=20, expand=True, fill="both")
        ctk.CTkLabel(card4, text="System", font=ctk.CTkFont(size=14)).pack(pady=(16, 0))
        ctk.CTkLabel(card4, text=self.last_os_info, font=ctk.CTkFont(size=13), wraplength=250, justify="center").pack(pady=(8, 16))

        # Welcome and scan button
        ctk.CTkLabel(frame, text="Welcome to SpectraGuard", font=ctk.CTkFont(size=26, weight="bold")).pack(pady=(10, 0))
        ctk.CTkLabel(frame, text="• Run a scan to get started\n• View reports and recommendations\n• Visualize your network topology", font=ctk.CTkFont(size=16)).pack(pady=10)
        ctk.CTkButton(frame, text="Start Scan", command=self.start_scan_from_dashboard, width=220, height=48, font=ctk.CTkFont(size=18, weight="bold")).pack(pady=30)
        self.dashboard_frame = frame

    def show_scan(self):
        self.clear_content()
        frame = ctk.CTkFrame(self.content, fg_color="#121629")
        frame.pack(fill="both", expand=True)
        self.scanner_ui = ScannerUI(frame)
        self.scan_frame = frame
        self.start_scan_thread()

    def start_scan_from_dashboard(self):
        self.show_scan()

    def start_scan_from_sidebar(self):
        self.show_scan()

    def start_scan_thread(self):
        self.status_label.configure(text="Scanning...")
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        try:
            import datetime
            self.scanner_ui.progress.set(0)  # Use scanner_ui's progress bar instead
            self.scanner_ui.status_label.configure(text="Initializing scan...")
            sections = [
                # System Scanning
                ("OS Information", get_os_info),
                ("System Uptime", get_uptime),
                ("Installed Hotfixes", get_installed_hotfixes),
                (".NET Versions", get_dotnet_versions),
                ("Antivirus/Defender Status", get_antivirus_status),
                ("Audit Policy", get_audit_policy),
                ("Firewall Status", get_firewall_status),
                ("User Accounts", get_users),
                ("Admin Accounts", get_admins),
                ("Password Policy", get_password_policy),
                ("Running Services", get_running_services),
                ("Startup Programs", get_startup_programs),
                ("BitLocker Status", get_bitlocker_status),
                ("UAC Status", get_uac_status),
                ("Exploit Protection", get_exploit_protection),
                ("RDP Settings", get_rdp_settings),
                ("Microsoft Updates", get_windows_update_status),
                ("Boot Configuration", get_boot_config),
                # Network Scanning
                ("Network Adapters", get_network_adapters),
                ("Network Properties", get_network_adapters),  # Alias for clarity
                ("Open Ports", get_open_ports),
                ("DNS Cache", get_dns_cache),
                ("ARP Table", get_arp_table),
                ("RPC Endpoints", get_rpc_endpoints),
                ("VLAN Info", get_vlan_info),
                ("Nmap Scan Results (This will take some time ...)", lambda: run_nmap_scan()),  # Add this line
                # Other
                ("Recent Security Events", get_event_logs),
                ("Resource Usage", get_resource_usage),
            ]
            report_data = {}
            for idx, (section, func) in enumerate(sections):
                progress = (idx+1)/len(sections)
                self.scanner_ui.update(progress, section)
                try:
                    result = func()
                    self.scanner_ui.log.configure(state="normal")
                    self.scanner_ui.log.insert("end", f"✅ {section}: Complete\n")
                    self.scanner_ui.log.see("end")
                    self.scanner_ui.log.configure(state="disabled")
                    report_data[section] = result
                except Exception as e:
                    self.scanner_ui.log.configure(state="normal")
                    self.scanner_ui.log.insert("end", f"❌ Error in {section}: {e}\n")
                    self.scanner_ui.log.see("end")
                    self.scanner_ui.log.configure(state="disabled")
                    report_data[section] = f"Error: {e}"
            
            # Final steps
            self.scanner_ui.progress.set(1.0)
            self.scanner_ui.status_label.configure(text="Scan completed! Generating reports...")
            # Recommendations
            add_recommendations(report_data)
            # Risk scoring: count warnings in recommendations
            recs = report_data.get("Recommendations", "")
            warning_count = recs.count("Warning:") + recs.count("Critical:") + recs.count("Vulnerable:")
            risk_score = min(warning_count * 10, 100)
            report_data["Risk Score"] = f"{risk_score}/100"
            save_report(report_data, 'vulnerability_report.txt')
            save_json(report_data, 'vulnerability_report.json')
            generate_pdf(report_data, 'vulnerability_report.pdf')
            # Update dashboard stats
            self.last_scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.last_risk_score = f"{risk_score}/100"
            self.last_recommend_count = str(warning_count)
            os_info = report_data.get("OS Information", "").splitlines()
            self.last_os_info = os_info[0].replace("Caption", "").replace(":", "").strip() if os_info else "Unknown"
            # Instead of saving topology image here, schedule it in main thread:
            self.after(0, self._after_scan_complete)
        except Exception as e:
            self.scanner_ui.status_label.configure(text=f"Error: {e}")
            self.status_label.configure(text=f"Error: {e}")

    def _after_scan_complete(self):
        self.save_topology_image()
        messagebox.showinfo("Scan Completed", "Scan completed and report generated.")
        self.show_dashboard()

    def save_topology_image(self, filename="network_topology.png"):
        G, hostname = get_network_topology()
        fig, ax = plt.subplots(figsize=(7, 4))
        pos = {}
        y_gap = 1.5
        pos[hostname] = (0, y_gap)
        adapters = [n for n in G.nodes if G.nodes[n].get("type") == "adapter"]
        ports = [n for n in G.nodes if G.nodes[n].get("type") == "port"]
        for i, adapter in enumerate(adapters):
            pos[adapter] = (i * 2 - len(adapters) + 1, 0)
        for i, port in enumerate(ports):
            pos[port] = (0, -y_gap - i)
        nx.draw_networkx_nodes(G, pos, nodelist=[hostname], node_color="skyblue", node_shape="o", node_size=1200, label="Host", ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=adapters, node_color="lightgreen", node_shape="s", node_size=1000, label="Adapter", ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=ports, node_color="orange", node_shape="D", node_size=800, label="Port", ax=ax)
        nx.draw_networkx_edges(G, pos, ax=ax)
        nx.draw_networkx_labels(G, pos, font_size=10, font_weight="bold", ax=ax)
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], marker='o', color='w', label='Host', markerfacecolor='skyblue', markersize=12),
            Line2D([0], [0], marker='s', color='w', label='Adapter', markerfacecolor='lightgreen', markersize=12),
            Line2D([0], [0], marker='D', color='w', label='Port', markerfacecolor='orange', markersize=12),
        ]
        ax.legend(handles=legend_elements, loc='upper left')
        ax.set_title("Network Topology (Minimal & Clear)")
        ax.axis('off')
        fig.tight_layout()
        fig.savefig(filename, bbox_inches='tight')
        plt.close(fig)

    def show_report(self):
        self.clear_content()
        frame = ctk.CTkFrame(self.content, fg_color="#121629")
        frame.pack(fill="both", expand=True)
        ctk.CTkLabel(frame, text="Scan Report", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=20)
        try:
            with open('vulnerability_report.txt', 'r', encoding="utf-8") as file:
                report = file.read()
        except Exception:
            report = "No report found. Please run a scan first."
        textbox = ctk.CTkTextbox(frame, width=900, height=500, font=ctk.CTkFont(size=13))
        textbox.pack(padx=20, pady=20, fill="both", expand=True)
        textbox.insert("1.0", report)
        textbox.configure(state="disabled")
        self.report_frame = frame

    def show_topology(self):
        self.clear_content()
        frame = ctk.CTkFrame(self.content, fg_color="#121629")
        frame.pack(fill="both", expand=True)
        ctk.CTkLabel(frame, text="Network Topology", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=20)
        G, hostname = get_network_topology()
        fig, ax = plt.subplots(figsize=(7, 4))
        pos = {}
        y_gap = 1.5
        pos[hostname] = (0, y_gap)
        adapters = [n for n in G.nodes if G.nodes[n].get("type") == "adapter"]
        ports = [n for n in G.nodes if G.nodes[n].get("type") == "port"]
        for i, adapter in enumerate(adapters):
            pos[adapter] = (i * 2 - len(adapters) + 1, 0)
        for i, port in enumerate(ports):
            pos[port] = (0, -y_gap - i)
        nx.draw_networkx_nodes(G, pos, nodelist=[hostname], node_color="skyblue", node_shape="o", node_size=1200, label="Host", ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=adapters, node_color="lightgreen", node_shape="s", node_size=1000, label="Adapter", ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=ports, node_color="orange", node_shape="D", node_size=800, label="Port", ax=ax)
        nx.draw_networkx_edges(G, pos, ax=ax)
        nx.draw_networkx_labels(G, pos, font_size=10, font_weight="bold", ax=ax)
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], marker='o', color='w', label='Host', markerfacecolor='skyblue', markersize=12),
            Line2D([0], [0], marker='s', color='w', label='Adapter', markerfacecolor='lightgreen', markersize=12),
            Line2D([0], [0], marker='D', color='w', label='Port', markerfacecolor='orange', markersize=12),
        ]
        ax.legend(handles=legend_elements, loc='upper left')
        ax.set_title("Network Topology (Minimal & Clear)")
        ax.axis('off')
        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        plt.close(fig)
        self.topology_frame = frame

    def export_json(self):
        try:
            with open('vulnerability_report.json', 'r', encoding="utf-8") as f:
                data = json.load(f)
            file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
            if file_path:
                with open(file_path, 'w', encoding="utf-8") as out:
                    json.dump(data, out, indent=2)
                messagebox.showinfo("Exported", f"Report exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not export: {e}")

    def send_email_report(self):
        dialog = ctk.CTkInputDialog(text="Enter recipient email address:", title="Send Report")
        email = dialog.get_input()
        if not email:
            return
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Invalid Email", "Please enter a valid email address")
            return
        self.show_loading_dialog("Sending email, please wait...")
        threading.Thread(target=self._send_email, args=(email,), daemon=True).start()

    def show_loading_dialog(self, message="Loading..."):
        self.loading_dialog = ctk.CTkToplevel(self)
        self.loading_dialog.title("")
        self.loading_dialog.geometry("320x120")
        self.loading_dialog.resizable(False, False)
        self.loading_dialog.grab_set()
        self.loading_dialog.transient(self)
        self.loading_dialog.protocol("WM_DELETE_WINDOW", lambda: None)  # Disable close
        self.loading_dialog.attributes("-topmost", True)
        ctk.CTkLabel(self.loading_dialog, text=message, font=ctk.CTkFont(size=16)).pack(pady=(24, 10))
        self.spinner_label = ctk.CTkLabel(self.loading_dialog, text="⏳", font=ctk.CTkFont(size=32))
        self.spinner_label.pack()
        self._spinner_running = True
        self._spinner_angle = 0
        self.after(100, self._animate_spinner)

    def _animate_spinner(self):
        if not hasattr(self, "_spinner_running") or not self._spinner_running:
            return
        spinner_chars = ["⏳", "🔄", "🔃", "⏳"]
        self.spinner_label.configure(text=spinner_chars[self._spinner_angle % len(spinner_chars)])
        self._spinner_angle += 1
        self.after(200, self._animate_spinner)

    def hide_loading_dialog(self):
        self._spinner_running = False
        if hasattr(self, "loading_dialog") and self.loading_dialog.winfo_exists():
            self.loading_dialog.grab_release()
            self.loading_dialog.destroy()

    def _send_email(self, to_email):
        try:
            send_email(
                subject="Vulnerability Report",
                body="Please find attached the vulnerability scan PDF report and the network topology map.",
                to_email=to_email,
                attachments=["vulnerability_report.pdf", "network_topology.png"]
            )
            self.after(0, self._on_email_sent, True, None)
        except Exception as e:
            self.after(0, self._on_email_sent, False, str(e))

    def _on_email_sent(self, success, error_msg):
        self.hide_loading_dialog()
        if success:
            self.status_label.configure(text="Email sent successfully.")
            messagebox.showinfo("Email Sent", "The vulnerability report and network map have been sent successfully.")
        else:
            self.status_label.configure(text=f"Email failed: {error_msg}")
            messagebox.showerror("Email Error", f"Failed to send email: {error_msg}")

    def on_close(self):
        self.destroy()

if __name__ == '__main__':
    if os.name == 'nt' and not is_admin():
        # Relaunch as admin
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1)
        sys.exit(0)
    app = ModernVulnScannerApp()
    app.mainloop()


