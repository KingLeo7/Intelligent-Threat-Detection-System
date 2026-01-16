import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import hashlib
import os
import time
import threading
import csv
import json
from datetime import datetime
from collections import defaultdict
from pathlib import Path

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# ================= CONFIGURATION CLASS =================
class Config:
    """Centralized configuration management"""
    def __init__(self):
        self.config_file = "config.json"
        self.load_config()
    
    def load_config(self):
        """Load configuration from file or use defaults"""
        defaults = {
            "monitor_dir": "test_files",
            "check_interval": 3,
            "threshold": 3,
            "log_file": "sample_logs.txt",
            "alert_file": "security_alerts.txt",
            "csv_file": "scan_history.csv",
            "recursive_scan": False,
            "excluded_extensions": [".tmp", ".log"],
            "max_log_entries": 1000
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded = json.load(f)
                    defaults.update(loaded)
        except Exception as e:
            print(f"Config load error: {e}")
        
        for key, value in defaults.items():
            setattr(self, key, value)
    
    def save_config(self):
        """Save current configuration to file"""
        config_dict = {
            "monitor_dir": self.monitor_dir,
            "check_interval": self.check_interval,
            "threshold": self.threshold,
            "recursive_scan": self.recursive_scan,
            "excluded_extensions": self.excluded_extensions
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config_dict, f, indent=4)
        except Exception as e:
            print(f"Config save error: {e}")

# ================= AUTHENTICATION CLASS =================
class AuthManager:
    """Secure authentication management"""
    def __init__(self):
        self.users_file = "users.json"
        self.load_users()
    
    def load_users(self):
        """Load users from encrypted file"""
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    self.users = json.load(f)
            else:
                # Default admin user
                self.users = {
                    "admin": {
                        "password_hash": hashlib.sha256("admin".encode()).hexdigest(),
                        "role": "admin"
                    }
                }
                self.save_users()
        except Exception as e:
            print(f"User load error: {e}")
            self.users = {}
    
    def save_users(self):
        """Save users to file"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=4)
        except Exception as e:
            print(f"User save error: {e}")
    
    def authenticate(self, username, password):
        """Verify user credentials"""
        if username not in self.users:
            return False
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return self.users[username]["password_hash"] == password_hash
    
    def add_user(self, username, password, role="user"):
        """Add new user"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = {
            "password_hash": password_hash,
            "role": role
        }
        self.save_users()

# ================= FILE MONITOR CLASS =================
class FileMonitor:
    """Enhanced file monitoring with better tracking"""
    def __init__(self, config):
        self.config = config
        self.previous_files = {}
        self.file_activity = defaultdict(int)
        self.monitoring = False
        self.monitor_thread = None
        self.callbacks = {
            'on_scan': None,
            'on_alert': None,
            'on_update': None
        }
    
    def get_file_hash(self, path):
        """Calculate SHA-256 hash of file"""
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            return None
    
    def scan_files(self):
        """Scan directory for files"""
        files = {}
        
        if not os.path.exists(self.config.monitor_dir):
            try:
                os.makedirs(self.config.monitor_dir)
            except Exception as e:
                print(f"Directory creation error: {e}")
                return files
        
        try:
            if self.config.recursive_scan:
                # Recursive scan
                for root, dirs, filenames in os.walk(self.config.monitor_dir):
                    for filename in filenames:
                        if self._should_monitor_file(filename):
                            path = os.path.join(root, filename)
                            rel_path = os.path.relpath(path, self.config.monitor_dir)
                            files[rel_path] = {
                                "hash": self.get_file_hash(path),
                                "size": os.path.getsize(path),
                                "modified": datetime.fromtimestamp(os.path.getmtime(path))
                            }
            else:
                # Single directory scan
                for filename in os.listdir(self.config.monitor_dir):
                    path = os.path.join(self.config.monitor_dir, filename)
                    if os.path.isfile(path) and self._should_monitor_file(filename):
                        files[filename] = {
                            "hash": self.get_file_hash(path),
                            "size": os.path.getsize(path),
                            "modified": datetime.fromtimestamp(os.path.getmtime(path))
                        }
        except Exception as e:
            print(f"Scan error: {e}")
        
        return files
    
    def _should_monitor_file(self, filename):
        """Check if file should be monitored"""
        ext = os.path.splitext(filename)[1].lower()
        return ext not in self.config.excluded_extensions
    
    def start_monitoring(self):
        """Start file monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop file monitoring"""
        self.monitoring = False
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        self.previous_files = self.scan_files()
        
        if self.callbacks['on_scan']:
            self.callbacks['on_scan']("Monitoring started", self.previous_files)
        
        while self.monitoring:
            time.sleep(self.config.check_interval)
            
            current = self.scan_files()
            new_files = []
            modified = []
            deleted = []
            
            # Check for new and modified files
            for filename, info in current.items():
                self.file_activity[filename] += 1
                
                if filename not in self.previous_files:
                    new_files.append(filename)
                elif info["hash"] != self.previous_files[filename]["hash"]:
                    modified.append(filename)
            
            # Check for deleted files
            for filename in self.previous_files:
                if filename not in current:
                    deleted.append(filename)
            
            # Log to CSV
            self._log_to_csv(current, new_files, modified, deleted)
            
            # Callback for UI update
            if self.callbacks['on_update']:
                self.callbacks['on_update'](current, new_files, modified, deleted)
            
            # Check for threats
            if len(modified) >= self.config.threshold:
                alert_msg = (
                    f"🚨 POTENTIAL RANSOMWARE DETECTED 🚨\n"
                    f"Modified Files: {len(modified)}\n"
                    f"Files: {', '.join(modified[:10])}\n"
                    f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
                
                if self.callbacks['on_alert']:
                    self.callbacks['on_alert'](alert_msg)
                
                # Save alert
                self._save_alert(alert_msg)
            
            self.previous_files = current.copy()
    
    def _log_to_csv(self, current, new_files, modified, deleted):
        """Log scan results to CSV"""
        try:
            with open(self.config.csv_file, "a", newline="", encoding='utf-8') as csvf:
                writer = csv.writer(csvf)
                
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                for filename in new_files:
                    writer.writerow([timestamp, filename, "New", current[filename]["hash"]])
                
                for filename in modified:
                    writer.writerow([timestamp, filename, "Modified", current[filename]["hash"]])
                
                for filename in deleted:
                    writer.writerow([timestamp, filename, "Deleted", "N/A"])
        except Exception as e:
            print(f"CSV logging error: {e}")
    
    def _save_alert(self, message):
        """Save alert to file"""
        try:
            with open(self.config.alert_file, "a", encoding='utf-8') as f:
                f.write(message + "\n" + "="*50 + "\n")
        except Exception as e:
            print(f"Alert save error: {e}")

# ================= MAIN APPLICATION CLASS =================
class ThreatDetectionApp:
    """Main application with improved UI"""
    def __init__(self, config, auth_manager):
        self.config = config
        self.auth_manager = auth_manager
        self.monitor = FileMonitor(config)
        self.dark_mode = False
        
        # Set up callbacks
        self.monitor.callbacks['on_scan'] = self.on_scan_callback
        self.monitor.callbacks['on_alert'] = self.on_alert_callback
        self.monitor.callbacks['on_update'] = self.on_update_callback
        
        self.setup_ui()
    
    def setup_ui(self):
        """Initialize main UI"""
        self.root = tk.Tk()
        self.root.title("Enhanced Threat Detection System")
        self.root.geometry("1000x700")
        
        # Initialize CSV if needed
        if not os.path.exists(self.config.csv_file):
            with open(self.config.csv_file, "w", newline="", encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "File Name", "Status", "Hash"])
        
        self._create_widgets()
        self.apply_theme()
    
    def _create_widgets(self):
        """Create all UI widgets"""
        # Title
        self.title_label = tk.Label(
            self.root,
            text="🛡 Enhanced Threat Detection System",
            font=("Arial", 16, "bold")
        )
        self.title_label.pack(pady=10)
        
        # Top control frame
        top_frame = tk.Frame(self.root)
        top_frame.pack(fill="x", padx=10)
        
        # Settings button
        tk.Button(
            top_frame,
            text="⚙️ Settings",
            command=self.open_settings,
            width=12
        ).pack(side="left", padx=5)
        
        # Dark mode toggle
        tk.Checkbutton(
            top_frame,
            text="🌙 Dark Mode",
            command=self.toggle_theme
        ).pack(side="left", padx=10)
        
        # Status label
        self.status_label = tk.Label(
            top_frame,
            text="🔴 Idle",
            font=("Arial", 10, "bold")
        )
        self.status_label.pack(side="right", padx=10)
        
        # Stats label
        self.stats_label = tk.Label(
            top_frame,
            text="📊 Files: 0 | Modified: 0 | New: 0"
        )
        self.stats_label.pack(side="right", padx=20)
        
        # Button frame
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        tk.Button(
            btn_frame,
            text="▶️ Start Monitoring",
            command=self.start_monitor,
            width=18,
            bg="#4CAF50",
            fg="white"
        ).grid(row=0, column=0, padx=5)
        
        tk.Button(
            btn_frame,
            text="⏸️ Stop Monitoring",
            command=self.stop_monitor,
            width=18,
            bg="#f44336",
            fg="white"
        ).grid(row=0, column=1, padx=5)
        
        tk.Button(
            btn_frame,
            text="📁 Choose Directory",
            command=self.choose_directory,
            width=18
        ).grid(row=0, column=2, padx=5)
        
        tk.Button(
            btn_frame,
            text="📊 View Reports",
            command=self.view_reports,
            width=18
        ).grid(row=0, column=3, padx=5)
        
        # Graph
        self.fig = Figure(figsize=(9, 3.5))
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, self.root)
        self.canvas.get_tk_widget().pack(padx=10)
        
        # Log box
        log_frame = tk.Frame(self.root)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        tk.Label(log_frame, text="📋 Activity Log", font=("Arial", 10, "bold")).pack(anchor="w")
        
        self.log_box = scrolledtext.ScrolledText(
            log_frame,
            height=15,
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.log_box.pack(fill="both", expand=True)
        
        # Initial graph
        self.update_graph({}, [], [], [])
    
    def start_monitor(self):
        """Start monitoring"""
        if not self.monitor.monitoring:
            self.monitor.start_monitoring()
            self.status_label.config(text="🟢 Monitoring Active")
            self.log_message("✅ Monitoring started successfully")
    
    def stop_monitor(self):
        """Stop monitoring"""
        if self.monitor.monitoring:
            self.monitor.stop_monitoring()
            self.status_label.config(text="🔴 Stopped")
            self.log_message("🛑 Monitoring stopped")
    
    def choose_directory(self):
        """Choose monitoring directory"""
        directory = filedialog.askdirectory(
            title="Select Directory to Monitor",
            initialdir=self.config.monitor_dir
        )
        if directory:
            self.config.monitor_dir = directory
            self.config.save_config()
            self.log_message(f"📁 Monitoring directory changed to: {directory}")
    
    def view_reports(self):
        """Open reports window"""
        ReportsWindow(self.root, self.config)
    
    def open_settings(self):
        """Open settings window"""
        SettingsWindow(self.root, self.config, self.on_settings_saved)
    
    def on_settings_saved(self):
        """Callback when settings are saved"""
        self.log_message("⚙️ Settings updated")
    
    def toggle_theme(self):
        """Toggle dark/light theme"""
        self.dark_mode = not self.dark_mode
        self.apply_theme()
    
    def apply_theme(self):
        """Apply current theme"""
        if self.dark_mode:
            bg, fg = "#1e1e1e", "#ffffff"
            log_bg, log_fg = "#2d2d2d", "#e0e0e0"
        else:
            bg, fg = "#f0f0f0", "#000000"
            log_bg, log_fg = "#ffffff", "#000000"
        
        self.root.configure(bg=bg)
        self.title_label.configure(bg=bg, fg=fg)
        self.log_box.configure(bg=log_bg, fg=log_fg, insertbackground=log_fg)
    
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_box.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_box.see(tk.END)
        
        # Limit log entries
        lines = int(self.log_box.index('end-1c').split('.')[0])
        if lines > self.config.max_log_entries:
            self.log_box.delete('1.0', f'{lines - self.config.max_log_entries}.0')
    
    def on_scan_callback(self, message, files):
        """Callback when scan starts"""
        self.root.after(0, self.log_message, f"🔍 {message} - {len(files)} files found")
    
    def on_alert_callback(self, message):
        """Callback when alert is raised"""
        self.root.after(0, self.log_message, message)
        self.root.after(0, messagebox.showwarning, "Security Alert", message)
    
    def on_update_callback(self, current, new_files, modified, deleted):
        """Callback when files are scanned"""
        status_msg = (
            f"Files: {len(current)} | "
            f"Modified: {len(modified)} | "
            f"New: {len(new_files)}"
        )
        if deleted:
            status_msg += f" | Deleted: {len(deleted)}"
        
        self.root.after(0, self.stats_label.config, {"text": f"📊 {status_msg}"})
        self.root.after(0, self.update_graph, current, new_files, modified, deleted)
        
        # Log details
        if new_files:
            self.root.after(0, self.log_message, f"➕ New files: {', '.join(new_files[:5])}")
        if modified:
            self.root.after(0, self.log_message, f"⚠️ Modified: {', '.join(modified[:5])}")
        if deleted:
            self.root.after(0, self.log_message, f"❌ Deleted: {', '.join(deleted[:5])}")
    
    def update_graph(self, current, new_files, modified, deleted):
        """Update visualization graph"""
        self.ax.clear()
        
        if not current:
            self.ax.set_title("No files detected in monitored directory")
            self.ax.text(0.5, 0.5, "Waiting for files...", 
                        ha='center', va='center', transform=self.ax.transAxes)
            self.canvas.draw()
            return
        
        # Limit display to top 15 most active files
        sorted_files = sorted(
            current.keys(),
            key=lambda f: self.monitor.file_activity[f],
            reverse=True
        )[:15]
        
        colors = []
        for f in sorted_files:
            if f in modified:
                colors.append('#f44336')  # Red
            elif f in new_files:
                colors.append('#2196F3')  # Blue
            else:
                colors.append('#4CAF50')  # Green
        
        activity_counts = [self.monitor.file_activity[f] for f in sorted_files]
        
        bars = self.ax.bar(range(len(sorted_files)), activity_counts, color=colors)
        
        self.ax.set_ylabel("Scan Count", fontsize=10)
        self.ax.set_title("File Activity Monitor (Top 15)", fontsize=11, fontweight='bold')
        self.ax.set_xticks(range(len(sorted_files)))
        self.ax.set_xticklabels([f[:20] for f in sorted_files], rotation=45, ha='right', fontsize=8)
        
        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#4CAF50', label='Safe'),
            Patch(facecolor='#2196F3', label='New'),
            Patch(facecolor='#f44336', label='Modified')
        ]
        self.ax.legend(handles=legend_elements, loc='upper right', fontsize=8)
        
        self.fig.tight_layout()
        self.canvas.draw()
    
    def run(self):
        """Start application"""
        self.root.mainloop()

# ================= SETTINGS WINDOW =================
class SettingsWindow:
    """Settings configuration window"""
    def __init__(self, parent, config, callback):
        self.config = config
        self.callback = callback
        
        self.window = tk.Toplevel(parent)
        self.window.title("Settings")
        self.window.geometry("400x350")
        self.window.transient(parent)
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create settings widgets"""
        # Check interval
        tk.Label(self.window, text="Scan Interval (seconds):").pack(pady=5)
        self.interval_var = tk.IntVar(value=self.config.check_interval)
        tk.Spinbox(
            self.window,
            from_=1,
            to=60,
            textvariable=self.interval_var,
            width=10
        ).pack()
        
        # Threshold
        tk.Label(self.window, text="Alert Threshold (modified files):").pack(pady=5)
        self.threshold_var = tk.IntVar(value=self.config.threshold)
        tk.Spinbox(
            self.window,
            from_=1,
            to=100,
            textvariable=self.threshold_var,
            width=10
        ).pack()
        
        # Recursive scan
        self.recursive_var = tk.BooleanVar(value=self.config.recursive_scan)
        tk.Checkbutton(
            self.window,
            text="Enable Recursive Scanning",
            variable=self.recursive_var
        ).pack(pady=10)
        
        # Excluded extensions
        tk.Label(self.window, text="Excluded Extensions (comma-separated):").pack(pady=5)
        self.extensions_var = tk.StringVar(value=", ".join(self.config.excluded_extensions))
        tk.Entry(
            self.window,
            textvariable=self.extensions_var,
            width=40
        ).pack()
        
        # Save button
        tk.Button(
            self.window,
            text="Save Settings",
            command=self.save_settings,
            bg="#4CAF50",
            fg="white",
            width=20
        ).pack(pady=20)
    
    def save_settings(self):
        """Save configuration"""
        self.config.check_interval = self.interval_var.get()
        self.config.threshold = self.threshold_var.get()
        self.config.recursive_scan = self.recursive_var.get()
        
        # Parse extensions
        extensions = [ext.strip() for ext in self.extensions_var.get().split(',')]
        self.config.excluded_extensions = [ext if ext.startswith('.') else f'.{ext}' 
                                           for ext in extensions if ext]
        
        self.config.save_config()
        self.callback()
        self.window.destroy()

# ================= REPORTS WINDOW =================
class ReportsWindow:
    """View scan history and alerts"""
    def __init__(self, parent, config):
        self.config = config
        
        self.window = tk.Toplevel(parent)
        self.window.title("Reports & History")
        self.window.geometry("700x500")
        self.window.transient(parent)
        
        self._create_widgets()
        self.load_reports()
    
    def _create_widgets(self):
        """Create report widgets"""
        # Tabs
        tab_frame = tk.Frame(self.window)
        tab_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Button(
            tab_frame,
            text="Scan History",
            command=self.show_scan_history,
            width=15
        ).pack(side="left", padx=5)
        
        tk.Button(
            tab_frame,
            text="Security Alerts",
            command=self.show_alerts,
            width=15
        ).pack(side="left", padx=5)
        
        tk.Button(
            tab_frame,
            text="Export CSV",
            command=self.export_data,
            width=15
        ).pack(side="left", padx=5)
        
        # Text area
        self.report_box = scrolledtext.ScrolledText(
            self.window,
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.report_box.pack(fill="both", expand=True, padx=10, pady=5)
    
    def load_reports(self):
        """Load default report"""
        self.show_scan_history()
    
    def show_scan_history(self):
        """Display scan history"""
        self.report_box.delete('1.0', tk.END)
        self.report_box.insert(tk.END, "📊 SCAN HISTORY\n" + "="*60 + "\n\n")
        
        try:
            with open(self.config.csv_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                
                rows = list(reader)
                for row in rows[-100:]:  # Last 100 entries
                    if len(row) >= 3:
                        self.report_box.insert(tk.END, 
                            f"[{row[0]}] {row[1]} - Status: {row[2]}\n")
        except FileNotFoundError:
            self.report_box.insert(tk.END, "No scan history available.\n")
        except Exception as e:
            self.report_box.insert(tk.END, f"Error loading history: {e}\n")
    
    def show_alerts(self):
        """Display security alerts"""
        self.report_box.delete('1.0', tk.END)
        self.report_box.insert(tk.END, "🚨 SECURITY ALERTS\n" + "="*60 + "\n\n")
        
        try:
            with open(self.config.alert_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.report_box.insert(tk.END, content if content else "No alerts recorded.\n")
        except FileNotFoundError:
            self.report_box.insert(tk.END, "No alerts file found.\n")
        except Exception as e:
            self.report_box.insert(tk.END, f"Error loading alerts: {e}\n")
    
    def export_data(self):
        """Export scan data"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if filename:
                import shutil
                shutil.copy(self.config.csv_file, filename)
                messagebox.showinfo("Success", f"Data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

# ================= LOGIN WINDOW =================
class LoginWindow:
    """Secure login interface"""
    def __init__(self, auth_manager, on_success):
        self.auth_manager = auth_manager
        self.on_success = on_success
        
        self.window = tk.Tk()
        self.window.title("Secure Login")
        self.window.geometry("350x250")
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create login widgets"""
        tk.Label(
            self.window,
            text="🔐 Secure Login",
            font=("Arial", 14, "bold")
        ).pack(pady=20)
        
        # Username
        tk.Label(self.window, text="Username:").pack()
        self.user_entry = tk.Entry(self.window, width=30)
        self.user_entry.pack(pady=5)
        
        # Password
        tk.Label(self.window, text="Password:").pack()
        self.pass_entry = tk.Entry(self.window, show="●", width=30)
        self.pass_entry.pack(pady=5)
        
        # Login button
        tk.Button(
            self.window,
            text="Login",
            command=self.login,
            bg="#4CAF50",
            fg="white",
            width=15
        ).pack(pady=20)
        
        # Bind Enter key
        self.window.bind('<Return>', lambda e: self.login())
        
        # Focus username
        self.user_entry.focus()
    
    def login(self):
        """Attempt login"""
        username = self.user_entry.get()
        password = self.pass_entry.get()
        
        if self.auth_manager.authenticate(username, password):
            self.window.destroy()
            self.on_success()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")
            self.pass_entry.delete(0, tk.END)
    
    def run(self):
        """Start login window"""
        self.window.mainloop()

# ================= MAIN ENTRY POINT =================
def main():
    """Application entry point"""
    config = Config()
    auth_manager = AuthManager()
    
    def start_app():
        app = ThreatDetectionApp(config, auth_manager)
        app.run()
    
    login = LoginWindow(auth_manager, start_app)
    login.run()

if __name__ == "__main__":
    main()