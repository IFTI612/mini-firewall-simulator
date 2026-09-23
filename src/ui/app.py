"""
app.py
The main window: toolbar, notebook of tabs, status bar.

It also owns the event pump — a repeating `after()` callback that drains
the controller's queue on the main thread and updates the widgets. This is
how we get live updates without calling Tkinter from the simulator thread.
"""

import queue
import tkinter as tk
from tkinter import ttk, messagebox

import config
from controller import Controller
from ui import theme
from ui.conntrack_tab import ConntrackTab
from ui.dashboard import DashboardTab
from ui.detection_tab import DetectionTab
from ui.ip_tab import IPManagementTab
from ui.logs_tab import LogsTab
from ui.rules_tab import RulesTab
from ui.settings_tab import SettingsTab
from ui.traffic_monitor import TrafficMonitorTab


class FirewallApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{config.APP_NAME}  v{config.APP_VERSION}")
        self.geometry("1280x800")
        self.minsize(1100, 700)
        theme.apply_theme(self)

        self.controller = Controller()
        self.last_alert_text = tk.StringVar(value="No attacks detected yet.")

        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._pump()

    # ------------------------------------------------------------------ layout
    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=(14, 10))
        bar.pack(fill="x")

        tk.Label(bar, text="🛡  " + config.APP_NAME, font=("Segoe UI", 16, "bold"),
                 bg=theme.BG, fg=theme.TEXT).pack(side="left")
        tk.Label(bar, text="simulation only — no real network traffic",
                 font=("Segoe UI", 9), bg=theme.BG,
                 fg=theme.MUTED).pack(side="left", padx=12)

        self.btn_stop = ttk.Button(bar, text="■  Stop", state="disabled",
                                   command=self.stop_simulation)
        self.btn_stop.pack(side="right", padx=4)
        self.btn_start = ttk.Button(bar, text="▶  Start simulation",
                                    style="Success.TButton",
                                    command=self.start_simulation)
        self.btn_start.pack(side="right", padx=4)

        self.sim_state = tk.Label(bar, text="● Stopped", font=theme.FONT_BOLD,
                                  bg=theme.BG, fg=theme.MUTED)
        self.sim_state.pack(side="right", padx=14)

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(0, 6))

        refresh = self.refresh_all

        self.tab_dashboard = DashboardTab(self.notebook, self.controller)
        self.tab_traffic = TrafficMonitorTab(self.notebook, self.controller)
        self.tab_conntrack = ConntrackTab(self.notebook, self.controller)
        self.tab_rules = RulesTab(self.notebook, self.controller, on_change=refresh)
        self.tab_detection = DetectionTab(self.notebook, self.controller,
                                          on_change=refresh)
        self.tab_ip = IPManagementTab(self.notebook, self.controller, on_change=refresh)
        self.tab_logs = LogsTab(self.notebook, self.controller)
        self.tab_settings = SettingsTab(self.notebook, self.controller,
                                        on_change=refresh)

        self.notebook.add(self.tab_dashboard, text="Dashboard")
        self.notebook.add(self.tab_traffic, text="Traffic Monitor")
        self.notebook.add(self.tab_conntrack, text="Connection Tracking")
        self.notebook.add(self.tab_rules, text="Firewall Rules")
        self.notebook.add(self.tab_detection, text="Attack Detection")
        self.notebook.add(self.tab_ip, text="IP Management")
        self.notebook.add(self.tab_logs, text="Security Logs")
        self.notebook.add(self.tab_settings, text="Settings")

    def _build_statusbar(self):
        bar = ttk.Frame(self, padding=(14, 6))
        bar.pack(fill="x")
        self.status = ttk.Label(bar, text="Ready.", foreground=theme.MUTED)
        self.status.pack(side="left")
        ttk.Label(bar, textvariable=self.last_alert_text,
                  foreground=theme.RED).pack(side="right")

    # ------------------------------------------------------------------ control
    def start_simulation(self):
        self.controller.start()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.sim_state.config(text="● Running", fg=theme.GREEN)
        self.status.config(text="Simulation running — generating local traffic.")

    def stop_simulation(self):
        self.controller.stop()
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.sim_state.config(text="● Stopped", fg=theme.MUTED)
        self.status.config(text="Simulation stopped.")

    def refresh_all(self):
        """Re-read everything from the database after a user edit."""
        self.tab_rules.refresh()
        self.tab_detection.refresh()
        self.tab_ip.refresh()
        self.tab_logs.refresh()
        self.tab_settings.load()

    # ------------------------------------------------------------------ pump
    def _pump(self):
        """Drain the controller's event queue on the main (GUI) thread."""
        processed = 0
        try:
            while processed < 400:              # cap work per cycle
                kind, payload = self.controller.events.get_nowait()
                processed += 1
                if kind == "packet":
                    self.tab_traffic.add_packet(payload)
                elif kind == "alert":
                    self._on_alert(payload)
        except queue.Empty:
            pass

        self.after(config.UI_REFRESH_MS, self._pump)

    def _on_alert(self, alert):
        self.tab_detection.add_alert(alert)
        blocked = " — source IP auto-blocked" if alert.auto_blocked else ""
        self.last_alert_text.set(
            f"⚠ {alert.attack_type} from {alert.source_ip} "
            f"at {alert.time_text}{blocked}")
        if alert.auto_blocked:
            self.tab_ip.refresh()

    # ------------------------------------------------------------------ exit
    def on_close(self):
        if messagebox.askokcancel("Quit", "Close the firewall simulator?"):
            self.controller.shutdown()
            self.destroy()
