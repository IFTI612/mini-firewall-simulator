"""
settings_tab.py
Edit the default policy, detection thresholds and simulation speed.
All values are stored in the `settings` table.
"""

import tkinter as tk
from tkinter import ttk, messagebox

import config
from ui import theme

NUMERIC_FIELDS = [
    ("portscan_threshold", "Port scan: unique ports"),
    ("portscan_window", "Port scan: window (s)"),
    ("bruteforce_threshold", "Brute force: failed logins"),
    ("bruteforce_window", "Brute force: window (s)"),
    ("flood_threshold", "Traffic flood: packets"),
    ("flood_window", "Traffic flood: window (s)"),
    ("conntrack_tcp_timeout", "Conntrack: TCP timeout (s)"),
    ("conntrack_udp_timeout", "Conntrack: UDP timeout (s)"),
    ("alert_cooldown", "Alert cooldown per IP (s)"),
    ("sim_speed", "Normal traffic (packets/second)"),
]


class SettingsTab(ttk.Frame):
    def __init__(self, parent, controller, on_change=None):
        super().__init__(parent, padding=12)
        self.controller = controller
        self.on_change = on_change or (lambda: None)

        self.policy = tk.StringVar()
        self.auto_block = tk.IntVar()
        self.stateful = tk.IntVar()
        self.fields = {key: tk.StringVar() for key, _ in NUMERIC_FIELDS}

        self._build()
        self.load()

    # ------------------------------------------------------------------
    def _build(self):
        policy_box = ttk.LabelFrame(self, text="  Firewall policy  ", padding=12)
        policy_box.pack(fill="x")

        ttk.Label(policy_box,
                  text="Action when no rule matches:").grid(row=0, column=0,
                                                            sticky="w", padx=4)
        ttk.Combobox(policy_box, textvariable=self.policy, width=10,
                     state="readonly",
                     values=config.POLICIES).grid(row=0, column=1, padx=6)
        ttk.Label(policy_box,
                  text="DENY is the secure default and is what a real firewall uses.",
                  foreground=theme.MUTED).grid(row=0, column=2, sticky="w", padx=10)

        ttk.Checkbutton(policy_box,
                        text="Enable Stateful Inspection (TCP Connection Tracking / Conntrack)",
                        variable=self.stateful).grid(row=1, column=0, columnspan=3,
                                                       sticky="w", pady=(8, 0))

        ttk.Checkbutton(policy_box,
                        text="Automatically blacklist an IP when an attack is detected",
                        variable=self.auto_block).grid(row=2, column=0, columnspan=3,
                                                       sticky="w", pady=(6, 0))

        det_box = ttk.LabelFrame(self, text="  Detection thresholds  ", padding=12)
        det_box.pack(fill="x", pady=(14, 0))
        for i, (key, label) in enumerate(NUMERIC_FIELDS):
            row, col = divmod(i, 2)
            cell = ttk.Frame(det_box)
            cell.grid(row=row, column=col, sticky="w", padx=10, pady=5)
            ttk.Label(cell, text=label, width=32).pack(side="left")
            ttk.Entry(cell, textvariable=self.fields[key], width=10).pack(side="left")

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=(16, 0))
        ttk.Button(btns, text="Save settings", style="Accent.TButton",
                   command=self.save).pack(side="left", padx=3)
        ttk.Button(btns, text="Restore defaults",
                   command=self.restore_defaults).pack(side="left", padx=3)

        maint = ttk.LabelFrame(self, text="  Maintenance  ", padding=12)
        maint.pack(fill="x", pady=(18, 0))
        ttk.Button(maint, text="Clear traffic logs", style="Danger.TButton",
                   command=self.clear_traffic).pack(side="left", padx=3)
        ttk.Button(maint, text="Clear security alerts", style="Danger.TButton",
                   command=self.clear_alerts).pack(side="left", padx=3)
        ttk.Button(maint, text="Clear everything", style="Danger.TButton",
                   command=self.clear_all).pack(side="left", padx=3)
        ttk.Label(maint, text=f"Database: {config.db_summary()}",
                  foreground=theme.MUTED).pack(side="left", padx=18)

        about = ttk.Label(
            self,
            text=(f"{config.APP_NAME} v{config.APP_VERSION}  —  "
                  "educational project. All traffic and all attacks are "
                  "simulated inside this program. No real network interface is "
                  "used and no external system is scanned or contacted."),
            foreground=theme.MUTED, wraplength=900, justify="left")
        about.pack(anchor="w", pady=(20, 0))

    # ------------------------------------------------------------------
    def load(self):
        db = self.controller.db
        self.policy.set(db.get_setting("default_policy", "DENY"))
        self.auto_block.set(1 if db.get_bool_setting("auto_block") else 0)
        self.stateful.set(1 if db.get_bool_setting("stateful_inspection") else 0)
        for key, _ in NUMERIC_FIELDS:
            self.fields[key].set(db.get_setting(key))

    def save(self):
        values = {}
        for key, label in NUMERIC_FIELDS:
            raw = self.fields[key].get().strip()
            if not raw.isdigit() or int(raw) <= 0:
                messagebox.showerror(
                    "Invalid value",
                    f"'{label}' must be a whole number greater than zero.")
                return
            values[key] = int(raw)

        db = self.controller.db
        db.set_setting("default_policy", self.policy.get())
        db.set_setting("auto_block", self.auto_block.get())
        db.set_setting("stateful_inspection", self.stateful.get())
        for key, value in values.items():
            db.set_setting(key, value)

        self.controller.reload_all()
        self.on_change()
        messagebox.showinfo("Saved", "Settings applied.")

    def restore_defaults(self):
        if not messagebox.askyesno("Restore defaults",
                                   "Reset all settings to their default values?"):
            return
        for key, value in config.DEFAULT_SETTINGS.items():
            self.controller.db.set_setting(key, value)
        self.load()
        self.controller.reload_all()
        self.on_change()

    # ------------------------------------------------------------------
    def clear_traffic(self):
        if messagebox.askyesno("Clear traffic logs",
                               "Delete all stored traffic logs?"):
            self.controller.db.clear_traffic_logs()
            self.controller.reset_counters()
            self.on_change()

    def clear_alerts(self):
        if messagebox.askyesno("Clear alerts", "Delete all security alerts?"):
            self.controller.db.clear_alerts()
            self.controller.reset_counters()
            self.on_change()

    def clear_all(self):
        if messagebox.askyesno("Clear everything",
                               "Delete all traffic logs and alerts?\n"
                               "Rules and IP lists are kept."):
            self.controller.clear_data()
            self.on_change()
