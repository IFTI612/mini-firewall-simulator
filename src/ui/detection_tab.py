"""
detection_tab.py
Shows detection rules, lets you launch simulated attacks, and lists alerts.
"""

import tkinter as tk
from tkinter import ttk, messagebox

import config
from ui import theme

COLUMNS = ["Time", "Attack type", "Source IP", "Severity", "Auto-blocked", "Details"]
WIDTHS = [75, 120, 130, 75, 100, 330]


class DetectionTab(ttk.Frame):
    def __init__(self, parent, controller, on_change=None):
        super().__init__(parent, padding=12)
        self.controller = controller
        self.on_change = on_change or (lambda: None)
        self.attacker_ip = tk.StringVar(value="203.0.113.7")
        self.auto_block = tk.IntVar(
            value=1 if controller.db.get_bool_setting("auto_block") else 0)

        self._build_top()
        self._build_table()
        self.refresh()

    # ------------------------------------------------------------------
    def _build_top(self):
        top = ttk.Frame(self)
        top.pack(fill="x")
        top.columnconfigure(0, weight=1)
        top.columnconfigure(1, weight=1)

        # --- detection rules explanation ---
        rules_box = ttk.LabelFrame(top, text="  Detection rules  ", padding=12)
        rules_box.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.rules_text = tk.Label(rules_box, justify="left", anchor="w",
                                   bg=theme.BG, font=("Consolas", 9))
        self.rules_text.pack(fill="both", expand=True)

        # --- attack launcher ---
        sim_box = ttk.LabelFrame(top, text="  Simulate an attack (local only)  ",
                                 padding=12)
        sim_box.grid(row=0, column=1, sticky="nsew")

        row = ttk.Frame(sim_box)
        row.pack(fill="x", pady=(0, 10))
        ttk.Label(row, text="Attacker IP:").pack(side="left")
        ttk.Entry(row, textvariable=self.attacker_ip, width=18).pack(side="left", padx=6)
        ttk.Button(row, text="Random",
                   command=lambda: self.attacker_ip.set("")).pack(side="left")

        btns = ttk.Frame(sim_box)
        btns.pack(fill="x")
        ttk.Button(btns, text="Launch port scan", style="Accent.TButton",
                   command=self.launch_scan).pack(side="left", padx=3)
        ttk.Button(btns, text="Launch brute force", style="Accent.TButton",
                   command=self.launch_brute).pack(side="left", padx=3)
        ttk.Button(btns, text="Launch traffic flood", style="Accent.TButton",
                   command=self.launch_flood).pack(side="left", padx=3)

        opts = ttk.Frame(sim_box)
        opts.pack(fill="x", pady=(12, 0))
        ttk.Checkbutton(opts, text="Automatic IP blocking when an attack is detected",
                        variable=self.auto_block,
                        command=self.save_auto_block).pack(side="left")

        ttk.Label(sim_box,
                  text="Attacks are generated inside this program only. "
                       "No real host is scanned or contacted.",
                  foreground=theme.MUTED, wraplength=380,
                  justify="left").pack(anchor="w", pady=(10, 0))

    def _build_table(self):
        head = ttk.Frame(self)
        head.pack(fill="x", pady=(14, 6))
        ttk.Label(head, text="Security alerts", style="Title.TLabel").pack(side="left")
        ttk.Button(head, text="Refresh", command=self.refresh).pack(side="right", padx=3)
        ttk.Button(head, text="Blacklist selected IP",
                   command=self.blacklist_selected).pack(side="right", padx=3)

        self.tree = theme.make_tree(self, COLUMNS, WIDTHS, height=14)

    # ------------------------------------------------------------------
    def refresh(self):
        db = self.controller.db
        self.rules_text.config(text=(
            f"PORT_SCAN\n"
            f"  >= {db.get_int_setting('portscan_threshold', 10)} unique destination "
            f"ports from one IP\n"
            f"     within {db.get_int_setting('portscan_window', 10)} seconds\n\n"
            f"BRUTE_FORCE\n"
            f"  >= {db.get_int_setting('bruteforce_threshold', 5)} failed login "
            f"attempts from one IP\n"
            f"     within {db.get_int_setting('bruteforce_window', 60)} seconds\n\n"
            f"TRAFFIC_FLOOD\n"
            f"  >= {db.get_int_setting('flood_threshold', 100)} packets from one IP\n"
            f"     within {db.get_int_setting('flood_window', 5)} seconds\n\n"
            f"Alert cooldown per IP: "
            f"{db.get_int_setting('alert_cooldown', 15)} s"
        ))

        self.tree.delete(*self.tree.get_children())
        for row in db.get_alerts(limit=300):
            self.tree.insert("", "end", values=(
                row["ts_text"].split(" ")[-1], row["attack_type"], row["source_ip"],
                row["severity"], "Yes" if row["auto_blocked"] else "No",
                row["details"] or ""), tags=("attack",))

    def add_alert(self, alert):
        """Called live by the main window when a new alert arrives."""
        self.tree.insert("", 0, values=alert.as_row(), tags=("attack",))

    # ------------------------------------------------------------------
    def _ip_or_none(self):
        ip = self.attacker_ip.get().strip()
        return ip or None

    def _require_running(self) -> bool:
        if not self.controller.simulator.is_running:
            messagebox.showinfo(
                "Simulation stopped",
                "Start the simulation first (the Start button in the toolbar).")
            return False
        return True

    def launch_scan(self):
        if self._require_running():
            self.controller.simulator.launch_port_scan(self._ip_or_none())

    def launch_brute(self):
        if self._require_running():
            self.controller.simulator.launch_brute_force(self._ip_or_none())

    def launch_flood(self):
        if self._require_running():
            self.controller.simulator.launch_flood(self._ip_or_none())

    # ------------------------------------------------------------------
    def save_auto_block(self):
        self.controller.db.set_setting("auto_block", self.auto_block.get())
        self.on_change()

    def blacklist_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select an alert first.")
            return
        ip = self.tree.item(sel[0], "values")[2]
        from firewall.ip_lists import BLACKLIST
        self.controller.ip_lists.add(ip, BLACKLIST, "Blocked manually from alert")
        self.controller.reload_all()
        self.on_change()
        messagebox.showinfo("Blacklisted", f"{ip} has been added to the blacklist.")
