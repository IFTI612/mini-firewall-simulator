"""
traffic_monitor.py
Live view of packets as the firewall processes them.
"""

from tkinter import ttk
import tkinter as tk

import config
from ui import theme

COLUMNS = ["Time", "Source IP", "SPort", "Destination IP", "DPort",
           "Proto", "Type", "Action", "Reason"]
WIDTHS = [75, 120, 60, 130, 60, 55, 70, 70, 260]


class TrafficMonitorTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=12)
        self.controller = controller
        self.paused = tk.BooleanVar(value=False)
        self.filter_action = tk.StringVar(value="ALL")
        self.autoscroll = tk.BooleanVar(value=True)

        self._build_toolbar()
        self.tree = theme.make_tree(self, COLUMNS, WIDTHS, height=22)

    # ------------------------------------------------------------------
    def _build_toolbar(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 10))

        ttk.Label(bar, text="Live packet stream",
                  style="Title.TLabel").pack(side="left")

        ttk.Button(bar, text="Clear view",
                   command=self.clear).pack(side="right", padx=4)
        ttk.Checkbutton(bar, text="Auto-scroll",
                        variable=self.autoscroll).pack(side="right", padx=8)
        ttk.Checkbutton(bar, text="Pause",
                        variable=self.paused).pack(side="right", padx=8)

        ttk.Combobox(bar, textvariable=self.filter_action, width=10,
                     state="readonly",
                     values=["ALL", "ALLOW", "BLOCK"]).pack(side="right", padx=4)
        ttk.Label(bar, text="Show:").pack(side="right")

    # ------------------------------------------------------------------
    def add_packet(self, packet):
        """Called by the main window for every packet event."""
        if self.paused.get():
            return
        wanted = self.filter_action.get()
        if wanted != "ALL" and packet.action != wanted:
            return

        tag = "allow" if packet.action == "ALLOW" else "block"
        if packet.kind in (config.KIND_SCAN, config.KIND_FLOOD):
            tag = "attack"

        item = self.tree.insert("", "end", values=packet.as_row(), tags=(tag,))

        # keep the table small so the GUI stays fast
        children = self.tree.get_children()
        if len(children) > config.MAX_LIVE_ROWS:
            for old in children[:len(children) - config.MAX_LIVE_ROWS]:
                self.tree.delete(old)

        if self.autoscroll.get():
            self.tree.see(item)

    def clear(self):
        self.tree.delete(*self.tree.get_children())
