"""
conntrack_tab.py
Live visualization of the Stateful Connection Tracking (Conntrack) table.
Displays active TCP sessions and UDP flows tracked in memory.
"""

import tkinter as tk
from tkinter import ttk, messagebox

import config
from ui import theme

COLUMNS = ["Proto", "Client (Source)", "Server (Destination)", "TCP State",
           "Conntrack State", "Fwd Pkts", "Rev Pkts", "Bytes", "Idle"]
WIDTHS = [60, 160, 160, 100, 110, 80, 80, 90, 80]


class ConntrackTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=12)
        self.controller = controller
        self.auto_refresh = tk.BooleanVar(value=True)

        self._build_header()
        self.tree = theme.make_tree(self, COLUMNS, WIDTHS, height=20)
        self._setup_tags()
        self.status = ttk.Label(self, text="", foreground=theme.MUTED)
        self.status.pack(anchor="w", pady=(6, 0))

        self.refresh()
        self._schedule_refresh()

    def _build_header(self):
        head = ttk.Frame(self)
        head.pack(fill="x", pady=(0, 8))

        left = ttk.Frame(head)
        left.pack(side="left")

        ttk.Label(left, text="Active Connection Tracking Table (Conntrack)",
                  style="Title.TLabel").pack(anchor="w")
        ttk.Label(left,
                  text="RFC 793 TCP state machine & UDP flow tracker. Established sessions are fast-pathed.",
                  foreground=theme.MUTED, font=("Segoe UI", 9)).pack(anchor="w")

        right = ttk.Frame(head)
        right.pack(side="right")

        self.lbl_count = ttk.Label(right, text="Active: 0", font=theme.FONT_BOLD)
        self.lbl_count.pack(side="left", padx=8)

        ttk.Checkbutton(right, text="Auto-refresh (1s)",
                        variable=self.auto_refresh).pack(side="left", padx=6)
        ttk.Button(right, text="Refresh", command=self.refresh).pack(side="left", padx=3)
        ttk.Button(right, text="Flush connections",
                   command=self.flush_connections).pack(side="left", padx=3)

    def _setup_tags(self):
        self.tree.tag_configure("established", foreground=theme.GREEN)
        self.tree.tag_configure("new", foreground=theme.PRIMARY)
        self.tree.tag_configure("closing", foreground=theme.ORANGE)

    def refresh(self):
        entries = self.controller.get_active_connections()
        self.lbl_count.config(text=f"Active: {len(entries)}")

        self.tree.delete(*self.tree.get_children())
        for e in entries:
            tag = "new"
            if e.conntrack_state == config.CONN_ESTABLISHED:
                tag = "established" if e.tcp_state == "ESTABLISHED" else "closing"

            self.tree.insert("", "end", values=e.as_row(), tags=(tag,))

        self.status.config(text=f"{len(entries)} active connection flow(s) tracked in memory.")

    def flush_connections(self):
        self.controller.flush_connections()
        self.refresh()

    def _schedule_refresh(self):
        if self.auto_refresh.get():
            self.refresh()
        self.after(1000, self._schedule_refresh)
