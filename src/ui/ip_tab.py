"""
ip_tab.py
Manage the IP whitelist and blacklist.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from firewall.ip_lists import BLACKLIST, WHITELIST
from ui import theme

COLUMNS = ["IP address", "Reason", "Added at"]
WIDTHS = [140, 250, 150]


class IPManagementTab(ttk.Frame):
    def __init__(self, parent, controller, on_change=None):
        super().__init__(parent, padding=12)
        self.controller = controller
        self.on_change = on_change or (lambda: None)

        self.ip_var = tk.StringVar()
        self.reason_var = tk.StringVar()
        self.list_var = tk.StringVar(value=BLACKLIST)

        self._build_form()
        self._build_tables()
        self.refresh()

    # ------------------------------------------------------------------
    def _build_form(self):
        box = ttk.LabelFrame(self, text="  Add an IP address  ", padding=12)
        box.pack(fill="x")

        ttk.Label(box, text="IP address").grid(row=0, column=0, sticky="w", padx=4)
        ttk.Entry(box, textvariable=self.ip_var, width=18).grid(row=1, column=0, padx=4)

        ttk.Label(box, text="Reason").grid(row=0, column=1, sticky="w", padx=4)
        ttk.Entry(box, textvariable=self.reason_var, width=40).grid(
            row=1, column=1, padx=4, sticky="we")
        box.columnconfigure(1, weight=1)

        ttk.Label(box, text="List").grid(row=0, column=2, sticky="w", padx=4)
        ttk.Combobox(box, textvariable=self.list_var, width=12, state="readonly",
                     values=[BLACKLIST, WHITELIST]).grid(row=1, column=2, padx=4)

        ttk.Button(box, text="Add", style="Accent.TButton",
                   command=self.add_ip).grid(row=1, column=3, padx=6)
        ttk.Button(box, text="Remove selected", style="Danger.TButton",
                   command=self.remove_selected).grid(row=1, column=4, padx=4)

        ttk.Label(box,
                  text="A whitelisted IP is always allowed and is never "
                       "auto-blocked. A blacklisted IP is always blocked, "
                       "before any rule is checked.",
                  foreground=theme.MUTED).grid(row=2, column=0, columnspan=5,
                                               sticky="w", pady=(8, 0))

    def _build_tables(self):
        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, pady=(14, 0))
        wrap.columnconfigure(0, weight=1)
        wrap.columnconfigure(1, weight=1)
        wrap.rowconfigure(0, weight=1)

        black_box = ttk.LabelFrame(wrap, text="  Blacklist (blocked)  ", padding=8)
        black_box.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.black_tree = theme.make_tree(black_box, COLUMNS, WIDTHS, height=16)

        white_box = ttk.LabelFrame(wrap, text="  Whitelist (always allowed)  ",
                                   padding=8)
        white_box.grid(row=0, column=1, sticky="nsew")
        self.white_tree = theme.make_tree(white_box, COLUMNS, WIDTHS, height=16)

    # ------------------------------------------------------------------
    def refresh(self):
        for tree, list_type, tag in ((self.black_tree, BLACKLIST, "block"),
                                     (self.white_tree, WHITELIST, "allow")):
            tree.delete(*tree.get_children())
            for row in self.controller.ip_lists.entries(list_type):
                tree.insert("", "end",
                            values=(row["ip"], row["reason"] or "",
                                    str(row["added_at"])[:19]),
                            tags=(tag,))

    def add_ip(self):
        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showerror("Missing IP", "Enter an IP address.")
            return
        self.controller.ip_lists.add(ip, self.list_var.get(),
                                     self.reason_var.get().strip() or "Added manually")
        self.ip_var.set("")
        self.reason_var.set("")
        self.controller.reload_all()
        self.refresh()
        self.on_change()

    def remove_selected(self):
        for tree in (self.black_tree, self.white_tree):
            sel = tree.selection()
            if sel:
                ip = tree.item(sel[0], "values")[0]
                self.controller.ip_lists.remove(ip)
                self.controller.reload_all()
                self.refresh()
                self.on_change()
                return
        messagebox.showinfo("No selection", "Select an IP address in either table.")
