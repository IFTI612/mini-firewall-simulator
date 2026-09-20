"""
rules_tab.py
Manage the firewall rule set: add, edit, delete, enable/disable.
"""

import tkinter as tk
from tkinter import ttk, messagebox

import config
from models.rule import Rule
from ui import theme

COLUMNS = ["ID", "Priority", "Src IP", "Src Port", "Dst IP", "Dst Port",
           "Protocol", "Action", "Enabled", "Description"]
WIDTHS = [45, 65, 120, 75, 120, 75, 75, 70, 65, 240]


class RulesTab(ttk.Frame):
    def __init__(self, parent, controller, on_change=None):
        super().__init__(parent, padding=12)
        self.controller = controller
        self.on_change = on_change or (lambda: None)
        self.selected_id = None

        self.vars = {
            "priority": tk.StringVar(value="100"),
            "src_ip": tk.StringVar(value="*"),
            "src_port": tk.StringVar(value="*"),
            "dst_ip": tk.StringVar(value="*"),
            "dst_port": tk.StringVar(value="*"),
            "protocol": tk.StringVar(value="*"),
            "action": tk.StringVar(value="BLOCK"),
            "description": tk.StringVar(value=""),
            "enabled": tk.IntVar(value=1),
        }

        self._build_form()
        self._build_table()
        self.refresh()

    # ------------------------------------------------------------------ form
    def _build_form(self):
        box = ttk.LabelFrame(self, text="  Rule editor  ", padding=12)
        box.pack(fill="x")

        fields = [
            ("Priority", "priority", 8),
            ("Source IP", "src_ip", 16),
            ("Src Port", "src_port", 9),
            ("Dest IP", "dst_ip", 16),
            ("Dst Port", "dst_port", 9),
        ]
        for col, (label, key, width) in enumerate(fields):
            ttk.Label(box, text=label).grid(row=0, column=col, sticky="w", padx=4)
            ttk.Entry(box, textvariable=self.vars[key], width=width).grid(
                row=1, column=col, padx=4, sticky="w")

        ttk.Label(box, text="Protocol").grid(row=0, column=5, sticky="w", padx=4)
        ttk.Combobox(box, textvariable=self.vars["protocol"], width=7,
                     state="readonly",
                     values=["*"] + config.PROTOCOLS).grid(row=1, column=5, padx=4)

        ttk.Label(box, text="Action").grid(row=0, column=6, sticky="w", padx=4)
        ttk.Combobox(box, textvariable=self.vars["action"], width=8,
                     state="readonly",
                     values=config.ACTIONS).grid(row=1, column=6, padx=4)

        ttk.Label(box, text="Description").grid(row=0, column=7, sticky="w", padx=4)
        ttk.Entry(box, textvariable=self.vars["description"], width=30).grid(
            row=1, column=7, padx=4, sticky="we")
        box.columnconfigure(7, weight=1)

        ttk.Checkbutton(box, text="Enabled",
                        variable=self.vars["enabled"]).grid(row=1, column=8, padx=8)

        btns = ttk.Frame(box)
        btns.grid(row=2, column=0, columnspan=9, sticky="w", pady=(12, 0))
        ttk.Button(btns, text="Add rule", style="Accent.TButton",
                   command=self.add_rule).pack(side="left", padx=3)
        ttk.Button(btns, text="Update selected",
                   command=self.update_rule).pack(side="left", padx=3)
        ttk.Button(btns, text="Enable / Disable",
                   command=self.toggle_rule).pack(side="left", padx=3)
        ttk.Button(btns, text="Delete", style="Danger.TButton",
                   command=self.delete_rule).pack(side="left", padx=3)
        ttk.Button(btns, text="Clear form",
                   command=self.clear_form).pack(side="left", padx=3)

        ttk.Label(box,
                  text="Wildcards:  *  = any    192.168.1.*  = subnet    "
                       "10.0.0.0/8 = CIDR    20-25 = port range    "
                       "Lower priority number is checked first.",
                  foreground=theme.MUTED).grid(row=3, column=0, columnspan=9,
                                               sticky="w", pady=(8, 0))

    # ------------------------------------------------------------------ table
    def _build_table(self):
        head = ttk.Frame(self)
        head.pack(fill="x", pady=(14, 6))
        ttk.Label(head, text="Rule set (evaluated top to bottom)",
                  style="Title.TLabel").pack(side="left")
        self.policy_label = ttk.Label(head, text="", foreground=theme.RED,
                                      font=theme.FONT_BOLD)
        self.policy_label.pack(side="right")

        self.tree = theme.make_tree(self, COLUMNS, WIDTHS, height=14)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    # ------------------------------------------------------------------ actions
    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for rule in self.controller.rule_engine.rules():
            tag = "disabled" if not rule.enabled else (
                "allow" if rule.action == "ALLOW" else "block")
            self.tree.insert("", "end", iid=str(rule.id),
                             values=rule.as_row(), tags=(tag,))
        policy = self.controller.db.get_setting("default_policy", "DENY")
        self.policy_label.config(
            text=f"Default policy if no rule matches:  {policy}",
            foreground=theme.RED if policy == "DENY" else theme.GREEN)

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        self.selected_id = int(sel[0])
        values = self.tree.item(sel[0], "values")
        self.vars["priority"].set(values[1])
        self.vars["src_ip"].set(values[2])
        self.vars["src_port"].set(values[3])
        self.vars["dst_ip"].set(values[4])
        self.vars["dst_port"].set(values[5])
        self.vars["protocol"].set(values[6])
        self.vars["action"].set(values[7])
        self.vars["enabled"].set(1 if values[8] == "Yes" else 0)
        self.vars["description"].set(values[9])

    def _collect(self) -> Rule:
        try:
            priority = int(self.vars["priority"].get())
        except ValueError:
            raise ValueError("Priority must be a whole number.")
        return Rule(
            id=self.selected_id or 0,
            priority=priority,
            src_ip=self.vars["src_ip"].get().strip() or "*",
            src_port=self.vars["src_port"].get().strip() or "*",
            dst_ip=self.vars["dst_ip"].get().strip() or "*",
            dst_port=self.vars["dst_port"].get().strip() or "*",
            protocol=self.vars["protocol"].get().strip() or "*",
            action=self.vars["action"].get(),
            enabled=self.vars["enabled"].get(),
            description=self.vars["description"].get().strip(),
        )

    def add_rule(self):
        try:
            rule = self._collect()
            rule.id = 0
            self.controller.db.add_rule(rule)
        except ValueError as exc:
            messagebox.showerror("Invalid rule", str(exc))
            return
        self._after_change()

    def update_rule(self):
        if not self.selected_id:
            messagebox.showinfo("No selection", "Select a rule in the table first.")
            return
        try:
            self.controller.db.update_rule(self._collect())
        except ValueError as exc:
            messagebox.showerror("Invalid rule", str(exc))
            return
        self._after_change()

    def toggle_rule(self):
        if not self.selected_id:
            messagebox.showinfo("No selection", "Select a rule in the table first.")
            return
        self.controller.db.toggle_rule(self.selected_id)
        self._after_change()

    def delete_rule(self):
        if not self.selected_id:
            messagebox.showinfo("No selection", "Select a rule in the table first.")
            return
        if messagebox.askyesno("Delete rule",
                               f"Delete rule #{self.selected_id}?"):
            self.controller.db.delete_rule(self.selected_id)
            self.selected_id = None
            self._after_change()

    def clear_form(self):
        self.selected_id = None
        self.vars["priority"].set("100")
        for key in ("src_ip", "src_port", "dst_ip", "dst_port", "protocol"):
            self.vars[key].set("*")
        self.vars["action"].set("BLOCK")
        self.vars["description"].set("")
        self.vars["enabled"].set(1)
        self.tree.selection_remove(self.tree.selection())

    def _after_change(self):
        self.controller.reload_all()
        self.refresh()
        self.on_change()
