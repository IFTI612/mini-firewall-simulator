"""
logs_tab.py
Query stored traffic logs and export them to CSV.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import config
from ui import theme

COLUMNS = ["ID", "Timestamp", "Source IP", "SPort", "Destination IP", "DPort",
           "Proto", "Flags", "State", "Type", "Payload", "Action", "Reason"]
WIDTHS = [40, 135, 110, 50, 115, 50, 48, 60, 75, 55, 130, 60, 200]


class LogsTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=12)
        self.controller = controller

        self.f_action = tk.StringVar(value="ALL")
        self.f_proto = tk.StringVar(value="ALL")
        self.f_kind = tk.StringVar(value="ALL")
        self.f_ip = tk.StringVar()
        self.f_limit = tk.StringVar(value="500")

        self._build_filters()
        self.tree = theme.make_tree(self, COLUMNS, WIDTHS, height=20)
        self.status = ttk.Label(self, text="", foreground=theme.MUTED)
        self.status.pack(anchor="w", pady=(6, 0))
        self.refresh()

    # ------------------------------------------------------------------
    def _build_filters(self):
        box = ttk.LabelFrame(self, text="  Filters  ", padding=12)
        box.pack(fill="x", pady=(0, 10))

        ttk.Label(box, text="Action").grid(row=0, column=0, padx=4, sticky="w")
        ttk.Combobox(box, textvariable=self.f_action, width=9, state="readonly",
                     values=["ALL", "ALLOW", "BLOCK"]).grid(row=1, column=0, padx=4)

        ttk.Label(box, text="Protocol").grid(row=0, column=1, padx=4, sticky="w")
        ttk.Combobox(box, textvariable=self.f_proto, width=9, state="readonly",
                     values=["ALL"] + config.PROTOCOLS).grid(row=1, column=1, padx=4)

        ttk.Label(box, text="Packet type").grid(row=0, column=2, padx=4, sticky="w")
        ttk.Combobox(box, textvariable=self.f_kind, width=10, state="readonly",
                     values=["ALL", config.KIND_NORMAL, config.KIND_AUTH,
                             config.KIND_SCAN, config.KIND_FLOOD]).grid(
            row=1, column=2, padx=4)

        ttk.Label(box, text="Source IP contains").grid(row=0, column=3, padx=4,
                                                       sticky="w")
        ttk.Entry(box, textvariable=self.f_ip, width=18).grid(row=1, column=3, padx=4)

        ttk.Label(box, text="Max rows").grid(row=0, column=4, padx=4, sticky="w")
        ttk.Entry(box, textvariable=self.f_limit, width=8).grid(row=1, column=4, padx=4)

        ttk.Button(box, text="Apply filters", style="Accent.TButton",
                   command=self.refresh).grid(row=1, column=5, padx=8)
        ttk.Button(box, text="Reset",
                   command=self.reset_filters).grid(row=1, column=6, padx=2)

        ttk.Button(box, text="Export traffic to CSV", style="Success.TButton",
                   command=self.export_traffic).grid(row=1, column=7, padx=(24, 2))
        ttk.Button(box, text="Export alerts to CSV", style="Success.TButton",
                   command=self.export_alerts).grid(row=1, column=8, padx=2)
        box.columnconfigure(9, weight=1)

    # ------------------------------------------------------------------
    def _filters(self) -> dict:
        try:
            limit = int(self.f_limit.get())
        except ValueError:
            limit = 500
        return {
            "limit": limit,
            "action": self.f_action.get(),
            "protocol": self.f_proto.get(),
            "kind": self.f_kind.get(),
            "src_ip": self.f_ip.get().strip() or None,
        }

    def reset_filters(self):
        self.f_action.set("ALL")
        self.f_proto.set("ALL")
        self.f_kind.set("ALL")
        self.f_ip.set("")
        self.f_limit.set("500")
        self.refresh()

    def refresh(self):
        rows = self.controller.db.get_logs(**self._filters())
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            tag = "allow" if r["action"] == "ALLOW" else "block"
            payload_txt = (r.get("payload") or "").replace("\r", " ").replace("\n", " ").strip()
            preview = payload_txt[:35] + "..." if len(payload_txt) > 35 else (payload_txt or "-")
            self.tree.insert("", "end", values=(
                r["id"], r["ts_text"], r["src_ip"], r["src_port"], r["dst_ip"],
                r["dst_port"], r["protocol"], r.get("flags") or "-",
                r.get("conn_state") or "-", r["kind"], preview, r["action"],
                r["reason"] or ""), tags=(tag,))
        self.status.config(text=f"{len(rows)} row(s) shown.")

    # ------------------------------------------------------------------
    def _ask_path(self, prefix):
        return filedialog.asksaveasfilename(
            title="Export to CSV",
            defaultextension=".csv",
            initialdir=config.DATA_DIR,
            initialfile=self.controller.db.default_export_name(prefix),
            filetypes=[("CSV file", "*.csv"), ("All files", "*.*")],
        )

    def export_traffic(self):
        path = self._ask_path("traffic_logs")
        if not path:
            return
        try:
            count = self.controller.db.export_logs_csv(path, **self._filters())
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export complete",
                            f"{count} row(s) written to\n{os.path.abspath(path)}")

    def export_alerts(self):
        path = self._ask_path("security_alerts")
        if not path:
            return
        try:
            count = self.controller.db.export_alerts_csv(path)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export complete",
                            f"{count} alert(s) written to\n{os.path.abspath(path)}")
