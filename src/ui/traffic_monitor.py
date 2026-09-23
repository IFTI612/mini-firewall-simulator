"""
traffic_monitor.py
Live view of packets as the firewall processes them, with real-time category filtering,
IP/keyword search, and deep packet inspection.
"""

from collections import deque
import tkinter as tk
from tkinter import ttk, messagebox

import config
from ui import theme

COLUMNS = ["Time", "Source IP", "SPort", "Destination IP", "DPort",
           "Proto", "Flags", "State", "Type", "Payload", "Action", "Reason"]
WIDTHS = [70, 110, 50, 115, 50, 48, 65, 80, 60, 140, 65, 200]

CATEGORY_OPTIONS = [
    "ALL TYPES",
    "⚠️ ATTACKS ONLY",
    "SQL Injection (SQLI)",
    "Cross-Site Scripting (XSS)",
    "Path Traversal (TRAVERSAL)",
    "Stealth Scan (STEALTH)",
    "Port Scan (SCAN)",
    "Traffic Flood (FLOOD)",
    "Brute Force (AUTH)",
    "Normal Traffic (NORMAL)",
]


class TrafficMonitorTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=12)
        self.controller = controller

        # Controls & filter variables
        self.paused = tk.BooleanVar(value=False)
        self.autoscroll = tk.BooleanVar(value=True)
        self.filter_category = tk.StringVar(value="ALL TYPES")
        self.filter_action = tk.StringVar(value="ALL")
        self.filter_proto = tk.StringVar(value="ALL")
        self.search_query = tk.StringVar(value="")

        # In-memory buffer of recent packets to allow instantaneous live filtering
        self.packet_buffer = deque(maxlen=800)
        self._displayed_packets = {}  # tree_item_id -> packet

        self._build_top_controls()
        self._build_filter_bar()
        self.tree = theme.make_tree(self, COLUMNS, WIDTHS, height=20)
        self.tree.bind("<Double-1>", lambda event: self.inspect_selected())

    # ------------------------------------------------------------------ UI Layout
    def _build_top_controls(self):
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=(0, 6))

        # Title & packet counter badge
        title_box = ttk.Frame(top_bar)
        title_box.pack(side="left")
        ttk.Label(title_box, text="Live packet stream", style="Title.TLabel").pack(side="left")
        self.lbl_count = ttk.Label(title_box, text="Showing: 0 / 0 packets",
                                   foreground=theme.MUTED, font=("Segoe UI", 9))
        self.lbl_count.pack(side="left", padx=12)

        # Right-side action controls
        ttk.Button(top_bar, text="Clear view",
                   command=self.clear).pack(side="right", padx=3)
        ttk.Button(top_bar, text="Inspect packet", style="Accent.TButton",
                   command=self.inspect_selected).pack(side="right", padx=5)
        ttk.Checkbutton(top_bar, text="Auto-scroll",
                        variable=self.autoscroll).pack(side="right", padx=6)
        ttk.Checkbutton(top_bar, text="Pause",
                        variable=self.paused).pack(side="right", padx=6)

    def _build_filter_bar(self):
        fbar = ttk.LabelFrame(self, text="  Search & Category Filter  ", padding=(8, 6))
        fbar.pack(fill="x", pady=(0, 8))

        # Row 1: Search Entry + Dropdowns
        r1 = ttk.Frame(fbar)
        r1.pack(fill="x")

        # 1. Search Query Box (IP, Port, Payload, Reason)
        ttk.Label(r1, text="Search:").pack(side="left")
        search_ent = ttk.Entry(r1, textvariable=self.search_query, width=22)
        search_ent.pack(side="left", padx=(4, 2))
        search_ent.bind("<KeyRelease>", self._on_search_change)

        btn_clear_search = ttk.Button(r1, text="✕", width=2, command=self._clear_search)
        btn_clear_search.pack(side="left", padx=(0, 10))

        # 2. Category Filter Dropdown
        ttk.Label(r1, text="Category:").pack(side="left")
        cb_cat = ttk.Combobox(r1, textvariable=self.filter_category, width=24,
                              state="readonly", values=CATEGORY_OPTIONS)
        cb_cat.pack(side="left", padx=4)
        cb_cat.bind("<<ComboboxSelected>>", self._reapply_filters)

        # 3. Action Filter Dropdown (ALL / ALLOW / BLOCK)
        ttk.Label(r1, text="Action:").pack(side="left", padx=(8, 0))
        cb_act = ttk.Combobox(r1, textvariable=self.filter_action, width=8,
                              state="readonly", values=["ALL", "ALLOW", "BLOCK"])
        cb_act.pack(side="left", padx=4)
        cb_act.bind("<<ComboboxSelected>>", self._reapply_filters)

        # 4. Protocol Filter Dropdown (ALL / TCP / UDP)
        ttk.Label(r1, text="Proto:").pack(side="left", padx=(8, 0))
        cb_proto = ttk.Combobox(r1, textvariable=self.filter_proto, width=7,
                                state="readonly", values=["ALL", "TCP", "UDP"])
        cb_proto.pack(side="left", padx=4)
        cb_proto.bind("<<ComboboxSelected>>", self._reapply_filters)

        # Quick Preset Buttons
        ttk.Button(r1, text="Reset filters",
                   command=self.reset_filters).pack(side="right", padx=3)
        btn_attacks = ttk.Button(r1, text="⚠️ Show Attacks Only", style="Danger.TButton",
                                 command=self.show_attacks_only)
        btn_attacks.pack(side="right", padx=4)

    # ------------------------------------------------------------------ Packet Matching
    def _is_attack_packet(self, packet) -> bool:
        return (
            packet.kind in (
                config.KIND_SCAN,
                config.KIND_FLOOD,
                config.KIND_STEALTH,
                config.KIND_SQLI,
                config.KIND_XSS,
                config.KIND_TRAVERSAL,
            )
            or packet.is_failed_auth
            or getattr(packet, "dpi_match", None) is not None
            or "DPI:" in packet.reason
            or "Stealth" in packet.reason
        )

    def _packet_tag(self, packet) -> str:
        if self._is_attack_packet(packet):
            return "attack"
        elif packet.action == "ALLOW":
            return "allow"
        else:
            return "block"

    def _matches_category(self, packet, cat: str) -> bool:
        if cat == "ALL TYPES":
            return True
        if cat == "⚠️ ATTACKS ONLY":
            return self._is_attack_packet(packet)
        if cat == "SQL Injection (SQLI)":
            return packet.kind == config.KIND_SQLI or "SQL_INJECTION" in packet.reason
        if cat == "Cross-Site Scripting (XSS)":
            return packet.kind == config.KIND_XSS or "XSS" in packet.reason
        if cat == "Path Traversal (TRAVERSAL)":
            return packet.kind == config.KIND_TRAVERSAL or "PATH_TRAVERSAL" in packet.reason
        if cat == "Stealth Scan (STEALTH)":
            return packet.kind == config.KIND_STEALTH or "Stealth" in packet.reason
        if cat == "Port Scan (SCAN)":
            return packet.kind == config.KIND_SCAN
        if cat == "Traffic Flood (FLOOD)":
            return packet.kind == config.KIND_FLOOD
        if cat == "Brute Force (AUTH)":
            return packet.kind == config.KIND_AUTH
        if cat == "Normal Traffic (NORMAL)":
            return packet.kind == config.KIND_NORMAL and not self._is_attack_packet(packet)
        return True

    def _matches_search(self, packet, query: str) -> bool:
        if not query:
            return True
        haystack = (
            f"{packet.src_ip} {packet.src_port} {packet.dst_ip} {packet.dst_port} "
            f"{packet.protocol} {packet.flags} {packet.conn_state} {packet.kind} "
            f"{packet.action} {packet.reason} {packet.payload}"
        ).lower()
        return query in haystack

    def _packet_matches(self, packet) -> bool:
        # 1. Action filter
        act = self.filter_action.get()
        if act != "ALL" and packet.action != act:
            return False

        # 2. Protocol filter
        proto = self.filter_proto.get()
        if proto != "ALL" and packet.protocol != proto:
            return False

        # 3. Category filter
        if not self._matches_category(packet, self.filter_category.get()):
            return False

        # 4. Text search query
        q = self.search_query.get().strip().lower()
        if not self._matches_search(packet, q):
            return False

        return True

    # ------------------------------------------------------------------ Event Handlers
    def add_packet(self, packet):
        """Called live by app.py for every simulated packet event."""
        # Always buffer recent packets so filter changes can instantly re-populate
        self.packet_buffer.append(packet)

        if self.paused.get():
            self._update_counter_label()
            return

        if not self._packet_matches(packet):
            self._update_counter_label()
            return

        tag = self._packet_tag(packet)
        item = self.tree.insert("", "end", values=packet.as_row(), tags=(tag,))
        self._displayed_packets[item] = packet

        # Keep table within max display bounds for GUI speed
        children = self.tree.get_children()
        if len(children) > config.MAX_LIVE_ROWS:
            removed = children[0]
            self._displayed_packets.pop(removed, None)
            self.tree.delete(removed)

        if self.autoscroll.get():
            self.tree.see(item)

        self._update_counter_label()

    def _on_search_change(self, event=None):
        self._reapply_filters()

    def _clear_search(self):
        self.search_query.set("")
        self._reapply_filters()

    def show_attacks_only(self):
        """One-click preset to instantly isolate attack packets."""
        self.filter_category.set("⚠️ ATTACKS ONLY")
        self.filter_action.set("ALL")
        self.filter_proto.set("ALL")
        self._reapply_filters()

    def reset_filters(self):
        """Restore default view showing all packet types."""
        self.filter_category.set("ALL TYPES")
        self.filter_action.set("ALL")
        self.filter_proto.set("ALL")
        self.search_query.set("")
        self._reapply_filters()

    def _reapply_filters(self, event=None):
        """Re-populates the tree view with matching packets from the live buffer."""
        self.tree.delete(*self.tree.get_children())
        self._displayed_packets.clear()

        # Iterate forward so they are displayed chronologically
        matching = [pkt for pkt in self.packet_buffer if self._packet_matches(pkt)]
        # Slice to the most recent MAX_LIVE_ROWS
        display_slice = matching[-config.MAX_LIVE_ROWS:] if len(matching) > config.MAX_LIVE_ROWS else matching

        for pkt in display_slice:
            tag = self._packet_tag(pkt)
            item = self.tree.insert("", "end", values=pkt.as_row(), tags=(tag,))
            self._displayed_packets[item] = pkt

        if self.autoscroll.get() and self.tree.get_children():
            self.tree.see(self.tree.get_children()[-1])

        self._update_counter_label()

    def _update_counter_label(self):
        shown = len(self.tree.get_children())
        total = len(self.packet_buffer)
        cat = self.filter_category.get()
        hint = f" [{cat}]" if cat != "ALL TYPES" else ""
        self.lbl_count.config(text=f"Showing: {shown} / {total} packets{hint}")

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self._displayed_packets.clear()
        self.packet_buffer.clear()
        self._update_counter_label()

    # ------------------------------------------------------------------ Packet Inspector Modal
    def inspect_selected(self):
        """Opens deep packet inspection dialog for the selected row."""
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("No Selection", "Please click on a packet in the table to inspect.")
            return

        item = sel[0]
        pkt = self._displayed_packets.get(item)
        if not pkt:
            messagebox.showinfo("Expired", "Packet details are no longer held in memory.")
            return

        self._open_inspector_window(pkt)

    def _open_inspector_window(self, packet):
        top = tk.Toplevel(self)
        top.title(f"Packet Inspector — {packet.time_text}")
        top.geometry("680x560")
        top.minsize(580, 480)
        top.transient(self.winfo_toplevel())

        # Header Status Banner
        is_atk = self._is_attack_packet(packet)
        if is_atk:
            hdr_bg = "#fee2e2"
            hdr_fg = theme.RED
            status_title = f"⚠️ ATTACK VECTOR DETECTED  [{packet.kind}]"
        elif packet.action == "ALLOW":
            hdr_bg = "#dcfce7"
            hdr_fg = theme.GREEN
            status_title = f"✓ PACKET ALLOWED  [{packet.action}]"
        else:
            hdr_bg = "#f3f4f6"
            hdr_fg = theme.RED
            status_title = f"⨉ PACKET BLOCKED  [{packet.action}]"

        header_frame = tk.Frame(top, bg=hdr_bg, padx=14, pady=10)
        header_frame.pack(fill="x")
        tk.Label(header_frame, text=status_title, font=("Segoe UI", 12, "bold"),
                 bg=hdr_bg, fg=hdr_fg).pack(anchor="w")
        tk.Label(header_frame, text=f"Reason: {packet.reason}", font=("Segoe UI", 9),
                 bg=hdr_bg, fg=theme.TEXT).pack(anchor="w", pady=(2, 0))

        content = ttk.Frame(top, padding=12)
        content.pack(fill="both", expand=True)

        # Metadata Section
        meta_box = ttk.LabelFrame(content, text="  Network & Transport Headers  ", padding=10)
        meta_box.pack(fill="x", pady=(0, 10))

        fields = [
            ("Timestamp", packet.datetime_text),
            ("Source", f"{packet.src_ip} : {packet.src_port}"),
            ("Destination", f"{packet.dst_ip} : {packet.dst_port}"),
            ("Protocol", packet.protocol),
            ("TCP Flags", packet.flags or "(none)"),
            ("Conntrack State", packet.conn_state or "STATELESS"),
            ("Simulation Kind", packet.kind),
            ("Packet Size", f"{packet.size} bytes"),
        ]

        for i, (label, val) in enumerate(fields):
            r, c = divmod(i, 2)
            ttk.Label(meta_box, text=f"{label}:", font=theme.FONT_BOLD, width=16).grid(
                row=r, column=c * 2, sticky="w", padx=(6, 2), pady=3)
            ttk.Label(meta_box, text=val, foreground=theme.PRIMARY if "Source" in label or "Dest" in label else theme.TEXT).grid(
                row=r, column=c * 2 + 1, sticky="w", padx=(0, 14), pady=3)

        # DPI Signature Match Banner (if matched)
        match = getattr(packet, "dpi_match", None)
        if match:
            dpi_box = ttk.LabelFrame(content, text="  DPI Signature Engine Alert  ", padding=10)
            dpi_box.pack(fill="x", pady=(0, 10))
            ttk.Label(dpi_box, text=f"Signature: {match.name}", font=theme.FONT_BOLD,
                      foreground=theme.RED).pack(anchor="w")
            ttk.Label(dpi_box, text=f"Category: {match.attack_type}   |   Severity: {match.severity}   |   Rule ID: #{match.sig_id}",
                      foreground=theme.MUTED).pack(anchor="w", pady=(2, 2))
            ttk.Label(dpi_box, text=f"Matched Exploit Snippet:  {match.snippet}",
                      font=("Consolas", 10, "bold"), foreground=theme.RED).pack(anchor="w", pady=(4, 0))

        # Layer 7 Payload Section
        payload_box = ttk.LabelFrame(content, text="  Layer 7 Application Payload (Raw)  ", padding=10)
        payload_box.pack(fill="both", expand=True)

        txt_payload = tk.Text(payload_box, font=("Consolas", 9), height=7,
                              bg=theme.CARD_BG, fg=theme.TEXT, wrap="word",
                              relief="solid", borderwidth=1)
        vsb = ttk.Scrollbar(payload_box, orient="vertical", command=txt_payload.yview)
        txt_payload.configure(yscrollcommand=vsb.set)

        payload_content = packet.payload if packet.payload else "(No Layer 7 application payload carried in this packet)"
        txt_payload.insert("1.0", payload_content)
        txt_payload.configure(state="disabled")

        txt_payload.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Bottom Button Bar
        btn_bar = ttk.Frame(content)
        btn_bar.pack(fill="x", pady=(10, 0))

        def blacklist_ip():
            self.controller.ip_lists.add(packet.src_ip, "BLACKLIST",
                                         f"Manually blacklisted via Packet Inspector ({packet.kind})")
            messagebox.showinfo("Blacklisted", f"IP address {packet.src_ip} has been added to the Blacklist.")
            top.destroy()

        ttk.Button(btn_bar, text=f"🚫 Blacklist {packet.src_ip}", style="Danger.TButton",
                   command=blacklist_ip).pack(side="left")
        ttk.Button(btn_bar, text="Close", command=top.destroy).pack(side="right")
