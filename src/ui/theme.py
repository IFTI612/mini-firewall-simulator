"""
theme.py
Colours, ttk styles and a couple of small reusable widgets.
Kept in one place so every tab looks the same.
"""

import tkinter as tk
from tkinter import ttk

# ---------------------------------------------------------------- palette
BG = "#f4f6f8"
CARD_BG = "#ffffff"
SIDEBAR = "#1f2a37"
TEXT = "#1f2a37"
MUTED = "#6b7280"
PRIMARY = "#2563eb"
GREEN = "#16a34a"
RED = "#dc2626"
ORANGE = "#ea580c"
PURPLE = "#7c3aed"

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 15, "bold")
FONT_BIG = ("Segoe UI", 22, "bold")


def apply_theme(root):
    """Set up ttk styles for the whole application."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=BG)
    style.configure(".", font=FONT, background=BG, foreground=TEXT)
    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=CARD_BG, relief="flat")
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Card.TLabel", background=CARD_BG, foreground=TEXT)
    style.configure("Muted.TLabel", background=CARD_BG, foreground=MUTED,
                    font=("Segoe UI", 9))
    style.configure("Title.TLabel", font=FONT_TITLE)
    style.configure("TLabelframe", background=BG)
    style.configure("TLabelframe.Label", background=BG, font=FONT_BOLD)
    style.configure("TButton", padding=(10, 5))
    style.configure("Accent.TButton", background=PRIMARY, foreground="white")
    style.map("Accent.TButton", background=[("active", "#1d4ed8")])
    style.configure("Danger.TButton", background=RED, foreground="white")
    style.map("Danger.TButton", background=[("active", "#b91c1c")])
    style.configure("Success.TButton", background=GREEN, foreground="white")
    style.map("Success.TButton", background=[("active", "#15803d")])

    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", padding=(16, 9), font=FONT_BOLD)
    style.map("TNotebook.Tab",
              background=[("selected", CARD_BG)],
              foreground=[("selected", PRIMARY)])

    style.configure("Treeview", rowheight=24, fieldbackground=CARD_BG,
                    background=CARD_BG, font=("Consolas", 9))
    style.configure("Treeview.Heading", font=FONT_BOLD)
    style.map("Treeview", background=[("selected", "#dbeafe")],
              foreground=[("selected", TEXT)])
    return style


class StatCard(ttk.Frame):
    """A white box showing one big number with a caption."""

    def __init__(self, parent, title, value="0", color=PRIMARY):
        super().__init__(parent, style="Card.TFrame", padding=14)
        self.configure(borderwidth=1, relief="solid")
        ttk.Label(self, text=title.upper(), style="Muted.TLabel").pack(anchor="w")
        self.value_label = tk.Label(self, text=value, font=FONT_BIG,
                                    fg=color, bg=CARD_BG)
        self.value_label.pack(anchor="w", pady=(4, 0))

    def set(self, value):
        self.value_label.config(text=str(value))


def make_tree(parent, columns, widths=None, height=15, anchors=None):
    """Create a Treeview with a vertical scrollbar, returns the tree."""
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True)

    tree = ttk.Treeview(frame, columns=columns, show="headings", height=height)
    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)

    for i, col in enumerate(columns):
        width = widths[i] if widths else 110
        anchor = anchors[i] if anchors else "w"
        tree.heading(col, text=col)
        tree.column(col, width=width, anchor=anchor, stretch=True)

    # row colour tags used across the app
    tree.tag_configure("allow", foreground=GREEN)
    tree.tag_configure("block", foreground=RED)
    tree.tag_configure("attack", background="#fee2e2", foreground=RED)
    tree.tag_configure("disabled", foreground=MUTED)
    return tree
