"""
dashboard.py
Overview tab: counters, attack-type chart and a live traffic chart.
"""

from collections import deque
from tkinter import ttk

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from matplotlib.ticker import MaxNLocator

import config
from ui import theme


class DashboardTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=14)
        self.controller = controller

        # history for the live traffic chart (one entry per second)
        self.history_allowed = deque([0] * config.CHART_HISTORY,
                                     maxlen=config.CHART_HISTORY)
        self.history_blocked = deque([0] * config.CHART_HISTORY,
                                     maxlen=config.CHART_HISTORY)
        self._last = controller.snapshot()

        self._build_cards()
        self._build_charts()
        self._tick()

    # ------------------------------------------------------------------ layout
    def _build_cards(self):
        row = ttk.Frame(self)
        row.pack(fill="x")

        self.card_total = theme.StatCard(row, "Total packets", color=theme.PRIMARY)
        self.card_allowed = theme.StatCard(row, "Allowed", color=theme.GREEN)
        self.card_blocked = theme.StatCard(row, "Blocked", color=theme.RED)
        self.card_attacks = theme.StatCard(row, "Attacks detected", color=theme.ORANGE)
        self.card_black = theme.StatCard(row, "Blacklisted IPs", color=theme.PURPLE)

        for i, card in enumerate([self.card_total, self.card_allowed,
                                  self.card_blocked, self.card_attacks,
                                  self.card_black]):
            card.grid(row=0, column=i, padx=6, sticky="nsew")
            row.columnconfigure(i, weight=1)

    def _build_charts(self):
        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, pady=(16, 0))
        wrap.columnconfigure(0, weight=3)
        wrap.columnconfigure(1, weight=2)
        wrap.rowconfigure(0, weight=1)

        # --- live traffic (line) ---
        left = ttk.LabelFrame(wrap, text="  Live traffic (last 60 seconds)  ",
                              padding=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        self.fig_traffic = Figure(figsize=(6, 3.2), dpi=96, layout="constrained")
        self.ax_traffic = self.fig_traffic.add_subplot(111)
        self.canvas_traffic = FigureCanvasTkAgg(self.fig_traffic, master=left)
        self.canvas_traffic.get_tk_widget().pack(fill="both", expand=True)

        # --- attacks by type (bar) ---
        right = ttk.LabelFrame(wrap, text="  Attacks by type  ", padding=8)
        right.grid(row=0, column=1, sticky="nsew")

        self.fig_attacks = Figure(figsize=(4, 3.2), dpi=96, layout="constrained")
        self.ax_attacks = self.fig_attacks.add_subplot(111)
        self.canvas_attacks = FigureCanvasTkAgg(self.fig_attacks, master=right)
        self.canvas_attacks.get_tk_widget().pack(fill="both", expand=True)

        self._draw_traffic()
        self._draw_attacks()

    # ------------------------------------------------------------------ drawing
    def _draw_traffic(self):
        ax = self.ax_traffic
        ax.clear()
        x = list(range(-len(self.history_allowed) + 1, 1))
        ax.plot(x, list(self.history_allowed), color=theme.GREEN,
                linewidth=1.8, label="Allowed")
        ax.plot(x, list(self.history_blocked), color=theme.RED,
                linewidth=1.8, label="Blocked")
        ax.fill_between(x, list(self.history_allowed), color=theme.GREEN, alpha=0.12)
        ax.fill_between(x, list(self.history_blocked), color=theme.RED, alpha=0.12)
        ax.set_xlabel("seconds ago", fontsize=8)
        ax.set_ylabel("packets / second", fontsize=8)
        ax.tick_params(labelsize=8)
        ax.grid(True, alpha=0.25, linestyle="--")
        ax.legend(fontsize=8, loc="upper left")
        ax.set_ylim(bottom=0)
        self.canvas_traffic.draw_idle()

    def _draw_attacks(self):
        counts = self.controller.db.get_attack_counts()
        labels = ["Port\nscan", "Brute\nforce", "Traffic\nflood"]
        values = [counts.get(config.PORT_SCAN, 0),
                  counts.get(config.BRUTE_FORCE, 0),
                  counts.get(config.TRAFFIC_FLOOD, 0)]

        ax = self.ax_attacks
        ax.clear()
        bars = ax.bar(labels, values,
                      color=[theme.ORANGE, theme.PURPLE, theme.RED], width=0.55)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                    str(value), ha="center", va="bottom", fontsize=9)
        ax.set_ylabel("alerts", fontsize=8)
        ax.tick_params(labelsize=8)
        ax.grid(True, axis="y", alpha=0.25, linestyle="--")
        ax.set_ylim(0, max(values + [1]) * 1.25)
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        self.canvas_attacks.draw_idle()

    # ------------------------------------------------------------------ refresh
    def _tick(self):
        """Runs once per second: update counters and charts."""
        now = self.controller.snapshot()

        self.card_total.set(now["total"])
        self.card_allowed.set(now["allowed"])
        self.card_blocked.set(now["blocked"])
        self.card_attacks.set(now["attacks"])
        self.card_black.set(now["blacklisted"])

        # packets in the last second = difference from the previous sample
        self.history_allowed.append(max(0, now["allowed"] - self._last["allowed"]))
        self.history_blocked.append(max(0, now["blocked"] - self._last["blocked"]))
        self._last = now

        self._draw_traffic()
        self._draw_attacks()
        self.after(config.CHART_REFRESH_MS, self._tick)

    def reset_history(self):
        self.history_allowed = deque([0] * config.CHART_HISTORY,
                                     maxlen=config.CHART_HISTORY)
        self.history_blocked = deque([0] * config.CHART_HISTORY,
                                     maxlen=config.CHART_HISTORY)
        self._last = self.controller.snapshot()
