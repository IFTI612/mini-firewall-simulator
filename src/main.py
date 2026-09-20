"""
main.py
Entry point for the Mini Firewall Simulator.

Run from the project root:
    python src/main.py

Before the first run, create the PostgreSQL database:
    python src/database/setup_db.py

EDUCATIONAL PROJECT — every packet and every attack in this program is
generated internally. No real network interface is opened, no packet is
captured, and no external host is scanned or contacted.
"""

import os
import sys

# Make `import config`, `import models.packet`, etc. work no matter where
# the program is launched from.
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def main():
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("Tkinter is not installed.\n"
              "On Ubuntu/Debian run:  sudo apt install python3-tk")
        sys.exit(1)

    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print("Matplotlib is not installed.\n"
              "Run:  pip install -r requirements.txt")
        sys.exit(1)

    try:
        import psycopg2  # noqa: F401
    except ImportError:
        print("psycopg2 is not installed.\n"
              "Run:  pip install -r requirements.txt")
        sys.exit(1)

    from database.db_manager import DatabaseError
    from ui.app import FirewallApp

    try:
        app = FirewallApp()
    except DatabaseError as exc:
        # Show the problem in a dialog as well as the terminal, because the
        # program is usually started by double-clicking, not from a shell.
        print(f"\n{exc}\n")
        import tkinter.messagebox as mb
        root = tkinter.Tk()
        root.withdraw()
        mb.showerror("Database connection failed", str(exc))
        root.destroy()
        sys.exit(1)

    app.mainloop()


if __name__ == "__main__":
    main()
