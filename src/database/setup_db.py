"""
setup_db.py
One-time helper: create the PostgreSQL database if it does not exist.

PostgreSQL will not create a database on demand the way SQLite creates a
file, so this script connects to the built-in `postgres` database and
issues a CREATE DATABASE.

Run it once before the first launch:

    python src/database/setup_db.py

Use --reset to drop the database and start over.
"""

import argparse
import os
import sys

SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

import config


def connect_admin():
    """Connect to the default `postgres` database, not ours."""
    conn = psycopg2.connect(**config.db_params(dbname="postgres"))
    # CREATE DATABASE cannot run inside a transaction block
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    return conn


def database_exists(cur, name) -> bool:
    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
    return cur.fetchone() is not None


def main():
    parser = argparse.ArgumentParser(description="Create the firewall database.")
    parser.add_argument("--reset", action="store_true",
                        help="drop the database first (deletes all data)")
    args = parser.parse_args()

    print(f"Connecting to PostgreSQL at {config.DB_HOST}:{config.DB_PORT} "
          f"as '{config.DB_USER}' ...")
    try:
        conn = connect_admin()
    except psycopg2.OperationalError as exc:
        print(f"\nCould not connect:\n{exc}")
        print("Check that PostgreSQL is running and that DB_USER / DB_PASSWORD "
              "in your .env file are correct.")
        sys.exit(1)

    with conn.cursor() as cur:
        if args.reset and database_exists(cur, config.DB_NAME):
            confirm = input(f"Drop database '{config.DB_NAME}' and lose all data? [y/N] ")
            if confirm.lower() != "y":
                print("Cancelled.")
                sys.exit(0)
            cur.execute(f'DROP DATABASE "{config.DB_NAME}"')
            print(f"Dropped '{config.DB_NAME}'.")

        if database_exists(cur, config.DB_NAME):
            print(f"Database '{config.DB_NAME}' already exists.")
        else:
            cur.execute(f'CREATE DATABASE "{config.DB_NAME}"')
            print(f"Created database '{config.DB_NAME}'.")
    conn.close()

    # Now create the tables by simply constructing the manager.
    from database.db_manager import DatabaseManager, DatabaseError
    try:
        db = DatabaseManager()
    except DatabaseError as exc:
        print(f"\n{exc}")
        sys.exit(1)

    tables = db._query(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'public' ORDER BY table_name")
    print("\nTables ready:")
    for t in tables:
        print(f"  - {t['table_name']}")
    print(f"\nRules loaded: {len(db.get_rules())}")
    db.close()
    print("\nSetup complete. Start the application with:  python src/main.py")


if __name__ == "__main__":
    main()
