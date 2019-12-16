# coding: utf-8
"""
Add user_id column to actions table.
"""

import os

MIGRATION_INDEX = 12
MIGRATION_NAME, _ = os.path.splitext(os.path.basename(__file__))


def run(db):
    # Skip migration by condition
    client_column_names = db.session.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'users'
    """).fetchall()
    if ('is_readonly',) in client_column_names:
        return False

    # Perform migration
    db.session.execute("""
        ALTER TABLE users
        ADD is_readonly BOOLEAN NOT NULL DEFAULT(FALSE)
    """)
    return True
