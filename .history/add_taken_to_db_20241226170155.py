import sqlite3

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('aid_app.db')
cursor = conn.cursor()

# Add 'taken' column to 'families' table
cursor.execute('''
ALTER TABLE families ADD COLUMN taken BOOLEAN NOT NULL DEFAULT 0
''')

# Commit changes and close the connection
conn.commit()
conn.close()
