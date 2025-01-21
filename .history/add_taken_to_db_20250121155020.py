import sqlite3

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('aid_app.db')
cursor = conn.cursor()

# Add 'taken' column to 'families' table
# cursor.execute('''
# ALTER TABLE families ADD COLUMN taken BOOLEAN NOT NULL DEFAULT 0
# ''')
# Create Active Sessions Table 
cursor.execute(''' 
CREATE TABLE IF NOT EXISTS active_sessions ( 
    user_id INTEGER PRIMARY KEY, 
    access_token TEXT, 
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
    token_creation_time TIMESTAMP, 
    FOREIGN KEY(user_id) REFERENCES users(id) 
) 
''')

# Commit changes and close the connection
conn.commit()
conn.close()
