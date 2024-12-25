import sqlite3

conn = sqlite3.connect('aid_app.db')
cursor = conn.cursor()

# Add an admin user
cursor.execute('''
    INSERT INTO users (username, password, isAdmin) VALUES (?, ?, ?)
''', ('admin', 'admin123', True))

conn.commit()
conn.close()
