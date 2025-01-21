import sqlite3

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('aid_app.db')
cursor = conn.cursor()

# Create Users Table with isAdmin boolean (if not already created)
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    isAdmin BOOLEAN NOT NULL
)
''')

# Create Families Table (with products embedded and 'other' as a comma-separated list)
cursor.execute('''
CREATE TABLE IF NOT EXISTS families (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullName TEXT NOT NULL,
    nationalID TEXT NOT NULL,
    familyBookID TEXT NOT NULL,
    phoneNumber TEXT NOT NULL,
    familyMembers INTEGER NOT NULL,
    children INTEGER NOT NULL,
    babies INTEGER NOT NULL,
    adults INTEGER NOT NULL,
    milk INTEGER NOT NULL,
    diapers INTEGER NOT NULL,
    basket INTEGER NOT NULL,
    clothing INTEGER NOT NULL,
    drugs INTEGER NOT NULL,
    other TEXT
)
''')

# Create Logs Table
cursor.execute('''
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    familyID INTEGER NOT NULL,
    userID INTEGER NOT NULL,
    changeDescription TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (familyID) REFERENCES families (id),
    FOREIGN KEY (userID) REFERENCES users (id)
)
''')

# Create Active Sessions Table
cursor.execute('''
CREATE TABLE IF NOT EXISTS active_sessions (
    user_id INTEGER PRIMARY KEY,
    access_token TEXT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')


# Commit changes and close the connection
conn.commit()
conn.close()
