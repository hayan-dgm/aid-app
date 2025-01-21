import pandas as pd
import sqlite3

# Read Excel file
df = pd.read_excel('data.xlsx')

# Connect to SQLite database
conn = sqlite3.connect('aid_app.db')
cursor = conn.cursor()

# Insert Data into Families Table
for index, row in df.iterrows():
    cursor.execute('''
        INSERT INTO families (fullName, nationalID, familyBookID, phoneNumber, familyMembers, children, babies, adults, milk, diapers, basket, clothing, drugs, other)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        row['full_name'], row['national_id'], row['family_book_id'], row['phone_number'], row['family_members'], 
        row['children'], row['babies'], row['adults'], row['milk'], row['diapers'], 
        row['basket'], row['clothing'], row['drugs'], row['other']
    ))

# Commit changes and close the connection
conn.commit()
conn.close()
