from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
import datetime

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a random secret key
jwt = JWTManager(app)

# Database connection function
def get_db_connection():
    conn = sqlite3.connect('aid_app.db')
    conn.row_factory = sqlite3.Row
    return conn

# Helper function to check if the user is admin
def is_admin(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT isAdmin FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user['isAdmin'] if user else False

# Helper function to log changes
def log_change(family_id, user_id, description):
    conn = get_db_connection()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute('''
        INSERT INTO logs (familyID, userID, changeDescription, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (family_id, user_id, description, timestamp))
    conn.commit()
    conn.close()

# Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
    conn.close()
    if user:
        access_token = create_access_token(identity={'id': user['id'], 'isAdmin': user['isAdmin']})
        return jsonify({'message': 'Login successful', 'access_token': access_token})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Get Families Endpoint
@app.route('/families', methods=['GET'])
@jwt_required()
def get_families():
    user = get_jwt_identity()
    conn = get_db_connection()
    families = conn.execute('SELECT * FROM families').fetchall()
    conn.close()
    return jsonify([dict(family) for family in families])

# Update Products Endpoint
@app.route('/families/<int:id>/products', methods=['PUT'])
@jwt_required()
def update_products(id):
    user = get_jwt_identity()
    if not user:
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.json
    milk = data.get('milk')
    diapers = data.get('diapers')
    basket = data.get('basket')
    clothing = data.get('clothing')
    drugs = data.get('drugs')
    other = data.get('other')

    conn = get_db_connection()
    conn.execute('''
        UPDATE families SET milk = ?, diapers = ?, basket = ?, clothing = ?, drugs = ?, other = ?
        WHERE id = ?
    ''', (milk, diapers, basket, clothing, drugs, other, id))
    conn.commit()
    conn.close()

    # Log the change
    change_description = f'User {user["id"]} updated family {id}: milk={milk}, diapers={diapers}, basket={basket}, clothing={clothing}, drugs={drugs}, other={other}'
    log_change(id, user['id'], change_description)

    return jsonify({'message': 'Product updated successfully'})

# Add New User (Admin only)
@app.route('/users', methods=['POST'])
@jwt_required()
def add_user():
    user = get_jwt_identity()
    if not user['isAdmin']:
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.json
    username = data.get('username')
    password = data.get('password')
    isAdmin = data.get('isAdmin')
    
    conn = get_db_connection()
    conn.execute('INSERT INTO users (username, password, isAdmin) VALUES (?, ?, ?)', 
                 (username, password, isAdmin))
    conn.commit()
    conn.close()

    return jsonify({'message': 'User added successfully'})

# Add New Family Member (Admin only)
@app.route('/families', methods=['POST'])
@jwt_required()
def add_family():
    user = get_jwt_identity()
    if not user['isAdmin']:
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.json
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO families (fullName, nationalID, familyBookID, phoneNumber, familyNumber, 
                              children, babies, adults, milk, diapers, basket, clothing, drugs, other)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['fullName'], data['nationalID'], data['familyBookID'], data['phoneNumber'], data['familyNumber'], 
        data['children'], data['babies'], data['adults'], data['milk'], data['diapers'], 
        data['basket'], data['clothing'], data['drugs'], data['other']
    ))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Family member added successfully'})

# Edit User Info (Admin only)
@app.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def edit_user(id):
    user = get_jwt_identity()
    if not user['isAdmin']:
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.json
    conn = get_db_connection()
    conn.execute('''
        UPDATE users SET username = ?, password = ?, isAdmin = ? WHERE id = ?
    ''', (data['username'], data['password'], data['isAdmin'], id))
    conn.commit()
    conn.close()

    return jsonify({'message': 'User info updated successfully'})

# Edit Family Member Info (Admin only)
@app.route('/families/<int:id>', methods=['PUT'])
@jwt_required()
def edit_family(id):
    user = get_jwt_identity()
    if not user['isAdmin']:
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.json
    conn = get_db_connection()
    conn.execute('''
        UPDATE families SET fullName = ?, nationalID = ?, familyBookID = ?, phoneNumber = ?, familyNumber = ?, 
                            children = ?, babies = ?, adults = ?, milk = ?, diapers = ?, basket = ?, clothing = ?, drugs = ?, other = ?
        WHERE id = ?
    ''', (
        data['fullName'], data['nationalID'], data['familyBookID'], data['phoneNumber'], data['familyNumber'], 
        data['children'], data['babies'], data['adults'], data['milk'], data['diapers'], 
        data['basket'], data['clothing'], data['drugs'], data['other'], id
    ))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Family info updated successfully'})

# Get All Users (Admin only)
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    user = get_jwt_identity()
    if not user['isAdmin']:
        return jsonify({'message': 'Unauthorized'}), 401

    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return jsonify([dict(user) for user in users])

# Get Family Logs (Admin only)
@app.route('/families/<int:id>/logs', methods=['GET'])
@jwt_required()
def get_family_logs(id):
    user = get_jwt_identity()
    if not user['isAdmin']:
        return jsonify({'message': 'Unauthorized'}), 401

    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM logs WHERE familyID = ?', (id,)).fetchall()
    conn.close()
    return jsonify([dict(log) for log in logs])

# Start the Server
if __name__ == '__main__':
    app.run(debug=True)
