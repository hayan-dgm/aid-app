# from flask import Flask, request, jsonify
# from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# from flask_socketio import SocketIO, emit
# import sqlite3
# import datetime

# app = Flask(__name__)
# app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a random secret key
# jwt = JWTManager(app)
# socketio = SocketIO(app, cors_allowed_origins="*")

# # Database connection function
# def get_db_connection():
#     conn = sqlite3.connect('aid_app.db')
#     conn.row_factory = sqlite3.Row
#     return conn

# # WebSocket events
# @socketio.on('connect')
# def handle_connect():
#     print('Client connected')
#     emit('connection_response', {'message': 'Connected successfully'})

# @socketio.on('disconnect')
# def handle_disconnect():
#     print('Client disconnected')

# # Helper function to log changes
# def log_change(family_id, user_id, description):
#     conn = get_db_connection()
#     timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     conn.execute('''
#         INSERT INTO logs (familyID, userID, changeDescription, timestamp)
#         VALUES (?, ?, ?, ?)
#     ''', (family_id, user_id, description, timestamp))
#     conn.commit()
#     conn.close()

# # Login Endpoint
# @app.route('/login', methods=['POST'])
# def login():
#     data = request.json
#     username = data.get('username')
#     password = data.get('password')
#     conn = get_db_connection()
#     user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
#     conn.close()
#     if user:
#         access_token = create_access_token(identity={'id': user['id'], 'isAdmin': user['isAdmin']})
#         return jsonify({'message': 'Login successful', 'access_token': access_token})
#     else:
#         return jsonify({'message': 'Invalid credentials'}), 401

# # Get Families Endpoint
# @app.route('/families', methods=['GET'])
# @jwt_required()
# def get_families():
#     user = get_jwt_identity()
#     conn = get_db_connection()
#     families = conn.execute('SELECT * FROM families').fetchall()
#     conn.close()
#     return jsonify([dict(family) for family in families])

# # Update Products Endpoint
# @app.route('/families/<int:id>/products', methods=['PUT'])
# @jwt_required()
# def update_products(id):
#     user = get_jwt_identity()
#     if not user:
#         return jsonify({'message': 'Unauthorized'}), 401

#     data = request.json
#     milk = data.get('milk')
#     diapers = data.get('diapers')
#     basket = data.get('basket')
#     clothing = data.get('clothing')
#     drugs = data.get('drugs')
#     other = data.get('other')

#     conn = get_db_connection()
#     conn.execute('''
#         UPDATE families SET milk = ?, diapers = ?, basket = ?, clothing = ?, drugs = ?, other = ?
#         WHERE id = ?
#     ''', (milk, diapers, basket, clothing, drugs, other, id))
#     conn.commit()
#     conn.close()

#     # Log the change
#     change_description = f'User {user["id"]} updated family {id}: milk={milk}, diapers={diapers}, basket={basket}, clothing={clothing}, drugs={drugs}, other={other}'
#     log_change(id, user['id'], change_description)

#     # Emit a real-time update to all connected clients
#     print(f'Emitting update: {change_description}')
#     socketio.emit('update_family', {'family_id': id, 'change_description': change_description})

#     return jsonify({'message': 'Product updated successfully'})

# # Add New User (Admin only)
# @app.route('/users', methods=['POST'])
# @jwt_required()
# def add_user():
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     data = request.json
#     username = data.get('username')
#     password = data.get('password')
#     isAdmin = data.get('isAdmin')
    
#     conn = get_db_connection()
#     conn.execute('INSERT INTO users (username, password, isAdmin) VALUES (?, ?, ?)', 
#                  (username, password, isAdmin))
#     conn.commit()
#     conn.close()

#     # Emit a real-time update to all connected clients
#     socketio.emit('update_users', {'username': username, 'isAdmin': isAdmin})

#     return jsonify({'message': 'User added successfully'})

# # Add New Family Member (Admin only)
# @app.route('/families', methods=['POST'])
# @jwt_required()
# def add_family():
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     data = request.json
#     conn = get_db_connection()
#     conn.execute('''
#         INSERT INTO families (fullName, nationalID, familyBookID, phoneNumber, familyNumber, 
#                               children, babies, adults, milk, diapers, basket, clothing, drugs, other)
#         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#     ''', (
#         data['fullName'], data['nationalID'], data['familyBookID'], data['phoneNumber'], data['familyNumber'], 
#         data['children'], data['babies'], data['adults'], data['milk'], data['diapers'], 
#         data['basket'], data['clothing'], data['drugs'], data['other']
#     ))
#     conn.commit()
#     conn.close()

#     # Emit a real-time update to all connected clients
#     socketio.emit('update_families', {'fullName': data['fullName'], 'familyNumber': data['familyNumber']})

#     return jsonify({'message': 'Family member added successfully'})

# # Edit User Info (Admin only)
# @app.route('/users/<int:id>', methods=['PUT'])
# @jwt_required()
# def edit_user(id):
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     data = request.json
#     conn = get_db_connection()
#     conn.execute('''
#         UPDATE users SET username = ?, password = ?, isAdmin = ? WHERE id = ?
#     ''', (data['username'], data['password'], data['isAdmin'], id))
#     conn.commit()
#     conn.close()

#     return jsonify({'message': 'User info updated successfully'})

# # Edit Family Member Info (Admin only)
# @app.route('/families/<int:id>', methods=['PUT'])
# @jwt_required()
# def edit_family(id):
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     data = request.json
#     conn = get_db_connection()
#     conn.execute('''
#         UPDATE families SET fullName = ?, nationalID = ?, familyBookID = ?, phoneNumber = ?, familyNumber = ?, 
#                             children = ?, babies = ?, adults = ?, milk = ?, diapers = ?, basket = ?, clothing = ?, drugs = ?, other = ?
#         WHERE id = ?
#     ''', (
#         data['fullName'], data['nationalID'], data['familyBookID'], data['phoneNumber'], data['familyNumber'], 
#         data['children'], data['babies'], data['adults'], data['milk'], data['diapers'], 
#         data['basket'], data['clothing'], data['drugs'], data['other'], id
#     ))
#     conn.commit()
#     conn.close()

#     # Emit a real-time update to all connected clients
#     socketio.emit('update_families', {'id': id, 'fullName': data['fullName'], 'familyNumber': data['familyNumber']})

#     return jsonify({'message': 'Family info updated successfully'})

# # Get All Users (Admin only)
# @app.route('/users', methods=['GET'])
# @jwt_required()
# def get_users():
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     conn = get_db_connection()
#     users = conn.execute('SELECT * FROM users').fetchall()
#     conn.close()
#     return jsonify([dict(user) for user in users])

# # Get Family Logs (Admin only)
# @app.route('/families/<int:id>/logs', methods=['GET'])
# @jwt_required()
# def get_family_logs(id):
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     conn = get_db_connection()
#     logs = conn.execute('SELECT * FROM logs WHERE familyID = ?', (id,)).fetchall()
#     conn.close()
#     return jsonify([dict(log) for log in logs])

# # Start the Server
# if __name__ == '__main__':
#     app.debug = True
#     socketio.run(app, debug=True)



# from flask import Flask, request, jsonify
# from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# from flask_socketio import SocketIO, emit
# import sqlite3
# import datetime

# app = Flask(__name__)
# app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a random secret key
# jwt = JWTManager(app)
# socketio = SocketIO(app, cors_allowed_origins="*")

# # Database connection function
# def get_db_connection():
#     conn = sqlite3.connect('aid_app.db')
#     conn.row_factory = sqlite3.Row
#     return conn

# # WebSocket events
# @socketio.on('connect')
# def handle_connect():
#     print('Client connected')
#     emit('connection_response', {'message': 'Connected successfully'})

# @socketio.on('disconnect')
# def handle_disconnect():
#     print('Client disconnected')

# # Helper function to log changes
# def log_change(family_id, user_id, description):
#     conn = get_db_connection()
#     timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     conn.execute('''
#         INSERT INTO logs (familyID, userID, changeDescription, timestamp)
#         VALUES (?, ?, ?, ?)
#     ''', (family_id, user_id, description, timestamp))
#     conn.commit()
#     conn.close()

# # # Login Endpoint
# # @app.route('/login', methods=['POST'])
# # def login():
# #     data = request.json
# #     username = data.get('username')
# #     password = data.get('password')
# #     conn = get_db_connection()
# #     user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
# #     conn.close()
# #     if user:
# #         access_token = create_access_token(identity={'id': user['id'], 'isAdmin': user['isAdmin']})
# #         return jsonify({'message': 'Login successful', 'access_token': access_token})
# #     else:
# #         return jsonify({'message': 'Invalid credentials'}), 401


# @app.route('/login', methods=['POST'])
# def login():
#     data = request.json
#     username = data.get('username')
#     password = data.get('password')
#     conn = get_db_connection()
#     user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
#     conn.close()
#     if user:
#         access_token = create_access_token(identity={'id': user['id'], 'username': user['username'], 'isAdmin': user['isAdmin']})
#         return jsonify({'message': 'Login successful', 'access_token': access_token})
#     else:
#         return jsonify({'message': 'Invalid credentials'}), 401


# # # Get Families Endpoint
# # @app.route('/families', methods=['GET'])
# # @jwt_required()
# # def get_families():
# #     user = get_jwt_identity()
# #     conn = get_db_connection()
# #     families = conn.execute('SELECT * FROM families').fetchall()
# #     conn.close() 
# #     return jsonify([dict(family) for family in families])

# @app.route('/families', methods=['GET'])
# @jwt_required()
# def get_families():
#     user = get_jwt_identity()
#     print(f"User: {user}")  # Log user identity
#     conn = get_db_connection()
#     families = conn.execute('SELECT * FROM families').fetchall()
#     conn.close()
#     return jsonify([dict(family) for family in families])

# # Get single Family Endpoint
# @app.route('/families/<int:id>', methods=['GET'])
# @jwt_required() 
# def get_single_family(id): 
#     user = get_jwt_identity()# Ensure you use this if needed 
#     conn = get_db_connection() # Correctly parameterize the SQL query 
    
#     family = conn.execute('SELECT * FROM families WHERE id = ?', (id,)).fetchone()
#     conn.close() # Check if the family was found 

#     if family is None:
#         return jsonify({"message": "Family not found"}), 404 
    
#     # Return the single family as a dictionary 
#     return jsonify(dict(family))

# # Update Products Endpoint
# @app.route('/families/<int:id>/products', methods=['PUT'])
# @jwt_required()
# def update_products(id):
#     user = get_jwt_identity()
#     if not user:
#         return jsonify({'message': 'Unauthorized'}), 401

#     data = request.json
#     milk = data.get('milk')
#     diapers = data.get('diapers')
#     basket = data.get('basket')
#     clothing = data.get('clothing')
#     drugs = data.get('drugs')
#     other = data.get('other')

#     conn = get_db_connection()
#     conn.execute('''
#         UPDATE families SET milk = ?, diapers = ?, basket = ?, clothing = ?, drugs = ?, other = ?
#         WHERE id = ?
#     ''', (milk, diapers, basket, clothing, drugs, other, id))
#     conn.commit()

#     # Fetch the username
#     user_info = conn.execute('SELECT username FROM users WHERE id = ?', (user['id'],)).fetchone()
#     username = user_info['username'] if user_info else 'Unknown'
#     conn.close()

#     # Log the change
#     change_description = f'User {username} (ID: {user["id"]}) updated family {id}: milk={milk}, diapers={diapers}, basket={basket}, clothing={clothing}, drugs={drugs}, other={other}'
#     log_change(id, user['id'], change_description)

#     # Emit a real-time update to all connected clients
#     print(f'Emitting update: {change_description}')
#     socketio.emit('update_family', {'family_id': id, 'user_id': user['id'], 'username': username, 'change_description': change_description})

#     return jsonify({'message': 'Product updated successfully'})



# # Add New User (Admin only)
# @app.route('/users', methods=['POST'])
# @jwt_required()
# def add_user():
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     data = request.json
#     username = data.get('username')
#     password = data.get('password')
#     isAdmin = data.get('isAdmin')
    
#     conn = get_db_connection()
#     conn.execute('INSERT INTO users (username, password, isAdmin) VALUES (?, ?, ?)', 
#                  (username, password, isAdmin))
#     conn.commit()
#     conn.close()

#     # Emit a real-time update to all connected clients
#     socketio.emit('update_users', {'username': username, 'isAdmin': isAdmin})

#     return jsonify({'message': 'User added successfully'})

# # Add New Family Member (Admin only)
# @app.route('/families', methods=['POST'])
# @jwt_required()
# def add_family():
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     data = request.json
#     conn = get_db_connection()
#     conn.execute('''
#         INSERT INTO families (fullName, nationalID, familyBookID, phoneNumber, familyNumber, 
#                               children, babies, adults, milk, diapers, basket, clothing, drugs, other)
#         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#     ''', (
#         data['fullName'], data['nationalID'], data['familyBookID'], data['phoneNumber'], data['familyNumber'], 
#         data['children'], data['babies'], data['adults'], data['milk'], data['diapers'], 
#         data['basket'], data['clothing'], data['drugs'], data['other']
#     ))
#     conn.commit()
#     conn.close()

#     # Emit a real-time update to all connected clients
#     socketio.emit('update_families', {'fullName': data['fullName'], 'familyNumber': data['familyNumber']})

#     return jsonify({'message': 'Family member added successfully'})

# # Edit User Info (Admin only)
# @app.route('/users/<int:id>', methods=['PUT'])
# @jwt_required()
# def edit_user(id):
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     data = request.json
#     conn = get_db_connection()
#     conn.execute('''
#         UPDATE users SET username = ?, password = ?, isAdmin = ? WHERE id = ?
#     ''', (data['username'], data['password'], data['isAdmin'], id))
#     conn.commit()
#     conn.close()

#     return jsonify({'message': 'User info updated successfully'})

# # Edit Family Member Info (Admin only)
# @app.route('/families/<int:id>', methods=['PUT'])
# @jwt_required()
# def edit_family(id):
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     data = request.json
#     conn = get_db_connection()
#     conn.execute('''
#         UPDATE families SET fullName = ?, nationalID = ?, familyBookID = ?, phoneNumber = ?, familyNumber = ?, 
#                             children = ?, babies = ?, adults = ?, milk = ?, diapers = ?, basket = ?, clothing = ?, drugs = ?, other = ?
#         WHERE id = ?
#     ''', (
#         data['fullName'], data['nationalID'], data['familyBookID'], data['phoneNumber'], data['familyNumber'], 
#         data['children'], data['babies'], data['adults'], data['milk'], data['diapers'], 
#         data['basket'], data['clothing'], data['drugs'], data['other'], id
#     ))
#     conn.commit()
#     conn.close()

#     # Emit a real-time update to all connected clients
#     socketio.emit('update_families', {'id': id, 'fullName': data['fullName'], 'familyNumber': data['familyNumber']})

#     return jsonify({'message': 'Family info updated successfully'})

# # Get All Users (Admin only)
# @app.route('/users', methods=['GET'])
# @jwt_required()
# def get_users():
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     conn = get_db_connection()
#     users = conn.execute('SELECT * FROM users').fetchall()
#     conn.close()
#     return jsonify([dict(user) for user in users])

# # Get Family Logs (Admin only)
# @app.route('/families/<int:id>/logs', methods=['GET'])
# @jwt_required()
# def get_family_logs(id):
#     user = get_jwt_identity()
#     if not user['isAdmin']:
#         return jsonify({'message': 'Unauthorized'}), 401

#     conn = get_db_connection()
#     logs = conn.execute('SELECT * FROM logs WHERE familyID = ?', (id,)).fetchall()
#     conn.close()
#     return jsonify([dict(log) for log in logs])

# # Start the Server
# if __name__ == '__main__':
#     app.debug = True
#     socketio.run(app, debug=True)



import logging
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_socketio import SocketIO, emit
import sqlite3
import datetime
import os
import jwt as jww

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') 
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_VERIFY_SUB'] = False # Add this line to disable `sub` claim verification
# app.config['JWT_SECRET_KEY'] = '57a6a39a94d76c5cbbdec50f2a6ec31ba17b318f695d39750ee133a078fd128d'  # Change this to a random secret key
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database connection function
def get_db_connection():
    # db_path = os.path.join(os.getenv('PERSISTENT_DISK_PATH', '/data'), 'aid_app.db')
    db_url = os.getenv('DATABASE_URL')
    conn = sqlite3.connect('aid_app.db')
    conn.row_factory = sqlite3.Row
    return conn

# Root route
@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'Welcome to the API'})

# WebSocket events
@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')
    emit('connection_response', {'message': 'Connected successfully'})

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

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



@app.route('/login', methods=['POST'])
def login():
     try: 
        data = request.json 
        logger.debug(f"Incoming login data: {data}") 
        username = data.get('username') 
        password = data.get('password') 
        logger.debug(f'Login attempt for username: {username}') 

        if not username or not password:
             logger.error(f'Missing username or password: username={username}, password={password}') 
             return jsonify({'message': 'Missing username or password'}), 400 
        
        conn = get_db_connection() 
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone() 
        conn.close() 
        if user: 
            access_token = create_access_token(identity={'id': user['id'], 'username': user['username'], 'isAdmin': user['isAdmin']}) 
            logger.debug(f'Login successful for user: {username}') 
            return jsonify({'message': 'Login successful', 'access_token': access_token}) 
        else:
            logger.warning(f'Invalid login attempt for username: {username}')
            return jsonify({'message': 'Invalid credentials'}), 401 
     except Exception as e:
         logger.error(f"Error during login: {e}") 
         return jsonify({'message': 'An error occurred during login'}), 500

# @app.route('/families', methods=['GET']) 
# @jwt_required() 
# def get_families():
#     user = get_jwt_identity()
#     logger.debug(f"User: {user} requested /families")
#     try: 
#          # Log the request headers 
#         logger.debug(f"Request Headers: {request.headers}")
#           # Decode and log the JWT token 
#         token = request.headers.get('Authorization').split()[1] 
#         print(str(token))
#         decoded_token = jww.decode(token, options={"verify_signature": False})
#         logger.debug(f"Decoded JWT Token: {decoded_token}")
#         print(f"Decoded JWT Token: {decoded_token}")
#         conn = get_db_connection()
#         families = conn.execute('SELECT * FROM families').fetchall()
#         conn.close()
#         response = jsonify([dict(family) for family in families])
#         logger.debug(f"Response for /families: {response.get_json()}")
#         return response 
#     except Exception as e:
#         logger.error(f"Error retrieving families: {e}") 
#         return jsonify({"error": "An error occurred while retrieving families"}), 500

@app.route('/families', methods=['GET'])
@jwt_required()
def get_families():
    user = get_jwt_identity()
    logger.debug(f"User: {user} requested /families")
    
    # Get query parameters
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)
    
    try:
        conn = get_db_connection()
        
        # Calculate offset
        offset = (page - 1) * per_page

        # Fetch families with pagination
        families = conn.execute('SELECT * FROM families LIMIT ? OFFSET ?', (per_page, offset)).fetchall()
        conn.close()

        # Fetch total count of families
        conn = get_db_connection()
        total_families = conn.execute('SELECT COUNT(*) FROM families').fetchone()[0]
        conn.close()

        response = {
            'page': page,
            'per_page': per_page,
            'total': total_families,
            'families': [dict(family) for family in families]
        }

        logger.debug(f"Response for /families: {response}")
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error retrieving families: {e}")
        return jsonify({"error": "An error occurred while retrieving families"}), 500


@app.route('/families/<int:id>', methods=['GET'])
@jwt_required()
def get_single_family(id):
    user = get_jwt_identity()
    logger.debug(f"User: {user} requested /families/{id}")
    try:
        conn = get_db_connection()
        family = conn.execute('SELECT * FROM families WHERE id = ?', (id,)).fetchone()
        conn.close()
        if family is None:
            logger.warning(f"Family with id {id} not found")
            return jsonify({"message": "Family not found"}), 404
        response = jsonify(dict(family))
        logger.debug(f"Response for /families/{id}: {response.get_json()}")
        return response
    except Exception as e:
        logger.error(f"Error retrieving family {id}: {e}")
        return jsonify({"error": "An error occurred while retrieving the family"}), 500

# Update Products Endpoint
@app.route('/families/<int:id>/products', methods=['PUT'])
@jwt_required()
def update_products(id):
    user = get_jwt_identity()
    logger.debug(f"User: {user} requested update on family {id}")
    if not user:
        logger.warning('Unauthorized access attempt')
        return jsonify({'message': 'Unauthorized'}), 401

    try:
        data = request.json
        milk = data.get('milk')
        diapers = data.get('diapers')
        basket = data.get('basket')
        clothing = data.get('clothing')
        drugs = data.get('drugs')
        other = data.get('other')
        taken = data.get('taken')

        conn = get_db_connection()
        conn.execute('''
            UPDATE families SET milk = ?, diapers = ?, basket = ?, clothing = ?, drugs = ?, other = ?, taken = ?
            WHERE id = ?
        ''', (milk, diapers, basket, clothing, drugs, other, taken, id))
        conn.commit()

        user_info = conn.execute('SELECT username FROM users WHERE id = ?', (user['id'],)).fetchone()
        username = user_info['username'] if user_info else 'Unknown'
        conn.close()

        change_description = f'User {username} (ID: {user["id"]}) updated family {id}'
        log_change(id, user['id'], change_description)
        logger.debug(f"Emitting update: {change_description}")
        socketio.emit('update_family', {'family_id': id, 'user_id': user['id'], 'username': username, 'change_description': change_description})
        return jsonify({'message': 'Product updated successfully'})
    except Exception as e:
        logger.error(f"Error updating products for family {id}: {e}")
        return jsonify({"error": "An error occurred while updating products"}), 500

# Error handler to catch all exceptions and log them
@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled Exception: {e}")
    return jsonify({"error": "An internal server error occurred"}), 500

# Start the Server
# if __name__ == '__main__':
#     app.debug = False
#     socketio.run(app, debug=False)
if __name__ == '__main__':
    app.debug = True
    socketio.run(app, debug=True, use_reloader=False, host='0.0.0.0', port=5000)
