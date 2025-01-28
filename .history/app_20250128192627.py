import logging
from functools import wraps
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt
from flask_socketio import SocketIO, emit
import sqlite3
from datetime import datetime, timezone , timedelta
import os
import jwt as jww
import dateutil.parser
import sqlitecloud

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') 
app.config['JWT_ALGORITHM'] = 'HS256'  # Ensure the algorithm matches your token's algorithm
# app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_VERIFY_SUB'] = False # Add this line to disable `sub` claim verification
app.config['JWT_SECRET_KEY'] = '57a6a39a94d76c5cbbdec50f2a6ec31ba17b318f695d39750ee133a078fd128d'  # Change this to a random secret key
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database connection function
def get_db_connection():
    # db_path = os.path.join(os.getenv('PERSISTENT_DISK_PATH', '/data'), 'aid_app.db')
    # db_url = os.getenv('DATABASE_URL')
    # conn = sqlitecloud.connect(db_url)
    # if db_url.startswith("sqlite:///"):
    #     db_path=db_url[10:]
    #     conn = sqlite3.connect(db_path)
    # else:
    #     raise ValueError("Invalid DATABASE_URL format")
    # # conn.row_factory = sqlite3.Row
    conn = sqlite3.connect('aid_app.db')
    # conn = sqlite3.connect(db_url)
    # conn.row_factory = sqlite3.Row
    return conn





# def token_required(fn):
#     @wraps(fn)
#     def wrapper(*args, **kwargs):
#         verify_jwt_in_request()
#         jwt_data = get_jwt()
#         user_id = jwt_data['sub']['id']
#         login_time = jwt_data['iat']
        
#         conn = get_db_connection()
#         session = conn.execute('SELECT login_time FROM active_sessions WHERE user_id = ?', (user_id,)).fetchone()
#         conn.close()
        
#         if session:
#             db_login_time = dateutil.parser.parse(session['login_time']) 
#             if db_login_time.tzinfo is None: 
#                 db_login_time = db_login_time.replace(tzinfo=timezone.utc) 
#             token_login_time = datetime.fromtimestamp(login_time, timezone.utc)
#             logger.debug(f"db_login_time: {db_login_time}, token_login_time: {token_login_time}")

#             tolerance = timedelta(seconds=1)
#             if db_login_time > token_login_time + tolerance:
#                 return jsonify({'message': 'Token has been revoked'}), 401
        
#         return fn(*args, **kwargs)
#     return wrapper


# def token_required(fn):
#     @wraps(fn)
#     def wrapper(*args, **kwargs):
#         verify_jwt_in_request()
#         jwt_data = get_jwt()
#         user_id = jwt_data['sub']['id']
#         login_time = jwt_data['iat']
#         jti = jwt_data['jti']

#         conn = get_db_connection()
#         session = conn.execute('SELECT login_time FROM active_sessions WHERE user_id = ?', (user_id,)).fetchone()
#         revoked = conn.execute('SELECT * FROM revoked_tokens WHERE jti = ?', (jti,)).fetchone()
#         conn.close()

#         if revoked:
#             return jsonify({'message': 'Token has been revoked'}), 401

#         if session:
#             try:
#                 db_login_time = dateutil.parser.parse('login_time')
#             except (IndexError, KeyError, TypeError) as e:
#                 logger.error(f"Error parsing login time from session: {e}", exc_info=True)
#                 return jsonify({'message': 'Error parsing session data'}), 500

#             # db_login_time = dateutil.parser.parse(session[0])
#             # if isinstance(session, sqlitecloud.Row):
#             # db_login_time = dateutil.parser.parse(session['login_time'])
#             # else:
#             #     db_login_time = dateutil.parser.parse(session[0])  # Access tuple element with index

#             if db_login_time.tzinfo is None:
#                 db_login_time = db_login_time.replace(tzinfo=timezone.utc)
#             token_login_time = datetime.fromtimestamp(login_time, timezone.utc)

#             logger.debug(f"db_login_time: {db_login_time}, token_login_time: {token_login_time}")

#             tolerance = timedelta(seconds=1)
#             if db_login_time > token_login_time + tolerance:
#                 return jsonify({'message': 'Token has been revoked'}), 401

#         return fn(*args, **kwargs)
#     return wrapper

def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            jwt_data = get_jwt()
        except Exception as e:
            logger.error(f"Error verifying JWT: {e}", exc_info=True)
            return jsonify({"msg": "Invalid JWT"}), 401

        try:
            user_id = jwt_data['sub']['id']
            login_time = jwt_data['iat']
            jti = jwt_data['jti']

            conn = get_db_connection()
            session = conn.execute('SELECT login_time FROM active_sessions WHERE user_id = ?', (user_id,)).fetchone()
            revoked = conn.execute('SELECT * FROM revoked_tokens WHERE jti = ?', (jti,)).fetchone()
            conn.close()

            if revoked:
                return jsonify({'message': 'Token has been revoked'}), 401

            if session:
                db_login_time = dateutil.parser.parse(session[0])

                if db_login_time.tzinfo is None:
                    db_login_time = db_login_time.replace(tzinfo=timezone.utc)
                token_login_time = datetime.fromtimestamp(login_time, timezone.utc)

                logger.debug(f"db_login_time: {db_login_time}, token_login_time: {token_login_time}")

                tolerance = timedelta(seconds=1)
                if db_login_time > token_login_time + tolerance:
                    return jsonify({'message': 'Token has been revoked'}), 401

            return fn(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error processing token: {e}", exc_info=True)
            return jsonify({"msg": "Error processing token"}), 500
    return wrapper

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
            # user_dict = {key: user[key] for key in user.keys()}
            # user_dict = dict(user)  # Add this line to convert the row to a dictionary

            print(user)
            access_token = create_access_token(identity={'id': user[0], 'username': user[1], 'isAdmin': user[3]})
            login_time = datetime.now(timezone.utc) # Use datetime.now(timezone.utc)
            conn = get_db_connection()
            existing_session = conn.execute('SELECT * FROM active_sessions WHERE user_id = ?', (user[0],)).fetchone()
            
            if existing_session:
                conn.execute('DELETE FROM active_sessions WHERE user_id = ?', (user[0],))
            
            conn.execute('INSERT INTO active_sessions (user_id, access_token, login_time) VALUES (?, ?, ?)', (user[0], access_token, login_time))
            conn.commit()
            conn.close()
            
            logger.debug(f'Login successful for user: {username}')
            return jsonify({'message': 'Login successful', 'access_token': access_token})
        else:
            logger.warning(f'Invalid login attempt for username: {username}')
            return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Error during login: {e}", exc_info=True)
        return jsonify({'message': 'An error occurred during login'}), 500


# @app.route('/logout', methods=['POST'])
# @token_required
# def logout():
#     user = get_jwt_identity()
#     conn = get_db_connection()
#     conn.execute('DELETE FROM active_sessions WHERE user_id = ?', (user['id'],))
#     conn.commit()
#     conn.close()
#     return jsonify({'message': 'Logged out successfully'})

@app.route('/logout', methods=['POST'])
@token_required
def logout():
    user = get_jwt_identity()
    jwt_data = get_jwt()
    jti = jwt_data['jti']  # JWT ID

    conn = get_db_connection()
    conn.execute('DELETE FROM active_sessions WHERE user_id = ?', (user['id'],))
    conn.execute('INSERT INTO revoked_tokens (jti) VALUES (?)', (jti,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Logged out successfully'})

@app.route('/active_sessions', methods=['GET'])
# @token_required
def view_active_sessions():
    # user = get_jwt_identity()
    # logger.debug(f"User: {user} requested to view active sessions")

    try:
        conn = get_db_connection()
        sessions = conn.execute('SELECT * FROM active_sessions').fetchall()
        conn.close()

        response = [dict(session) for session in sessions]
        logger.debug(f"Active sessions: {response}")
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error retrieving active sessions: {e}")
        return jsonify({"error": "An error occurred while retrieving active sessions"}), 500

@app.route('/active_sessions', methods=['DELETE'])
# @token_required
def clear_active_sessions():
    # user = get_jwt_identity()
    # logger.debug(f"User: {user} requested to clear all active sessions")

    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM active_sessions')
        conn.commit()
        conn.close()

        logger.debug("All active sessions cleared")
        return jsonify({'message': 'All active sessions cleared'})
    except Exception as e:
        logger.error(f"Error clearing active sessions: {e}")
        return jsonify({"error": "An error occurred while clearing active sessions"}), 500


@app.route('/families', methods=['GET'])
@token_required
def get_families():
    user = get_jwt_identity()
    print(user)
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
        # families = cursor
        # column_names = [description[0] for description in cursor.description]
        conn.close()

        # Fetch total count of families
        conn = get_db_connection()
        total_families = conn.execute('SELECT COUNT(*) FROM families').fetchone()[0]
        conn.close()

        # # Convert each family row to a dictionary
        # families_list = [
        #     {key: family[idx] for idx, key in enumerate(family.keys())}
        #     for family in families
        # ]

                # Convert each family row to a dictionary
       
        # families_list = []
        # families_list = [
        # dict(zip(column_names, family))
        # for family in families]   

        # for family in families:
        #     family_dict = {desc[0]: value for desc, value in zip(family.description, family)}
        #     families_list.append(family_dict)
        response = {
            'page': page,
            'per_page': per_page,
            'total': total_families,
            'families': [dict(family) for family in families]
            # 'families': families_list
        }

        logger.debug(f"Response for /families: {response}")
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error retrieving families: {e}")
        return jsonify({"error": "An error occurred while retrieving families"}), 500


@app.route('/families/<int:id>', methods=['GET'])
@token_required
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
@token_required
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
