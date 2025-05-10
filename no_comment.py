import logging
from functools import wraps
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt
from flask_socketio import SocketIO, emit
import sqlite3
sqlite3.threadsafety = 3  # Allow shared connections

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
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_VERIFY_SUB'] = False # Add this line to disable `sub` claim verification


# change
# app.config['JWT_SECRET_KEY'] = '57a6a39a94d76c5cbbdec50f2a6ec31ba17b318f695d39750ee133a078fd128d'  # Change this to a random secret key



jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database connection function
def get_db_connection():
    # db_path = os.path.join(os.getenv('PERSISTENT_DISK_PATH', '/data'), 'aid_app.db')
    
    # change
    db_url = os.getenv('DATABASE_URL')
    conn = sqlitecloud.connect(db_url)
    
    return conn






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
    # timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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


def map_columns_to_dict(columns, row):
    return {columns[idx]: value for idx, value in enumerate(row)}


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
        cursor = conn.execute('SELECT * FROM families LIMIT ? OFFSET ?', (per_page, offset))
        families = cursor.fetchall()
        column_names = [description[0] for description in cursor.description]
        conn.close()

        # Fetch total count of families
        conn = get_db_connection()
        total_families = conn.execute('SELECT COUNT(*) FROM families').fetchone()[0]
        conn.close()
        families_list = [map_columns_to_dict(column_names, family) for family in families]
        # # Convert each family row to a dictionary
    
        response = {
            'page': page,
            'per_page': per_page,
            'total': total_families,
            # 'families': [dict(family) for family in families]
            'families': families_list
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
        
        # Set row factory before creating cursor
        conn.row_factory = lambda cursor, row: {
            col[0]: row[idx] for idx, col in enumerate(cursor.description)
        }
        
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM families WHERE id = ?', (id,))
        family = cursor.fetchone()
        cursor.close()
        conn.close()

        if family is None:
            logger.warning(f"Family with id {id} not found")
            return jsonify({"message": "Family not found"}), 404
        
        logger.debug(f"Response for /families/{id}: {family}")
        return jsonify(family)
        
    except Exception as e:
        logger.error(f"Error retrieving family {id}: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while retrieving the family"}), 500
    finally:
        if 'conn' in locals():
            conn.close()



@app.route('/families/<int:id>/products', methods=['PUT'])
@token_required
def update_products(id):
    user = get_jwt_identity()
    if not user:
        return jsonify({'message': 'Unauthorized'}), 401

    conn = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        conn = get_db_connection()
        conn.row_factory = lambda cursor, row: {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
        
        # Start transaction explicitly
        conn.execute('BEGIN TRANSACTION')
        
        # Get current values
        cursor = conn.execute('SELECT * FROM families WHERE id = ?', (id,))
        current_values = cursor.fetchone()
        if not current_values:
            conn.rollback()
            return jsonify({'message': 'Family not found'}), 404

        # Execute update
        conn.execute('''
            UPDATE families SET 
                milk = COALESCE(?, milk),
                diapers = COALESCE(?, diapers),
                basket = COALESCE(?, basket),
                clothing = COALESCE(?, clothing),
                drugs = COALESCE(?, drugs),
                other = COALESCE(?, other),
                taken = COALESCE(?, taken)
            WHERE id = ?
        ''', (
            data.get('milk'),
            data.get('diapers'),
            data.get('basket'),
            data.get('clothing'),
            data.get('drugs'),
            data.get('other'),
            data.get('taken'),
            id
        ))

        # Get updated values
        cursor = conn.execute('SELECT * FROM families WHERE id = ?', (id,))
        updated_values = cursor.fetchone()
        
        # Verify update succeeded
        if not updated_values:
            conn.rollback()
            return jsonify({'error': 'Update verification failed'}), 500

        # Get username
        cursor = conn.execute('SELECT username FROM users WHERE id = ?', (user['id'],))
        user_info = cursor.fetchone()
        username = user_info['username'] if user_info else 'Unknown'

        # Commit transaction
        conn.commit()

        # Calculate changes safely
        changes = {}
        for field in ['milk', 'diapers', 'basket', 'clothing', 'drugs', 'other', 'taken']:
            current_val = current_values.get(field)
            updated_val = updated_values.get(field)
            if current_val != updated_val:
                changes[field] = updated_val

        if changes:
            socketio.emit(
                'family_updated',
                {
                    'family_id': id,
                    'changes': changes,
                    'updated_by': {
                        'user_id': user['id'],
                        'username': username
                    },
                    'timestamp': datetime.now().isoformat()
                },
                namespace='/families',
                room=f'family_{id}'
            )

        return jsonify({'message': 'Product updated successfully'})

    except sqlite3.Error as e:
        if conn: conn.rollback()
        logger.error(f"Database error updating family {id}: {str(e)}")
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        if conn: conn.rollback()
        logger.error(f"Unexpected error updating family {id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception as e:
                logger.error(f"Error closing connection: {str(e)}")

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled Exception: {e}")
    return jsonify({"error": "An internal server error occurred"}), 500

if __name__ == '__main__':
    app.debug = True
    socketio.run(app, debug=True, use_reloader=False, host='0.0.0.0', port=5000)
