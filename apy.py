from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import webbrowser

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

DB_NAME = 'dormfinder.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Users table updated with phone, address, and bio columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            bio TEXT
        )
    ''')
    
    # Properties table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS properties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_email TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            address TEXT NOT NULL,
            barangay TEXT NOT NULL,
            raw_rent TEXT NOT NULL,
            rent TEXT NOT NULL,
            total_rooms TEXT NOT NULL,
            avail_rooms TEXT NOT NULL,
            occupied TEXT NOT NULL,
            description TEXT,
            rules TEXT,
            amenities TEXT,
            image TEXT,
            FOREIGN KEY (owner_email) REFERENCES users (email)
        )
    ''')
    
    # Bookings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property_id INTEGER NOT NULL,
            property_name TEXT NOT NULL,
            room_name TEXT NOT NULL,
            student_name TEXT NOT NULL,
            student_email TEXT NOT NULL,
            owner_email TEXT NOT NULL,
            move_in_date TEXT NOT NULL,
            message TEXT,
            rent TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (property_id) REFERENCES properties (id),
            FOREIGN KEY (student_email) REFERENCES users (email),
            FOREIGN KEY (owner_email) REFERENCES users (email)
        )
    ''')

    # Messages table (for the split-screen conversation inbox)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property_id INTEGER,
            property_name TEXT,
            sender_email TEXT NOT NULL,
            sender_name TEXT NOT NULL,
            receiver_email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

@app.route('/')
def serve_homepage():
    return send_from_directory('.', 'homepage.html')

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    fullname = data.get('fullname', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', 'student')

    if not fullname or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    hashed_password = generate_password_hash(password)

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (fullname, email, password, role, phone, address, bio) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (fullname, email, hashed_password, role, '', '', '')
        )
        conn.commit()
        conn.close()
        return jsonify({
            'success': True, 
            'message': 'Account created successfully!',
            'user': {'name': fullname, 'email': email, 'role': role, 'phone': '', 'address': '', 'bio': ''}
        })
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Email already exists. Please sign in.'}), 400

@app.route('/api/signin', methods=['POST'])
def api_signin():
    data = request.json
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if email == 'admin@dormfinder.com' and password == 'admin123':
        return jsonify({
            'success': True,
            'user': {'name': 'System Administrator', 'email': email, 'role': 'admin', 'phone': '', 'address': '', 'bio': ''}
        })

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT fullname, email, password, role, phone, address, bio FROM users WHERE email = ?', (email,))
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row[2], password):
        return jsonify({
            'success': True,
            'user': {
                'name': row[0],
                'email': row[1],
                'role': row[3],
                'phone': row[4] or '',
                'address': row[5] or '',
                'bio': row[6] or ''
            }
        })
    
    return jsonify({'success': False, 'message': 'Invalid email or password.'}), 401

@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    data = request.json
    email = data.get('email', '').strip().lower()
    new_fullname = data.get('fullname', '').strip()
    phone = data.get('phone', '').strip()
    address = data.get('address', '').strip()
    bio = data.get('bio', '').strip()

    if not email or not new_fullname:
        return jsonify({'success': False, 'message': 'Email and full name are required.'}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users 
            SET fullname = ?, phone = ?, address = ?, bio = ? 
            WHERE email = ?
        ''', (new_fullname, phone, address, bio, email))
        conn.commit()

        cursor.execute('SELECT fullname, email, role, phone, address, bio FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return jsonify({'success': False, 'message': 'User not found.'}), 404

        return jsonify({
            'success': True,
            'message': 'Profile updated successfully!',
            'user': {
                'name': row[0],
                'email': row[1],
                'role': row[2],
                'phone': row[3] or '',
                'address': row[4] or '',
                'bio': row[5] or ''
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ── PROPERTY APIs ──────────────────────────────────────────
@app.route('/api/properties', methods=['GET'])
def get_properties():
    owner_email = request.args.get('email', '').strip().lower()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    query = '''
        SELECT p.id, p.owner_email, u.fullname, p.name, p.type, p.address, p.barangay, 
               p.raw_rent, p.rent, p.total_rooms, p.avail_rooms, p.occupied, 
               p.description, p.rules, p.amenities, p.image 
        FROM properties p
        LEFT JOIN users u ON p.owner_email = u.email
    '''
    
    if owner_email:
        cursor.execute(query + ' WHERE p.owner_email = ?', (owner_email,))
    else:
        cursor.execute(query)
    
    rows = cursor.fetchall()
    conn.close()

    props = []
    for r in rows:
        props.append({
            'id': r[0],
            'owner_email': r[1],
            'owner_name': r[2] if r[2] else 'Property Owner',
            'name': r[3],
            'type': r[4],
            'address': r[5],
            'barangay': r[6],
            'rawRent': r[7],
            'rent': r[8],
            'totalRooms': r[9],
            'availRooms': r[10],
            'occupied': r[11],
            'desc': r[12],
            'rules': r[13],
            'amenities': r[14].split(',') if r[14] else [],
            'image': r[15]
        })
    return jsonify({'success': True, 'properties': props})

@app.route('/api/properties', methods=['POST'])
def save_property():
    data = request.json
    owner_email = data.get('owner_email', '').strip().lower()
    prop_id = data.get('id')

    if not owner_email:
        return jsonify({'success': False, 'message': 'Owner email required.'}), 400

    name = data.get('name')
    ptype = data.get('type')
    address = data.get('address')
    barangay = data.get('barangay')
    raw_rent = data.get('rawRent')
    rent = data.get('rent')
    total_rooms = data.get('totalRooms')
    avail_rooms = data.get('availRooms')
    occupied = data.get('occupied')
    desc = data.get('desc')
    rules = data.get('rules')
    amenities = ','.join(data.get('amenities', []))
    image = data.get('image')

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    if prop_id:
        cursor.execute('''
            UPDATE properties SET name=?, type=?, address=?, barangay=?, raw_rent=?, rent=?, total_rooms=?, avail_rooms=?, occupied=?, description=?, rules=?, amenities=?, image=?
            WHERE id=? AND owner_email=?
        ''', (name, ptype, address, barangay, raw_rent, rent, total_rooms, avail_rooms, occupied, desc, rules, amenities, image, prop_id, owner_email))
    else:
        cursor.execute('''
            INSERT INTO properties (owner_email, name, type, address, barangay, raw_rent, rent, total_rooms, avail_rooms, occupied, description, rules, amenities, image)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (owner_email, name, ptype, address, barangay, raw_rent, rent, total_rooms, avail_rooms, occupied, desc, rules, amenities, image))

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Property saved successfully!'})

@app.route('/api/properties/<int:prop_id>', methods=['DELETE'])
def delete_property(prop_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM properties WHERE id = ?', (prop_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Property deleted successfully!'})

# ── BOOKING APIs ──────────────────────────────────────────
@app.route('/api/bookings', methods=['POST'])
def create_booking():
    data = request.json
    property_id = data.get('property_id')
    property_name = data.get('property_name')
    room_name = data.get('room_name')
    student_name = data.get('student_name')
    student_email = data.get('student_email', '').strip().lower()
    owner_email = data.get('owner_email', '').strip().lower()
    move_in_date = data.get('move_in_date')
    message = data.get('message', '')
    rent = data.get('rent')

    if not property_id or not student_email or not owner_email or not move_in_date:
        return jsonify({'success': False, 'message': 'Missing required booking details.'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO bookings (property_id, property_name, room_name, student_name, student_email, owner_email, move_in_date, message, rent, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    ''', (property_id, property_name, room_name, student_name, student_email, owner_email, move_in_date, message, rent))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Booking request submitted successfully!'})

@app.route('/api/bookings', methods=['GET'])
def get_bookings():
    student_email = request.args.get('student_email', '').strip().lower()
    owner_email = request.args.get('owner_email', '').strip().lower()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    if student_email:
        cursor.execute('''
            SELECT id, property_name, room_name, student_name, move_in_date, message, rent, status, created_at 
            FROM bookings WHERE student_email = ? ORDER BY id DESC
        ''', (student_email,))
    elif owner_email:
        cursor.execute('''
            SELECT id, property_name, room_name, student_name, student_email, move_in_date, message, rent, status, created_at 
            FROM bookings WHERE owner_email = ? ORDER BY id DESC
        ''', (owner_email,))
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'Email parameters required.'}), 400

    rows = cursor.fetchall()
    conn.close()

    bookings = []
    for r in rows:
        if student_email:
            bookings.append({
                'id': r[0],
                'property_name': r[1],
                'room_name': r[2],
                'student_name': r[3],
                'move_in_date': r[4],
                'message': r[5],
                'rent': r[6],
                'status': r[7],
                'created_at': r[8]
            })
        else:
            bookings.append({
                'id': r[0],
                'property_name': r[1],
                'room_name': r[2],
                'student_name': r[3],
                'student_email': r[4],
                'move_in_date': r[5],
                'message': r[6],
                'rent': r[7],
                'status': r[8],
                'created_at': r[9]
            })

    return jsonify({'success': True, 'bookings': bookings})

@app.route('/api/bookings/<int:booking_id>/status', methods=['POST'])
def update_booking_status(booking_id):
    data = request.json
    new_status = data.get('status')

    if new_status not in ['approved', 'rejected']:
        return jsonify({'success': False, 'message': 'Invalid status.'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('UPDATE bookings SET status = ? WHERE id = ?', (new_status, booking_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': f'Booking request {new_status}!'})

# ── MESSAGING APIs ────────────────────────────────────────
@app.route('/api/messages', methods=['POST'])
def send_message():
    data = request.json
    property_id = data.get('property_id')
    property_name = data.get('property_name', 'General Inquiry')
    sender_email = data.get('sender_email', '').strip().lower()
    sender_name = data.get('sender_name', 'User')
    receiver_email = data.get('receiver_email', '').strip().lower()
    message = data.get('message', '').strip()

    if not sender_email or not receiver_email or not message:
        return jsonify({'success': False, 'message': 'Missing required message fields.'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO messages (property_id, property_name, sender_email, sender_name, receiver_email, message)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (property_id, property_name, sender_email, sender_name, receiver_email, message))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Message sent successfully!'})

@app.route('/api/messages', methods=['GET'])
def get_messages():
    user_email = request.args.get('email', '').strip().lower()
    if not user_email:
        return jsonify({'success': False, 'message': 'Email parameter required.'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, property_id, property_name, sender_email, sender_name, receiver_email, message, created_at
        FROM messages 
        WHERE sender_email = ? OR receiver_email = ?
        ORDER BY created_at ASC
    ''', (user_email, user_email))
    rows = cursor.fetchall()
    conn.close()

    msgs = []
    for r in rows:
        msgs.append({
            'id': r[0],
            'property_id': r[1],
            'property_name': r[2],
            'sender_email': r[3],
            'sender_name': r[4],
            'receiver_email': r[5],
            'message': r[6],
            'created_at': r[7]
        })
    return jsonify({'success': True, 'messages': msgs})

if __name__ == '__main__':
    init_db()
    webbrowser.open_new('http://127.0.0.1:5000/')
    print('Starting Dorm Finder database server...')
    app.run(host='127.0.0.1', port=5000, debug=True)