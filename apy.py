from flask import Flask, request, jsonify, send_from_directory, abort
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import webbrowser
import json
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

DB_NAME = 'dormfinder.db'

# ── Admin account (stored in the users table, password is hashed) ──
ADMIN_EMAIL = 'admin@gmail.com'          # sign in with Admin@gmail.com (emails are case-insensitive here)
ADMIN_PASSWORD = 'admin123'
ADMIN_NAME = 'Admin'

# Used to sign the admin login token. Set DORMFINDER_SECRET in your environment for real use.
TOKEN_SECRET = os.environ.get('DORMFINDER_SECRET', 'dormfinder-dev-secret-change-me')
token_serializer = URLSafeTimedSerializer(TOKEN_SECRET)
TOKEN_MAX_AGE = 60 * 60 * 12  # 12 hours

@app.before_request
def block_private_files():
    # static_folder='.' would otherwise let anyone download the database and the source code
    if request.path.lower().endswith(('.db', '.py', '.sqlite', '.sqlite3')):
        abort(404)

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get('Authorization', '')
        token = header[7:] if header.startswith('Bearer ') else ''
        try:
            payload = token_serializer.loads(token, max_age=TOKEN_MAX_AGE)
        except (BadSignature, SignatureExpired):
            return jsonify({'success': False, 'message': 'Admin sign-in required.'}), 401
        if payload.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Admin access only.'}), 403
        return fn(*args, **kwargs)
    return wrapper

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
    
    # Reviews table (star rating + comment + recommend, one review per user per property)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property_id INTEGER NOT NULL,
            user_email TEXT NOT NULL,
            user_name TEXT NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT,
            recommend INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(property_id, user_email)
        )
    ''')

    # Migration: add columns for the map pin and extra photos to older databases
    cursor.execute('PRAGMA table_info(properties)')
    existing_cols = [c[1] for c in cursor.fetchall()]
    for col, ddl in (('lat', 'REAL'), ('lon', 'REAL'), ('images', 'TEXT')):
        if col not in existing_cols:
            cursor.execute(f'ALTER TABLE properties ADD COLUMN {col} {ddl}')

    # Migration: admin approval. Listings that already existed are treated as approved
    # so they don't disappear; every new listing starts as 'pending'.
    if 'status' not in existing_cols:
        cursor.execute("ALTER TABLE properties ADD COLUMN status TEXT DEFAULT 'pending'")
        cursor.execute("UPDATE properties SET status = 'approved'")
    for col, ddl in (('review_note', 'TEXT'), ('created_at', 'TEXT'), ('reviewed_at', 'TEXT')):
        if col not in existing_cols:
            cursor.execute(f'ALTER TABLE properties ADD COLUMN {col} {ddl}')

    # Seed / refresh the admin account in the database
    admin_hash = generate_password_hash(ADMIN_PASSWORD)
    cursor.execute('SELECT id FROM users WHERE email = ?', (ADMIN_EMAIL,))
    if cursor.fetchone():
        cursor.execute("UPDATE users SET role = 'admin', password = ?, fullname = ? WHERE email = ?",
                       (admin_hash, ADMIN_NAME, ADMIN_EMAIL))
    else:
        cursor.execute(
            'INSERT INTO users (fullname, email, password, role, phone, address, bio) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (ADMIN_NAME, ADMIN_EMAIL, admin_hash, 'admin', '', '', ''))

    conn.commit()
    conn.close()

@app.route('/')
def serve_homepage():
    return send_from_directory('.', 'index.html')

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    fullname = data.get('fullname', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', 'student')
    if role not in ('student', 'owner'):   # nobody can sign themselves up as admin
        role = 'student'

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

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT fullname, email, password, role, phone, address, bio FROM users WHERE email = ?', (email,))
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row[2], password):
        user = {
            'name': row[0],
            'email': row[1],
            'role': row[3],
            'phone': row[4] or '',
            'address': row[5] or '',
            'bio': row[6] or ''
        }
        if row[3] == 'admin':
            user['token'] = token_serializer.dumps({'email': row[1], 'role': 'admin'})
        return jsonify({'success': True, 'user': user})
    
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
               p.description, p.rules, p.amenities, p.image, p.lat, p.lon, p.images,
               p.status, p.review_note, p.created_at,
               rv.avg_rating, rv.review_count, rv.rec_count
        FROM properties p
        LEFT JOIN users u ON p.owner_email = u.email
        LEFT JOIN (
            SELECT property_id, AVG(rating) AS avg_rating, COUNT(*) AS review_count, SUM(recommend) AS rec_count
            FROM reviews GROUP BY property_id
        ) rv ON rv.property_id = p.id
    '''
    
    if owner_email:
        # an owner sees all of their own listings, including pending / rejected ones
        cursor.execute(query + ' WHERE p.owner_email = ? ORDER BY p.id DESC', (owner_email,))
    else:
        # everyone else (homepage, browse page, students) only sees admin-approved listings
        cursor.execute(query + " WHERE p.status = 'approved' ORDER BY p.id DESC")
    
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
            'image': r[15],
            'lat': r[16],
            'lon': r[17],
            'images': json.loads(r[18]) if r[18] else ([r[15]] if r[15] else []),
            'status': r[19] or 'approved',
            'reviewNote': r[20] or '',
            'createdAt': r[21],
            'rating': round(r[22], 1) if r[22] else 0,
            'reviewCount': r[23] or 0,
            'recommendPct': round(100 * (r[24] or 0) / r[23]) if r[23] else 0
        })
    return jsonify({'success': True, 'properties': props})

@app.route('/api/properties', methods=['POST'])
def save_property():
    data = request.json
    owner_email = data.get('owner_email', '').strip().lower()
    prop_id = data.get('id')

    if not owner_email:
        return jsonify({'success': False, 'message': 'Owner email required.'}), 400

    name = (data.get('name') or '').strip()
    ptype = data.get('type') or 'Dormitory'
    address = data.get('address') or 'Minglanilla, Cebu'
    # The owner dashboard doesn't send a barangay, and the column is NOT NULL
    barangay = data.get('barangay') or 'Minglanilla'
    raw_rent = str(data.get('rawRent') or '').strip()
    rent = data.get('rent') or ''
    total_rooms = str(data.get('totalRooms') or '10')
    avail_rooms = str(data.get('availRooms') or '5')
    occupied = data.get('occupied') or '0/' + total_rooms
    desc = data.get('desc') or ''
    rules = data.get('rules') or ''
    amenities = ','.join(data.get('amenities') or [])
    images_list = data.get('images') or []
    image = data.get('image') or (images_list[0] if images_list else '')
    images_json = json.dumps(images_list)
    lat = data.get('lat')
    lon = data.get('lon')

    if not name or not raw_rent:
        return jsonify({'success': False, 'message': 'Property name and monthly rent are required.'}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        if prop_id:
            cursor.execute('''
                UPDATE properties SET name=?, type=?, address=?, barangay=?, raw_rent=?, rent=?, total_rooms=?, avail_rooms=?, occupied=?, description=?, rules=?, amenities=?, image=?, lat=?, lon=?, images=?,
                    status = CASE WHEN status = 'rejected' THEN 'pending' ELSE status END,
                    review_note = CASE WHEN status = 'rejected' THEN NULL ELSE review_note END
                WHERE id=? AND owner_email=?
            ''', (name, ptype, address, barangay, raw_rent, rent, total_rooms, avail_rooms, occupied, desc, rules, amenities, image, lat, lon, images_json, prop_id, owner_email))
            message = 'Property updated successfully!'
        else:
            cursor.execute('''
                INSERT INTO properties (owner_email, name, type, address, barangay, raw_rent, rent, total_rooms, avail_rooms, occupied, description, rules, amenities, image, lat, lon, images, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'))
            ''', (owner_email, name, ptype, address, barangay, raw_rent, rent, total_rooms, avail_rooms, occupied, desc, rules, amenities, image, lat, lon, images_json))
            message = 'Listing submitted! It will appear publicly once the admin approves it.'

        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Database error: {e}'}), 500

@app.route('/api/properties/<int:prop_id>', methods=['DELETE'])
def delete_property(prop_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM properties WHERE id = ?', (prop_id,))
    cursor.execute('DELETE FROM reviews WHERE property_id = ?', (prop_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Property deleted successfully!'})

# ── REVIEWS & RATINGS ────────────────────────────────────────────────────
def _review_summary(cursor, prop_ids):
    """Average, count, star distribution and % who recommend for one or more properties."""
    if not prop_ids:
        return {'average': 0, 'count': 0, 'distribution': {str(i): 0 for i in range(1, 6)}, 'recommendPct': 0}
    marks = ','.join('?' * len(prop_ids))
    cursor.execute(f'SELECT rating, recommend FROM reviews WHERE property_id IN ({marks})', tuple(prop_ids))
    rows = cursor.fetchall()
    dist = {str(i): 0 for i in range(1, 6)}
    for rating, _ in rows:
        dist[str(rating)] += 1
    count = len(rows)
    return {
        'average': round(sum(r[0] for r in rows) / count, 1) if count else 0,
        'count': count,
        'distribution': dist,
        'recommendPct': round(100 * sum(1 for r in rows if r[1]) / count) if count else 0
    }

@app.route('/api/properties/<int:prop_id>/reviews', methods=['GET'])
def get_property_reviews(prop_id):
    """Anyone can read the reviews. viewer_email only marks which review is the viewer's own."""
    viewer = request.args.get('viewer_email', '').strip().lower()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.id, r.user_email, COALESCE(u.fullname, r.user_name), r.rating, r.comment, r.recommend,
               r.created_at, r.updated_at,
               EXISTS(SELECT 1 FROM bookings b WHERE b.property_id = r.property_id
                      AND b.student_email = r.user_email AND b.status = 'approved')
        FROM reviews r
        LEFT JOIN users u ON u.email = r.user_email
        WHERE r.property_id = ?
        ORDER BY r.id DESC
    ''', (prop_id,))
    rows = cursor.fetchall()
    summary = _review_summary(cursor, [prop_id])
    conn.close()

    reviews = [{
        'id': r[0],
        'name': r[2],
        'rating': r[3],
        'comment': r[4] or '',
        'recommend': bool(r[5]),
        'created_at': r[6],
        'updated_at': r[7],
        'booked': bool(r[8]),
        'mine': bool(viewer) and r[1].strip().lower() == viewer   # reviewer emails are never sent to the browser
    } for r in rows]
    return jsonify({'success': True, 'reviews': reviews, 'summary': summary})

@app.route('/api/properties/<int:prop_id>/reviews', methods=['POST'])
def save_property_review(prop_id):
    """Create or update the signed-in user's review for a property (one review per user)."""
    data = request.json or {}
    email = (data.get('user_email') or '').strip().lower()
    comment = (data.get('comment') or '').strip()[:1000]
    recommend = 1 if data.get('recommend', True) else 0
    try:
        rating = int(data.get('rating'))
    except (TypeError, ValueError):
        rating = 0

    if not email:
        return jsonify({'success': False, 'message': 'Please sign in to leave a review.'}), 401
    if rating < 1 or rating > 5:
        return jsonify({'success': False, 'message': 'Please choose a rating from 1 to 5 stars.'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('SELECT fullname, role FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'success': False, 'message': 'Please sign in to leave a review.'}), 401
    if user[1] == 'admin':
        conn.close()
        return jsonify({'success': False, 'message': 'Admin accounts cannot post reviews.'}), 403

    cursor.execute("SELECT owner_email FROM properties WHERE id = ? AND status = 'approved'", (prop_id,))
    prop = cursor.fetchone()
    if not prop:
        conn.close()
        return jsonify({'success': False, 'message': 'Property not found.'}), 404
    if (prop[0] or '').strip().lower() == email:
        conn.close()
        return jsonify({'success': False, 'message': 'You cannot review your own property.'}), 403

    cursor.execute('SELECT id FROM reviews WHERE property_id = ? AND user_email = ?', (prop_id, email))
    existing = cursor.fetchone()
    if existing:
        cursor.execute('''
            UPDATE reviews SET rating = ?, comment = ?, recommend = ?, user_name = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (rating, comment, recommend, user[0], existing[0]))
        message = 'Your review was updated.'
    else:
        cursor.execute('''
            INSERT INTO reviews (property_id, user_email, user_name, rating, comment, recommend)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (prop_id, email, user[0], rating, comment, recommend))
        message = 'Thanks! Your review was posted.'

    conn.commit()
    summary = _review_summary(cursor, [prop_id])
    conn.close()
    return jsonify({'success': True, 'message': message, 'summary': summary})

@app.route('/api/reviews/<int:review_id>', methods=['DELETE'])
def delete_review(review_id):
    """A user can delete their own review (an admin can delete any)."""
    data = request.get_json(silent=True) or {}
    email = (data.get('user_email') or '').strip().lower()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user_email, property_id FROM reviews WHERE id = ?', (review_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'message': 'Review not found.'}), 404

    cursor.execute('SELECT role FROM users WHERE email = ?', (email,))
    u = cursor.fetchone()
    if not email or not u or (row[0].strip().lower() != email and u[0] != 'admin'):
        conn.close()
        return jsonify({'success': False, 'message': 'You can only delete your own review.'}), 403

    cursor.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
    conn.commit()
    summary = _review_summary(cursor, [row[1]])
    conn.close()
    return jsonify({'success': True, 'message': 'Review deleted.', 'summary': summary})

@app.route('/api/reviews', methods=['GET'])
def get_owner_reviews():
    """All reviews written about the properties of one owner (for the owner dashboard)."""
    owner_email = request.args.get('owner_email', '').strip().lower()
    if not owner_email:
        return jsonify({'success': False, 'message': 'owner_email required'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM properties WHERE owner_email = ?', (owner_email,))
    prop_ids = [r[0] for r in cursor.fetchall()]

    reviews = []
    if prop_ids:
        marks = ','.join('?' * len(prop_ids))
        cursor.execute(f'''
            SELECT r.id, r.property_id, p.name, COALESCE(u.fullname, r.user_name), r.rating, r.comment,
                   r.recommend, r.created_at
            FROM reviews r
            JOIN properties p ON p.id = r.property_id
            LEFT JOIN users u ON u.email = r.user_email
            WHERE r.property_id IN ({marks})
            ORDER BY r.id DESC
        ''', tuple(prop_ids))
        reviews = [{
            'id': r[0], 'property_id': r[1], 'property_name': r[2], 'name': r[3],
            'rating': r[4], 'comment': r[5] or '', 'recommend': bool(r[6]), 'created_at': r[7]
        } for r in cursor.fetchall()]

    summary = _review_summary(cursor, prop_ids)
    conn.close()
    return jsonify({'success': True, 'reviews': reviews, 'summary': summary})

# ── ADMIN APIs (need the token returned when the admin signs in) ──────────
@app.route('/api/admin/properties', methods=['GET'])
@admin_required
def admin_get_properties():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT p.id, p.owner_email, u.fullname, p.name, p.type, p.address, p.raw_rent, p.rent,
               p.total_rooms, p.avail_rooms, p.occupied, p.description, p.rules, p.amenities,
               p.image, p.lat, p.lon, p.images, p.status, p.review_note, p.created_at, p.reviewed_at
        FROM properties p
        LEFT JOIN users u ON p.owner_email = u.email
        ORDER BY CASE p.status WHEN 'pending' THEN 0 ELSE 1 END, p.id DESC
    ''')
    rows = cursor.fetchall()
    conn.close()

    props = []
    for r in rows:
        props.append({
            'id': r[0], 'owner_email': r[1], 'owner_name': r[2] or 'Property Owner',
            'name': r[3], 'type': r[4], 'address': r[5], 'rawRent': r[6], 'rent': r[7],
            'totalRooms': r[8], 'availRooms': r[9], 'occupied': r[10],
            'desc': r[11], 'rules': r[12],
            'amenities': r[13].split(',') if r[13] else [],
            'image': r[14], 'lat': r[15], 'lon': r[16],
            'images': json.loads(r[17]) if r[17] else ([r[14]] if r[14] else []),
            'status': r[18] or 'approved', 'reviewNote': r[19] or '',
            'createdAt': r[20], 'reviewedAt': r[21]
        })
    return jsonify({'success': True, 'properties': props})

@app.route('/api/admin/properties/<int:prop_id>/review', methods=['POST'])
@admin_required
def admin_review_property(prop_id):
    data = request.json or {}
    status = data.get('status')
    note = (data.get('note') or '').strip()

    if status not in ('approved', 'rejected', 'pending'):
        return jsonify({'success': False, 'message': 'Invalid status.'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE properties SET status = ?, review_note = ?, reviewed_at = datetime('now') WHERE id = ?",
        (status, note if status == 'rejected' else None, prop_id))
    changed = cursor.rowcount
    conn.commit()
    conn.close()

    if not changed:
        return jsonify({'success': False, 'message': 'Listing not found.'}), 404
    return jsonify({'success': True, 'message': f'Listing {status}.'})

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, fullname, email, role, phone FROM users ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    return jsonify({'success': True, 'users': [
        {'id': r[0], 'name': r[1], 'email': r[2], 'role': r[3], 'phone': r[4] or ''} for r in rows
    ]})

@app.route('/api/admin/bookings', methods=['GET'])
@admin_required
def admin_get_bookings():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, property_name, room_name, student_name, student_email, owner_email,
               move_in_date, rent, status, created_at
        FROM bookings ORDER BY id DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return jsonify({'success': True, 'bookings': [
        {'id': r[0], 'property_name': r[1], 'room_name': r[2], 'student_name': r[3],
         'student_email': r[4], 'owner_email': r[5], 'move_in_date': r[6], 'rent': r[7],
         'status': r[8], 'created_at': r[9]} for r in rows
    ]})

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
        # JOIN owner + property so the student can open the booking and see who the owner is
        cursor.execute('''
            SELECT b.id, b.property_name, b.room_name, b.student_name, b.move_in_date, b.message,
                   b.rent, b.status, b.created_at,
                   b.property_id, b.owner_email, uo.fullname, uo.phone, p.address, p.image
            FROM bookings b
            LEFT JOIN users uo ON uo.email = b.owner_email
            LEFT JOIN properties p ON p.id = b.property_id
            WHERE b.student_email = ? ORDER BY b.id DESC
        ''', (student_email,))
    elif owner_email:
        # LEFT JOIN users so the owner can open the student's profile (phone / address / bio)
        cursor.execute('''
            SELECT b.id, b.property_name, b.room_name, b.student_name, b.student_email, b.move_in_date,
                   b.message, b.rent, b.status, b.created_at, b.property_id,
                   u.phone, u.address, u.bio
            FROM bookings b
            LEFT JOIN users u ON u.email = b.student_email
            WHERE b.owner_email = ? ORDER BY b.id DESC
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
                'created_at': r[8],
                'property_id': r[9],
                'owner_email': r[10],
                'owner_name': r[11] or 'Property Owner',
                'owner_phone': r[12] or '',
                'property_address': r[13] or '',
                'property_image': r[14] or ''
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
                'created_at': r[9],
                'property_id': r[10],
                'student_phone': r[11] or '',
                'student_address': r[12] or '',
                'student_bio': r[13] or ''
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

@app.route('/api/bookings/<int:booking_id>/cancel', methods=['POST'])
def cancel_booking(booking_id):
    """A student cancels their own booking. Only allowed while it is still pending (not yet approved)."""
    data = request.json or {}
    student_email = (data.get('student_email') or '').strip().lower()
    if not student_email:
        return jsonify({'success': False, 'message': 'Student email required.'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT student_email, status FROM bookings WHERE id = ?', (booking_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({'success': False, 'message': 'Booking not found.'}), 404
    if row[0].strip().lower() != student_email:
        conn.close()
        return jsonify({'success': False, 'message': 'You can only cancel your own bookings.'}), 403
    if row[1] != 'pending':
        conn.close()
        if row[1] == 'approved':
            msg = 'This booking was already approved by the owner and can no longer be cancelled.'
        else:
            msg = f'This booking is already {row[1]} and cannot be cancelled.'
        return jsonify({'success': False, 'message': msg}), 400

    cursor.execute("UPDATE bookings SET status = 'cancelled' WHERE id = ?", (booking_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Booking cancelled.'})

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