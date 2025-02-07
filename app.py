from collections import defaultdict
from itertools import groupby

from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
import sqlite3
import os
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for flashing messages

VALID_STORES = [
    "Kusan Uyghur Cuisine, 1516 N 4th Street, San Jose, CA 95112",
    "Kusan Bazaar, 510 Barber Ln, Milpitas, CA 95035"
]
    
# Database configuration
DATABASE = 'stock_manager.db'


# Define the upload folder
UPLOAD_FOLDER = 'static/uploads'  # Path to the folder where uploaded files will be saved
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed file extensions

# Configure the Flask app
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit file size to 16MB

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Helper function to validate file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        # Add 'is_authorized' column only if it doesn't exist
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN is_authorized INTEGER DEFAULT 0")
            print("Added 'is_authorized' column.")
        except sqlite3.OperationalError:
            print("'is_authorized' column already exists.")

        # Create tables with proper store_address fields
        cursor.execute('''CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            category TEXT,
            max_stock_level INTEGER,
            in_stock_level INTEGER,
            reorder_level INTEGER,
            picture TEXT,
            supplier TEXT,
            store_address TEXT NOT NULL  -- Store-specific items
        )''')

        # Keep original categories table structure
        cursor.execute('''CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            employee_name TEXT,
            store_address TEXT NOT NULL,  -- Store assignment
            role TEXT NOT NULL CHECK(role IN ('owner', 'employee', 'manager', 'server', 'line_cook', 'prep_cook')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            phone_number TEXT DEFAULT NULL,
            email TEXT DEFAULT NULL
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS stock_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            stock_before INTEGER NOT NULL,
            stock_after INTEGER NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            store_address TEXT NOT NULL,  -- Track store context
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (item_id) REFERENCES items(id)
        )''')

        # Default data setup
        cursor.execute('INSERT OR IGNORE INTO categories (name) VALUES (?)', ("Default",))

        # Create default owner with valid store address
        cursor.execute('SELECT COUNT(*) FROM users')
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO users (
                    username, password, employee_name, 
                    store_address, phone_number, email, 
                    role, is_authorized
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                "owner",
                "ownerpass",
                "Owner Name",
                "Kusan Uyghur Cuisine, 1516 N 4th Street, San Jose, CA 95112",
                "1234567890",
                "owner@example.com",
                "owner",
                1
            ))

        # Ensure all owners are authorized
        cursor.execute('UPDATE users SET is_authorized = 1 WHERE role = "owner"')
        conn.commit()

# Auto-initialize database when the app starts
with app.app_context():
    init_db()  # Checks and creates tables if missing

# Route for the login page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, role, store_address, is_authorized 
                    FROM users 
                    WHERE username = ? AND password = ?
                ''', (username, password))
                user = cursor.fetchone()

                if not user:
                    return render_template('userlogin.html',
                         error_message='Invalid username or password')

                if user['is_authorized'] == 0:
                    return render_template('userlogin.html',
                         error_message='Account pending authorization')

                # Store critical user info in session
                session.update({
                    'user_id': user['id'],
                    'role': user['role'],
                    'store_address': user['store_address'],
                    'authorized': True
                })

                # Debug log
                print(f"User {username} ({user['role']}) logged in to {user['store_address']}")

                # Redirect based on role with proper access control
                if user['role'] == 'owner':
                    return redirect(url_for('owner_dashboard'))
                elif user['role'] == 'manager':
                    return redirect(url_for('manager_dashboard'))
                else:
                    return redirect(url_for('employee_dashboard'))

        except Exception as e:
            return render_template('userlogin.html',
                 error_message=f'Login error: {str(e)}')

    return render_template('userlogin.html')


# Route for registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    VALID_STORES = [
        "Kusan Uyghur Cuisine, 1516 N 4th Street, San Jose, CA 95112",
        "Kusan Bazaar, 510 Barber Ln, Milpitas, CA 95035"
    ]

    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'message': 'Invalid JSON format'}), 400

        required_fields = ['username', 'password', 'employee_name',
                           'phone_number', 'email', 'store_address']
        missing = [field for field in required_fields if (field not in data or not data.get(field))]
        if missing:
            return jsonify({'message': f'Missing fields: {", ".join(missing)}'}), 400

        # Validate store address
        if data['store_address'] not in VALID_STORES:
            return jsonify({'message': 'Invalid store selection'}), 400

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (
                        username, password, employee_name,
                        phone_number, email, store_address, 
                        role, is_authorized
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    data['username'],
                    data['password'],  # Use plain password directly
                    data['employee_name'],
                    data['phone_number'],
                    data['email'],
                    data['store_address'],
                    'employee',  # Default role
                    0  # Requires authorization
                ))
                conn.commit()
                return jsonify({
                    'message': 'Registration successful! Awaiting owner approval',
                    'store': data['store_address']
                }), 200

        except sqlite3.IntegrityError as e:
            error_msg = 'Database error occurred'
            if 'UNIQUE constraint failed: users.username' in str(e):
                error_msg = 'Username already exists'
            return jsonify({'message': f'Error: {error_msg}'}), 400

        except Exception as e:
            return jsonify({'message': f'Server error: {str(e)}'}), 500

    return render_template('register.html')


@app.route('/pending_accounts', methods=['GET'])
def pending_accounts():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Build query based on user role
        base_query = '''
            SELECT id, username, role, employee_name, 
                   store_address, phone_number, email 
            FROM users 
            WHERE is_authorized = 0
        '''
        params = []

        if session.get('role') != 'owner':
            base_query += ' AND store_address = ?'
            params.append(session.get('store_address'))

        cursor.execute(base_query, params)
        accounts = [dict(account) for account in cursor.fetchall()]

    return jsonify(accounts)


@app.route('/authorize_account/<int:account_id>', methods=['POST'])
def authorize_account(account_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Verify store access
        cursor.execute('SELECT store_address FROM users WHERE id = ?', (account_id,))
        account = cursor.fetchone()

        if not account:
            return jsonify({'message': 'Account not found'}), 404

        if session.get('role') != 'owner' and account['store_address'] != session.get('store_address'):
            return jsonify({'message': 'Unauthorized to modify this account'}), 403

        cursor.execute('UPDATE users SET is_authorized = 1 WHERE id = ?', (account_id,))
        conn.commit()

        return jsonify({'message': 'Account authorized successfully'}), 200


@app.route('/reject_account/<int:account_id>', methods=['POST'])
def reject_account(account_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Verify store access
        cursor.execute('SELECT store_address FROM users WHERE id = ?', (account_id,))
        account = cursor.fetchone()

        if not account:
            return jsonify({'message': 'Account not found'}), 404

        if session.get('role') != 'owner' and account['store_address'] != session.get('store_address'):
            return jsonify({'message': 'Unauthorized to modify this account'}), 403

        cursor.execute('DELETE FROM users WHERE id = ?', (account_id,))
        conn.commit()

        return jsonify({'message': 'Account rejected successfully'}), 200

# Route for the owner dashboard
@app.route('/owner_dashboard', methods=['GET', 'POST'])
def owner_dashboard():
    if session.get('role') != 'owner':
        return redirect(url_for('login'))  # Or show 403
    if request.method == 'POST':
        try:
            # Get form data including store selection
            name = request.form['name']
            category = request.form['category']
            max_stock_level = int(request.form['max_stock_level'])
            in_stock_level = int(request.form['in_stock_level'])
            reorder_level = int(request.form['reorder_level'])
            supplier = request.form['supplier']
            store_address = request.form['store_address']  # Get store from form

            # Handle file upload
            picture = request.files['picture']
            picture_path = None
            if picture and picture.filename:
                if not allowed_file(picture.filename):
                    flash('Invalid file type. Allowed types: png, jpg, jpeg, gif.', 'error')
                    return redirect(url_for('owner_dashboard'))

                filename = os.path.join(app.config['UPLOAD_FOLDER'], picture.filename)
                picture.save(filename)
                picture_path = filename

            # Save to database with store address
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO items (
                        name, category, max_stock_level, 
                        in_stock_level, reorder_level, 
                        picture, supplier, store_address
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    name, category, max_stock_level,
                    in_stock_level, reorder_level,
                    picture_path, supplier, store_address
                ))
                conn.commit()

            flash('Item saved successfully!', 'success')
            return redirect(url_for('owner_dashboard'))

        except KeyError as e:
            flash(f'Missing form field: {str(e)}', 'error')
            return redirect(url_for('owner_dashboard'))
        except sqlite3.IntegrityError as e:
            flash(f'Database error: {str(e)}', 'error')
            return redirect(url_for('owner_dashboard'))
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('owner_dashboard'))

    # Handle filtering for GET requests
    store_filter = request.args.get('store', '')
    query = 'SELECT * FROM items'
    params = []

    if store_filter:
        query += ' WHERE store_address = ?'
        params.append(store_filter)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        items = cursor.fetchall()

    # Get available stores for filtering
    VALID_STORES = [
        "Kusan Uyghur Cuisine, 1516 N 4th Street, San Jose, CA 95112",
        "Kusan Bazaar, 510 Barber Ln, Milpitas, CA 95035"
    ]

    return render_template('owner_dashboard.html',
                           items=items,
                           valid_stores=VALID_STORES,
                           selected_store=store_filter)


# Route for the employee dashboard
@app.route('/employee_dashboard')
def employee_dashboard():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        base_query = 'SELECT * FROM items'
        params = []

        if session.get('role') != 'owner':
            base_query += ' WHERE store_address = ?'
            params.append(session.get('store_address'))

        cursor.execute(base_query, params)
        items = cursor.fetchall()

    return render_template('employee_dashboard.html', items=items)


@app.route('/manager_dashboard')
def manager_dashboard():
    if session.get('role') != 'manager':
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        cursor = conn.cursor()

        base_query = 'SELECT * FROM items'
        params = []

        if session.get('role') != 'owner':
            base_query += ' WHERE store_address = ?'
            params.append(session.get('store_address'))

        cursor.execute(base_query, params)
        items = cursor.fetchall()

    return render_template('manager_dashboard.html', items=items)

# Route for managing categories
@app.route('/categories', methods=['GET', 'POST'])
def categories():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if request.method == 'POST':
            categories = request.json.get('categories', [])
            cursor.execute('DELETE FROM categories')
            for category in categories:
                cursor.execute('INSERT INTO categories (name) VALUES (?)', (category.strip(),))
            conn.commit()
            return jsonify({'message': 'Categories updated globally for all stores'})

        cursor.execute('SELECT name FROM categories')
        return jsonify([row['name'] for row in cursor.fetchall()])


# Route for managing accounts with multi-store support
@app.route('/accounts', methods=['GET', 'POST'])
def accounts():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Handle account deletion
        if request.method == 'POST':
            user_id = request.json.get('id')

            # Security validation
            cursor.execute('''
                SELECT store_address, role 
                FROM users 
                WHERE id = ?
            ''', (user_id,))
            target_account = cursor.fetchone()

            if not target_account:
                return jsonify({'message': 'Error: User does not exist.'}), 404

            # Get current user's permissions
            current_user_role = session.get('role')
            current_user_store = session.get('store_address')

            # Validate store access for non-owners
            if current_user_role != 'owner' and target_account['store_address'] != current_user_store:
                return jsonify({
                    'message': 'Unauthorized: Cannot modify accounts from other stores'
                }), 403

            # Prevent owner account deletion
            if target_account['role'] == 'owner':
                return jsonify({
                    'message': 'Error: Owner accounts cannot be deleted'
                }), 403

            # Delete account
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()

            return jsonify({'message': 'Account deleted successfully!'}), 200

        # Handle account listing
        if session.get('role') == 'owner':
            # Owner sees all accounts from all stores
            cursor.execute('''
                SELECT id, username, role, employee_name, 
                       store_address, phone_number, email 
                FROM users 
                WHERE is_authorized = 1
            ''')
            authorized_accounts = cursor.fetchall()

            cursor.execute('''
                SELECT id, username, role, employee_name,
                       store_address, phone_number, email 
                FROM users 
                WHERE is_authorized = 0
            ''')
            pending_accounts = cursor.fetchall()
        else:
            # Non-owners only see accounts from their store
            current_store = session.get('store_address')

            cursor.execute('''
                SELECT id, username, role, employee_name,
                       store_address, phone_number, email 
                FROM users 
                WHERE is_authorized = 1 
                AND store_address = ?
            ''', (current_store,))
            authorized_accounts = cursor.fetchall()

            cursor.execute('''
                SELECT id, username, role, employee_name,
                       store_address, phone_number, email 
                FROM users 
                WHERE is_authorized = 0 
                AND store_address = ?
            ''', (current_store,))
            pending_accounts = cursor.fetchall()

        # Format response data
        def format_account(account):
            return {
                'id': account['id'],
                'username': account['username'],
                'role': account['role'] if 'role' in account.keys() else 'N/A',  # Direct access + key check
                'employee_name': account['employee_name'] or 'N/A',
                'store_address': account['store_address'] or 'N/A',
                'phone_number': account['phone_number'] or 'N/A',
                'email': account['email'] or 'N/A',
            }

        return jsonify({
            'authorized_accounts': [format_account(a) for a in authorized_accounts],
            'pending_accounts': [format_account(p) for p in pending_accounts]
        })


@app.route('/update_account/<int:account_id>', methods=['POST'])
def update_account(account_id):
    VALID_STORES = [
        "Kusan Uyghur Cuisine, 1516 N 4th Street, San Jose, CA 95112",
        "Kusan Bazaar, 510 Barber Ln, Milpitas, CA 95035"
    ]

    data = request.json
    required_fields = ['username', 'role', 'employee_name', 'store_address', 'phone_number', 'email']

    # Validate input
    if any(field not in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400

    current_user_role = session.get('role')
    current_user_store = session.get('store_address')

    with get_db_connection() as conn:
        try:
            cursor = conn.cursor()

            # Verify account exists and get current store
            cursor.execute('''
                SELECT id, role, store_address FROM users 
                WHERE id = ?
            ''', (account_id,))
            target_account = cursor.fetchone()

            if not target_account:
                return jsonify({'message': 'Account not found'}), 404

            # Authorization checks
            if current_user_role != 'owner':
                # Non-owners can only edit accounts in their own store
                if target_account['store_address'] != current_user_store:
                    return jsonify({'message': 'Unauthorized to modify this account'}), 403

                # Prevent role elevation to owner
                if data['role'] == 'owner' and target_account['role'] != 'owner':
                    return jsonify({'message': 'Only owners can create owner accounts'}), 403

            # Owner-specific validation
            if current_user_role == 'owner':
                # Validate store address for owner edits
                if data['store_address'] not in VALID_STORES:
                    return jsonify({'message': 'Invalid store address'}), 400

                # Ensure at least one owner remains
                if target_account['role'] == 'owner' and data['role'] != 'owner':
                    cursor.execute('SELECT COUNT(*) FROM users WHERE role = "owner"')
                    if cursor.fetchone()[0] == 1:
                        return jsonify({'message': 'System must have at least one owner'}), 400

            # Build update parameters
            update_data = (
                data['username'],
                data['role'],
                data['employee_name'],
                data['store_address'],
                data['phone_number'],
                data['email'],
                account_id
            )

            # Optional password update
            password_clause = 'password = ?,' if data.get('password') else ''
            if data.get('password'):
                update_data = (data['password'],) + update_data

            cursor.execute(f'''
                UPDATE users SET 
                    username = ?, 
                    role = ?, 
                    employee_name = ?, 
                    store_address = ?, 
                    phone_number = ?, 
                    email = ?
                    {',' + password_clause if password_clause else ''}
                WHERE id = ?
            ''', update_data)

            conn.commit()

            if cursor.rowcount == 0:
                return jsonify({'message': 'No changes detected'}), 200

            return jsonify({'message': 'Account updated successfully'}), 200

        except sqlite3.IntegrityError as e:
            return jsonify({'message': 'Username already exists'}), 409
        except Exception as e:
            return jsonify({'message': f'Server error: {str(e)}'}), 500


@app.route('/items', methods=['GET'])
def get_items():
    base_query = 'SELECT * FROM items'
    filter_clauses = []
    params = []

    if session.get('role') != 'owner':
        # Non-owners only see their store's items
        filter_clauses.append('store_address = ?')
        params.append(session.get('store_address'))
    else:
        # Owners can filter by store if specified
        store_filter = request.args.get('store')
        if store_filter:
            filter_clauses.append('store_address = ?')
            params.append(store_filter)

    # Build final query
    if filter_clauses:
        base_query += ' WHERE ' + ' AND '.join(filter_clauses)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(base_query, params)
        items = cursor.fetchall()
        items_list = [dict(item) for item in items]

    return jsonify(items_list)


@app.route('/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    if not session.get('authorized'):
        return jsonify({'message': 'Unauthorized'}), 401

    current_user_role = session.get('role')
    current_user_store = session.get('store_address')

    with get_db_connection() as conn:
        try:
            cursor = conn.cursor()

            # Get item's store address
            cursor.execute('''
                SELECT store_address FROM items 
                WHERE id = ?
            ''', (item_id,))
            item = cursor.fetchone()

            if not item:
                return jsonify({'message': 'Item not found'}), 404

            # Store validation for non-owners
            if current_user_role != 'owner' and item['store_address'] != current_user_store:
                return jsonify({'message': 'Unauthorized to delete items from other stores'}), 403

            # Delete the item
            cursor.execute('DELETE FROM items WHERE id = ?', (item_id,))

            # Delete associated stock updates
            cursor.execute('DELETE FROM stock_updates WHERE item_id = ?', (item_id,))

            conn.commit()

            return jsonify({
                'message': f'Item {item_id} deleted successfully',
                'store_affected': item['store_address']
            }), 200

        except Exception as e:
            conn.rollback()
            return jsonify({'message': f'Deletion failed: {str(e)}'}), 500


@app.route('/update_item/<int:item_id>', methods=['POST'])
def update_item(item_id):
    # Authorization check
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role = session.get('role')
    current_store = session.get('store_address')

    with get_db_connection() as conn:
        try:
            cursor = conn.cursor()

            # Get existing item details
            cursor.execute('''
                SELECT store_address FROM items 
                WHERE id = ?
            ''', (item_id,))
            item = cursor.fetchone()

            if not item:
                return jsonify({'message': 'Item not found'}), 404

            # Store validation for non-owners
            if current_role != 'owner' and item['store_address'] != current_store:
                return jsonify({'message': 'Unauthorized to modify items from other stores'}), 403

            # Validate input data
            data = request.json
            required_fields = {
                'category': str,
                'max_stock_level': int,
                'in_stock_level': int,
                'reorder_level': int
            }

            if not all(field in data for field in required_fields):
                return jsonify({'message': 'Missing required fields'}), 400

            # Conversion and range validation
            try:
                category = str(data['category']).strip()
                max_stock = int(data['max_stock_level'])
                in_stock = int(data['in_stock_level'])
                reorder = int(data['reorder_level'])

                if not category or max_stock < 0 or in_stock < 0 or reorder < 0:
                    raise ValueError("Invalid field values")

                if reorder > max_stock:
                    return jsonify({'message': 'Reorder level must be less than max stock'}), 400

            except (ValueError, TypeError) as e:
                return jsonify({'message': 'Invalid input format'}), 400

            # Perform update with store validation
            cursor.execute('''
                UPDATE items SET
                    category = ?,
                    max_stock_level = ?,
                    in_stock_level = ?,
                    reorder_level = ?
                WHERE id = ? AND store_address = ?
            ''', (
                category,
                max_stock,
                in_stock,
                reorder,
                item_id,
                item['store_address']  # Ensures item hasn't moved since initial check
            ))

            conn.commit()

            if cursor.rowcount == 0:
                return jsonify({'message': 'No changes detected or item not found'}), 200

            return jsonify({'message': 'Item updated successfully'}), 200

        except sqlite3.IntegrityError as e:
            return jsonify({'message': 'Database constraint error'}), 500
        except Exception as e:
            return jsonify({'message': f'Server error: {str(e)}'}), 500


@app.route('/delete_stock_update/<int:record_id>', methods=['DELETE'])
def delete_stock_update(record_id):
    # Security validation
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role = session.get('role')
    current_store = session.get('store_address')

    with get_db_connection() as conn:
        try:
            cursor = conn.cursor()

            # 1. Get the stock update record and its store association
            cursor.execute('''
                SELECT s.store_address 
                FROM stock_updates s
                WHERE s.id = ?
            ''', (record_id,))
            record = cursor.fetchone()

            if not record:
                return jsonify({'message': 'Record not found'}), 404

            # 2. Validate store access for non-owners
            if current_role != 'owner' and record['store_address'] != current_store:
                return jsonify({'message': 'Unauthorized to modify records from other stores'}), 403

            # 3. Delete the record with store validation
            delete_query = '''DELETE FROM stock_updates WHERE id = ?'''
            delete_params = (record_id,)

            cursor.execute(delete_query, delete_params)
            conn.commit()

            return jsonify({
                'message': 'Stock update deleted successfully',
                'deleted_store': record['store_address']
            }), 200

        except Exception as e:
            conn.rollback()
            return jsonify({'message': f'Deletion failed: {str(e)}'}), 500


@app.route('/delete_user_stock_updates/<string:username>', methods=['DELETE'])
def delete_user_stock_updates(username):
    """Delete all stock updates for a specific user with store validation"""
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role = session.get('role')
    current_store = session.get('store_address')

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Validate user exists and get store association
            cursor.execute('''
                SELECT id, store_address 
                FROM users 
                WHERE username = ?
            ''', (username,))
            user = cursor.fetchone()

            if not user:
                return jsonify({'message': 'User not found'}), 404

            # Authorization check
            if current_role != 'owner':
                if current_store != user['store_address']:
                    return jsonify({
                        'message': 'Unauthorized: Cannot modify records from other stores'
                    }), 403

            # Delete with store validation
            cursor.execute('''
                DELETE FROM stock_updates 
                WHERE user_id = ?
                AND EXISTS (
                    SELECT 1 FROM items 
                    WHERE items.id = stock_updates.item_id 
                    AND items.store_address = ?
                )
            ''', (user['id'], user['store_address']))

            conn.commit()

            return jsonify({
                'message': f'Deleted {cursor.rowcount} stock updates for {username}',
                'store_affected': user['store_address']
            }), 200

    except Exception as e:
        return jsonify({'message': f'Deletion failed: {str(e)}'}), 500


@app.route('/download_stock_report', methods=['GET'])
def download_stock_report():
    """Generate store-specific stock warning PDF report"""
    VALID_STORES = [
        "Kusan Uyghur Cuisine, 1516 N 4th Street, San Jose, CA 95112",
        "Kusan Bazaar, 510 Barber Ln, Milpitas, CA 95035"
    ]

    # Authorization check
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role = session.get('role')
    current_store = session.get('store_address')
    store_filter = request.args.get('store', current_store)

    # Validate store access
    if current_role != 'owner' and store_filter != current_store:
        return jsonify({'message': 'Unauthorized to access this store'}), 403

    if store_filter not in VALID_STORES:
        return jsonify({'message': 'Invalid store selection'}), 400

    # Get store-specific data
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT name, category, in_stock_level, reorder_level, max_stock_level
            FROM items
            WHERE in_stock_level <= reorder_level
            AND store_address = ?
            ORDER BY category
        ''', (store_filter,))
        items = cursor.fetchall()

    if not items:
        return jsonify({
            'message': f'No stock warnings for {store_filter}',
            'store': store_filter
        }), 200

    # Generate PDF with store information
    pdf_filename = os.path.join(os.getcwd(), f"Stock_Warnings_{store_filter.split(',')[0].replace(' ', '_')}.pdf")
    c = canvas.Canvas(pdf_filename, pagesize=letter)

    # Store header
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, 790, f"Stock Report for: {store_filter}")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, 770, f"Generated by: {session.get('employee_name', 'System')}")

    # Report title
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(300, 750, "Stock Warnings Report")
    c.setFont("Helvetica", 12)

    y_position = 720  # Start below headers
    for category, items in groupby(items, key=lambda x: x['category']):
        category_items = list(items)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y_position, f"Category: {category}")
        y_position -= 20

        # Table headers
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y_position, "Item Name")
        c.drawString(200, y_position, "Current")
        c.drawString(260, y_position, "Reorder")
        c.drawString(320, y_position, "Max")
        c.drawString(380, y_position, "Restock Qty")
        y_position -= 15

        # Table rows
        c.setFont("Helvetica", 10)
        for item in category_items:
            restock_qty = item['max_stock_level'] - item['in_stock_level']
            c.drawString(50, y_position, item['name'][:25])  # Truncate long names
            c.drawString(200, y_position, str(item['in_stock_level']))
            c.drawString(260, y_position, str(item['reorder_level']))
            c.drawString(320, y_position, str(item['max_stock_level']))
            c.drawString(380, y_position, str(restock_qty))
            y_position -= 15

            if y_position < 50:
                c.showPage()
                y_position = 770  # Reset for new page
                c.setFont("Helvetica-Bold", 10)
                c.drawString(50, 780, "Continued from previous page...")

        y_position -= 10  # Spacing between categories

    c.save()

    return send_file(
        pdf_filename,
        as_attachment=True,
        download_name=f"Stock_Warnings_{store_filter.split(',')[0]}.pdf"
    )


@app.route('/create_account', methods=['POST'])
def create_account():
    VALID_STORES = [
        "Kusan Uyghur Cuisine, 1516 N 4th Street, San Jose, CA 95112",
        "Kusan Bazaar, 510 Barber Ln, Milpitas, CA 95035"
    ]

    # Authorization check
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role = session.get('role')
    current_store = session.get('store_address')
    data = request.json

    # Validate required fields
    required_fields = ['username', 'password', 'employee_name', 'phone_number', 'email', 'role']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400

    # Authorization and validation logic
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Validate store address
            store_address = data.get('store_address', current_store)

            # Non-owners can only create accounts in their own store
            if current_role != 'owner':
                if 'store_address' in data and data['store_address'] != current_store:
                    return jsonify({'message': 'Cannot create accounts in other stores'}), 403
                store_address = current_store  # Force current store for non-owners

            # Verify store is valid
            if store_address not in VALID_STORES:
                return jsonify({'message': 'Invalid store address'}), 400

            # Prevent role escalation
            if current_role != 'owner' and data['role'] == 'owner':
                return jsonify({'message': 'Only owners can create owner accounts'}), 403

            # Validate phone number format
            phone = data['phone_number']
            if not (len(phone) == 10 and phone.isdigit()):
                return jsonify({'message': 'Invalid phone number format'}), 400

            # Validate email format
            email = data['email']
            if '@' not in email or '.' not in email.split('@')[-1]:
                return jsonify({'message': 'Invalid email format'}), 400

            # Check password complexity
            password = data['password']
            if len(password) < 8 or not any(c.isupper() for c in password):
                return jsonify({'message': 'Password must be at least 8 characters with uppercase'}), 400

            cursor.execute('''
                INSERT INTO users (
                    username, password, employee_name,
                    store_address, phone_number, email,
                    role, is_authorized
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['username'],
                password,
                data['employee_name'],
                store_address,
                phone,
                email,
                data['role'],
                1 if data['role'] == 'owner' else 0  # Auto-authorize owners
            ))

            # Ensure at least one owner per store
            if data['role'] == 'owner':
                cursor.execute('''
                    UPDATE users SET is_authorized = 1 
                    WHERE store_address = ? AND role = 'owner'
                ''', (store_address,))

            conn.commit()
            return jsonify({
                'message': 'Account created successfully',
                'store': store_address,
                'requires_authorization': 0 if data['role'] == 'owner' else 1
            }), 201

    except sqlite3.IntegrityError as e:
        error_map = {
            'username': 'Username already exists',
            'phone_number': 'Phone number already registered',
            'email': 'Email address already in use'
        }
        error_field = next((k for k in error_map if k in str(e)), 'database')
        return jsonify({'message': f'{error_map.get(error_field, "Database error")}'}), 409

    except Exception as e:
        return jsonify({'message': f'Server error: {str(e)}'}), 500


@app.route('/set_stock_level/<int:item_id>', methods=['POST'])
def set_stock_level(item_id):
    # Authentication and store validation
    if 'store_address' not in session or 'role' not in session:
        return jsonify({'message': 'User not authenticated or store not assigned'}), 401

    current_store = session['store_address']
    user_role = session['role']
    user_id = session.get('user_id')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Get item details with store information
            cursor.execute('''
                SELECT id, in_stock_level, max_stock_level, reorder_level, name, store_address 
                FROM items 
                WHERE id = ?
            ''', (item_id,))
            item = cursor.fetchone()

            if not item:
                return jsonify({'message': 'Item not found.'}), 404

            # Store validation (owners can modify any store, others only their own)
            if user_role != 'owner' and item['store_address'] != current_store:
                return jsonify({'message': 'Unauthorized to modify items in this store'}), 403

            # Validate input
            data = request.json
            new_stock_level = data.get('in_stock_level')
            if not isinstance(new_stock_level, int) or new_stock_level < 0:
                return jsonify({'message': 'Invalid stock level'}), 400

            if new_stock_level > item['max_stock_level']:
                return jsonify({
                    'message': f'Cannot exceed Max Stock Level ({item["max_stock_level"]})',
                    'max_stock': item['max_stock_level']
                }), 400

            # Record stock update with store information
            cursor.execute('''
                INSERT INTO stock_updates 
                (user_id, item_id, stock_before, stock_after, store_address)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, item_id, item['in_stock_level'], new_stock_level, item['store_address']))

            # Update item stock
            cursor.execute('''
                UPDATE items 
                SET in_stock_level = ? 
                WHERE id = ? AND store_address = ?
            ''', (new_stock_level, item_id, item['store_address']))

            conn.commit()

            # Generate warning if needed
            warning = None
            if new_stock_level <= item['reorder_level']:
                warning = {
                    'message': f'Stock for "{item["name"]}" has hit Reorder Level',
                    'item_id': item_id,
                    'current_stock': new_stock_level,
                    'reorder_level': item['reorder_level']
                }

            return jsonify({
                'message': 'Stock updated successfully',
                'new_stock': new_stock_level,
                'store': item['store_address'],
                'warning': warning
            }), 200

        except sqlite3.Error as e:
            conn.rollback()
            return jsonify({'message': f'Database error: {str(e)}'}), 500
        except Exception as e:
            return jsonify({'message': f'Server error: {str(e)}'}), 500


@app.route('/stock_update_history', methods=['GET'])
def stock_update_history():
    """Get multi-store stock update history grouped by user"""
    # Authorization check
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role = session.get('role')
    current_store = session.get('store_address')
    store_filter = request.args.get('store')

    # Base query with proper store filtering
    base_query = '''
        SELECT 
            su.id, su.store_address,
            u.username, 
            i.name AS item_name, 
            i.category AS category, 
            su.stock_before, 
            su.stock_after, 
            su.updated_at
        FROM stock_updates su
        JOIN users u ON su.user_id = u.id
        JOIN items i ON su.item_id = i.id
    '''
    filters = []
    params = []

    # Non-owners: only their store + real-time validation
    if current_role != 'owner':
        filters.append('su.store_address = ?')
        params.append(current_store)
    # Owners: apply store filter if specified
    elif store_filter:
        filters.append('su.store_address = ?')
        params.append(store_filter)

    if filters:
        base_query += ' WHERE ' + ' AND '.join(filters)

    base_query += ' ORDER BY su.updated_at DESC'

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(base_query, params)
        raw_history = cursor.fetchall()

    # Process and group data
    user_history = defaultdict(lambda: {'category': None, 'records': []})
    for entry in raw_history:
        username = entry['username']
        user_data = user_history[username]

        # Maintain most recent category for each user
        if not user_data['category']:
            user_data['category'] = entry['category']

        user_data['records'].append({
            'id': entry['id'],
            'item_name': entry['item_name'],
            'stock_before': entry['stock_before'],
            'stock_after': entry['stock_after'],
            'updated_at': entry['updated_at'],
            'store': entry['store_address']  # Add store context
        })

    return jsonify([
        {
            'username': user,
            'category': data['category'],
            'store': next(iter(data['records']), {}).get('store'),  # Get store from first record
            'records': data['records']
        }
        for user, data in user_history.items()
    ])

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(debug=True)