
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for flashing messages

    
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

        try:
            # Add 'is_authorized' column to the users table if it doesn't exist
            cursor.execute("ALTER TABLE users ADD COLUMN is_authorized INTEGER DEFAULT 0")
            print("Added 'is_authorized' column.")
        except sqlite3.OperationalError:
            print("'is_authorized' column already exists.")

        # Create items table
        cursor.execute('''CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            category TEXT,
            max_stock_level INTEGER,
            in_stock_level INTEGER,
            reorder_level INTEGER,
            picture TEXT,  -- For storing the picture file path or URL
            supplier TEXT  -- For storing the supplier name
        )''')

        # Create categories table
        cursor.execute('''CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )''')

        # Create users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            employee_name TEXT,
            store_address TEXT,
            role TEXT NOT NULL CHECK(role IN ('owner', 'employee', 'manager')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        # Create stock_updates table
        cursor.execute('''CREATE TABLE IF NOT EXISTS stock_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            stock_before INTEGER NOT NULL,
            stock_after INTEGER NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (item_id) REFERENCES items(id)
        )''')

        # Add a default category if the table is empty
        cursor.execute('SELECT COUNT(*) FROM categories')
        if cursor.fetchone()[0] == 0:  # Check if categories table is empty
            cursor.execute('INSERT INTO categories (name) VALUES (?)', ("Default",))

        # Add a default owner account if the users table is empty
        cursor.execute('SELECT COUNT(*) FROM users')
        if cursor.fetchone()[0] == 0:  # Check if users table is empty
            cursor.execute('''
                INSERT INTO users (username, password, employee_name, store_address, role, is_authorized)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ("owner", "ownerpass", "Owner Name", "Default Store", "owner", 1))  # Set is_authorized to 1

        # Ensure all owner accounts are authorized
        cursor.execute('UPDATE users SET is_authorized = 1 WHERE role = "owner"')

        # Commit changes to the database
        conn.commit()


# Route for the login page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
                user = cursor.fetchone()

                if not user:
                    return render_template('userlogin.html', error_message='Invalid username or password, please try again.')

                if user['is_authorized'] == 0:
                    return render_template('userlogin.html', error_message='Your account has not been authorized. Please wait for approval.')

                # Store user ID in the session
                session['user_id'] = user['id']
                print(f"User {username} logged in with ID {user['id']}")  # Debug log

                # Redirect based on role
                if user['role'] == 'owner':
                    return redirect(url_for('owner_dashboard'))
                elif user['role'] == 'employee':
                    return redirect(url_for('employee_dashboard'))
                elif user['role'] == 'manager':
                    return redirect(url_for('manager_dashboard'))
                else:
                    return render_template('userlogin.html', error_message='Invalid role assigned to the user.')

        except Exception as e:
            return render_template('userlogin.html', error_message=f'An error occurred: {str(e)}')

    return render_template('userlogin.html')



# Route for registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 从 JSON 请求体中解析数据
        data = request.json
        username = data.get('username')
        password = data.get('password')
        employee_name = data.get('employee_name')
        store_address = data.get('store_address')
        if not store_address:
            return jsonify({'message': 'Error: Store address is required.'}), 400
        # 强制设置角色为 'employee'
        role = 'employee'

        # 输入验证
        if not username or not password or not employee_name or not store_address or role not in ['owner', 'employee', 'manager']:
            return jsonify({'message': 'Error: Missing or invalid input.'}), 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                # 插入新用户到数据库
                cursor.execute(
                    'INSERT INTO users (username, password, employee_name, store_address, role, is_authorized) VALUES (?, ?, ?, ?, ?, ?)',
                    (username, password, employee_name, store_address, role, 0)
                )
                conn.commit()
                return jsonify({'message': 'Registration successful!'}), 200
            except sqlite3.IntegrityError as e:
                # 处理用户名重复的情况
                if 'UNIQUE constraint failed: users.username' in str(e):
                    return jsonify({'message': 'Error: Username already exists.'}), 400
                else:
                    # 处理其他数据库错误
                    return jsonify({'message': 'Database error occurred.'}), 500

    # 如果是 GET 请求，渲染注册页面
    return render_template('register.html')

@app.route('/pending_accounts', methods=['GET'])
def pending_accounts():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, employee_name, store_address FROM users WHERE is_authorized = 0')
        accounts = [
            {
                'id': account['id'],
                'username': account['username'],
                'role': account['role'],
                'employee_name': account['employee_name'],
                'store_address': account['store_address']
            }
            for account in cursor.fetchall()
        ]
    return jsonify(accounts)

@app.route('/authorize_account/<int:account_id>', methods=['POST'])
def authorize_account(account_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET is_authorized = 1 WHERE id = ?', (account_id,))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'message': 'Error: Account not found.'}), 404

    return jsonify({'message': 'Account authorized successfully!'}), 200


# Route for the owner dashboard
@app.route('/owner_dashboard', methods=['GET', 'POST'])
def owner_dashboard():
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form['name']
            category = request.form['category']
            max_stock_level = int(request.form['max_stock_level'])
            in_stock_level = int(request.form['in_stock_level'])
            reorder_level = int(request.form['reorder_level'])
            supplier = request.form['supplier']

            # Handle file upload
            picture = request.files['picture']
            picture_path = None
            if picture and picture.filename:
                if not allowed_file(picture.filename):
                    return "Invalid file type. Allowed types: png, jpg, jpeg, gif.", 400

                filename = os.path.join(app.config['UPLOAD_FOLDER'], picture.filename)
                picture.save(filename)
                picture_path = filename

            # Save to database
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO items (name, category, max_stock_level, in_stock_level, reorder_level, picture, supplier)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (name, category, max_stock_level, in_stock_level, reorder_level, picture_path, supplier))
                conn.commit()

            # Debug print
            print(f"Item added: {name}, {category}, {max_stock_level}, {in_stock_level}, {reorder_level}, {supplier}, {picture_path}")

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

    # Render the dashboard
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM items')
        items = cursor.fetchall()
    return render_template('owner_dashboard.html', items=items)

# Route for the employee dashboard
@app.route('/employee_dashboard')
def employee_dashboard():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM items')
        items = cursor.fetchall()
    return render_template('employee_dashboard.html', items=items)

# Route for managing categories
@app.route('/categories', methods=['GET', 'POST'])
def categories():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if request.method == 'POST':
            categories = request.json.get('categories', [])
            cursor.execute('DELETE FROM categories')  # Clear existing categories
            for category in categories:
                cursor.execute('INSERT INTO categories (name) VALUES (?)', (category,))
            conn.commit()
            return jsonify({'message': 'Categories updated successfully!'})

        cursor.execute('SELECT name FROM categories')
        categories = [row['name'] for row in cursor.fetchall()]
        return jsonify(categories)

# Route for managing accounts
@app.route('/accounts', methods=['GET', 'POST'])
def accounts():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if request.method == 'POST':  # Handle account deletion
            user_id = request.json.get('id')

            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'message': 'Error: User does not exist.'}), 404

            if user['role'] == 'owner':
                return jsonify({'message': 'Error: Cannot delete the owner account.'}), 403

            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()

            if cursor.rowcount == 0:  # Check deletion success
                return jsonify({'message': 'Error: Failed to delete account.'}), 500

            return jsonify({'message': 'Account deleted successfully!'}), 200

        # 获取已授权账户
        cursor.execute('SELECT id, username, role, employee_name, store_address FROM users WHERE is_authorized = 1')
        authorized_accounts = [
            {
                'id': account['id'],
                'username': account['username'],
                'role': account['role'],
                'employee_name': account['employee_name'] if account['employee_name'] else 'N/A',
                'store_address': account['store_address'] if account['store_address'] else 'N/A'
            }
            for account in cursor.fetchall()
        ]
        # 获取待授权账户
        cursor.execute('SELECT id, username, employee_name, store_address FROM users WHERE is_authorized = 0')
        pending_accounts = [
            {
                'id': account['id'],
                'username': account['username'],
                'employee_name': account['employee_name'] if account['employee_name'] else 'N/A',
                'store_address': account['store_address'] if account['store_address'] else 'N/A'
            }
            for account in cursor.fetchall()
        ]

    return jsonify({
        'authorized_accounts': authorized_accounts,
        'pending_accounts': pending_accounts
    })


@app.route('/update_account/<int:account_id>', methods=['POST'])
def update_account(account_id):
    data = request.json
    username = data.get('username')
    role = data.get('role')
    employee_name = data.get('employee_name')
    store_address = data.get('store_address')
    password = data.get('password')

    # 输入验证
    if not username or not role or not employee_name or not store_address or not password:
        return jsonify({'message': 'Error: Missing or invalid input.'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # 更新账户信息，但不更改 ID
            cursor.execute('''
                UPDATE users 
                SET username = ?, role = ?, employee_name = ?, store_address = ?, password = ? 
                WHERE id = ?
            ''', (username, role, employee_name, store_address, password, account_id))
            conn.commit()

            if cursor.rowcount == 0:  # 检查是否更新成功
                return jsonify({'message': 'Error: User not found.'}), 404

            return jsonify({'message': 'Account updated successfully!'}), 200
        except sqlite3.IntegrityError as e:
            if 'UNIQUE constraint failed: users.username' in str(e):
                return jsonify({'message': 'Error: Username already exists.'}), 400
            return jsonify({'message': 'Database error occurred.'}), 500


@app.route('/items', methods=['GET'])
def get_items():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM items')
        items = cursor.fetchall()
        # Convert the rows into dictionaries
        items_list = [
            {
                'id': item['id'],
                'name': item['name'],
                'category': item['category'],
                'max_stock_level': item['max_stock_level'],
                'in_stock_level': item['in_stock_level'],
                'reorder_level': item['reorder_level'],
                'supplier': item['supplier'],  # Ensure this is included
                'picture': item['picture']     # Ensure this is included
            }
            for item in items
        ]
    return jsonify(items_list)

@app.route('/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM items WHERE id = ?', (item_id,))
        conn.commit()
    return jsonify({'message': f'Item with ID {item_id} has been deleted.'}), 200

@app.route('/update_item/<int:item_id>', methods=['POST'])
def update_item(item_id):
    data = request.json
    category = data.get('category')
    max_stock_level = data.get('max_stock_level')
    in_stock_level = data.get('in_stock_level')
    reorder_level = data.get('reorder_level')

    if not all(isinstance(val, (int, str)) for val in [category, max_stock_level, in_stock_level, reorder_level]):
        return jsonify({'message': 'Invalid input values.'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            UPDATE items 
            SET category = ?, max_stock_level = ?, in_stock_level = ?, reorder_level = ?
            WHERE id = ?
            ''',
            (category, max_stock_level, in_stock_level, reorder_level, item_id)
        )
        conn.commit()

    return jsonify({'message': 'Item updated successfully!'}), 200

@app.route('/create_account', methods=['POST'])
def create_account():
    data = request.json
    username = data.get('username')
    role = data.get('role')
    employee_name = data.get('employee_name')
    store_address = data.get('store_address')
    password = data.get('password')

    if not username or not role or not employee_name or not store_address or not password:
        return jsonify({'message': 'Error: Missing or invalid input.'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, role, employee_name, store_address, password)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, role, employee_name, store_address, password))
            conn.commit()
            return jsonify({'message': 'Account created successfully!'}), 200
        except sqlite3.IntegrityError as e:
            if 'UNIQUE constraint failed' in str(e):
                return jsonify({'message': 'Error: Username already exists.'}), 400
            return jsonify({'message': 'Error: Database error occurred.'}), 500


@app.route('/set_stock_level/<int:item_id>', methods=['POST'])
def set_stock_level(item_id):
    data = request.json
    new_stock_level = data.get('in_stock_level')

    if new_stock_level is None or not isinstance(new_stock_level, int) or new_stock_level < 0:
        return jsonify({'message': 'Invalid stock level provided.'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Fetch the current stock level
        cursor.execute('SELECT * FROM items WHERE id = ?', (item_id,))
        item = cursor.fetchone()

        if not item:
            return jsonify({'message': 'Item not found.'}), 404

        if new_stock_level > item['max_stock_level']:
            return jsonify({'message': f'Error: Cannot exceed Max Stock Level ({item["max_stock_level"]}).'}), 400

        # Log the stock update
        user_id = session.get('user_id')  # Assuming the user ID is stored in the session
        if not user_id:
            return jsonify({'message': 'User not authenticated.'}), 401

        # Debug log: Print user_id and item details
        print(f"User ID: {user_id}, Item ID: {item_id}, Stock Before: {item['in_stock_level']}, Stock After: {new_stock_level}")

        # Insert into stock_updates table
        cursor.execute('''
            INSERT INTO stock_updates (user_id, item_id, stock_before, stock_after)
            VALUES (?, ?, ?, ?)
        ''', (user_id, item_id, item['in_stock_level'], new_stock_level))

        # Update the stock level in the items table
        cursor.execute('UPDATE items SET in_stock_level = ? WHERE id = ?', (new_stock_level, item_id))
        conn.commit()

        # Check if stock level is below reorder level
        warning = None
        if new_stock_level <= item['reorder_level']:
            warning = f'Warning: Stock for item "{item["name"]}" has hit Reorder Level ({item["reorder_level"]}).'

        return jsonify({
            'message': f'Stock updated successfully! New stock level: {new_stock_level}.',
            'warning': warning
        }), 200

@app.route('/stock_update_history', methods=['GET'])
def stock_update_history():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Fetch stock update history with user and item details
        cursor.execute('''
            SELECT 
                su.id, 
                u.username, 
                i.name AS item_name, 
                su.stock_before, 
                su.stock_after, 
                su.updated_at
            FROM stock_updates su
            JOIN users u ON su.user_id = u.id
            JOIN items i ON su.item_id = i.id
            ORDER BY su.updated_at DESC
        ''')
        history = [
            {
                'id': row['id'],
                'username': row['username'],
                'item_name': row['item_name'],
                'stock_before': row['stock_before'],
                'stock_after': row['stock_after'],
                'updated_at': row['updated_at']
            }
            for row in cursor.fetchall()
        ]

    return jsonify(history)


if __name__ == '__main__':
    app.run(debug=True)