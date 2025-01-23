from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import sqlite3

from tensorflow.python.distribute.multi_process_runner import manager
app = Flask(__name__)


# Database configuration
DATABASE = 'stock_manager.db'



def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN is_authorized INTEGER DEFAULT 0")
            print("Added 'is_authorized' column.")
        except sqlite3.OperationalError:
            print("'is_authorized' column already exists.")

        # Adding phone_number column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN phone_number TEXT DEFAULT NULL")
            print("Added 'phone_number' column.")
        except sqlite3.OperationalError:
            print("'phone_number' column already exists.")

        # Adding email column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT NULL")
            print("Added 'email' column.")
        except sqlite3.OperationalError:
            print("'email' column already exists.")

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        # Create items table
        cursor.execute('''CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            category TEXT,
            max_stock_level INTEGER,
            in_stock_level INTEGER,
            reorder_level INTEGER
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
            role TEXT NOT NULL CHECK(role IN ('owner', 'employee', 'manager', 'server', 'line_cook', 'prep_cook')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            phone_number TEXT DEFAULT NULL,
            email TEXT DEFAULT NULL
        )''')

        # Add a default category if the table is empty
        cursor.execute('SELECT COUNT(*) FROM categories')
        if cursor.fetchone()[0] == 0:  # Check if categories table is empty
            cursor.execute('INSERT INTO categories (name) VALUES (?)', ("Default",))

        # Add a default owner account if the users table is empty
        cursor.execute('SELECT COUNT(*) FROM users')
        if cursor.fetchone()[0] == 0:  # Check if users table is empty
            cursor.execute('''
                INSERT INTO users (username, password, employee_name, store_address, phone_number, email, role, is_authorized)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', ("owner", "ownerpass", "Owner Name", "Default Store", "1234567890", "owner@example.com", "owner",
                  1))  # 设置 is_authorized 为 1

        # 确保所有 owner 用户的 is_authorized 设置为 1
        cursor.execute('UPDATE users SET is_authorized = 1 WHERE role = "owner"')
        conn.commit()

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
                    # 用户名或密码错误
                    return render_template('userlogin.html', error_message='Invalid username or password, please try again.')

                if user['is_authorized'] == 0:
                    # 账号未被授权
                    return render_template('userlogin.html', error_message='Your account has not been authorized. Please wait for approval.')

                # 根据用户角色重定向到不同的页面
                if user['role'] == 'owner':
                    return redirect(url_for('owner_dashboard'))
                elif user['role'] in ['employee', 'server', 'line_cook', 'prep_cook']:
                    return redirect(url_for('employee_dashboard'))
                elif user['role'] == 'manager':
                    return redirect(url_for('manager_dashboard'))
                else:
                    return render_template('userlogin.html', error_message='Invalid role assigned to the user.')


        except Exception as e:
            # 捕获任何异常并显示错误信息
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
        phone_number = data.get('phone_number')  # New field
        email = data.get('email')  # New field
        store_address = data.get('store_address')
        if not store_address:
            return jsonify({'message': 'Error: Store address is required.'}), 400
        # 强制设置角色为 'employee'
        role = 'employee'



        # 输入验证
        if not username or not password or not employee_name or not phone_number or not email or not store_address:
            return jsonify({'message': 'Error: Missing or invalid input.'}), 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                # 插入新用户到数据库
                cursor.execute(
                    'INSERT INTO users (username, password, employee_name, phone_number, email, store_address, role, is_authorized) VALUES (?, ?, ?, ?, ?, ?,?,?)',
                    (username, password, employee_name, phone_number, email, store_address, role, 0)
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
        cursor.execute('SELECT id, username, role, employee_name, store_address, phone_number, email FROM users WHERE is_authorized = 0')
        accounts = [
            {
                'id': account['id'],
                'username': account['username'],
                'role': account['role'],
                'employee_name': account['employee_name'],
                'store_address': account['store_address'],
                'phone_number': account['phone_number'],
                'email': account['email']
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


@app.route('/reject_account/<int:account_id>', methods=['POST'])
def reject_account(account_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # 删除该账户
        cursor.execute('DELETE FROM users WHERE id = ?', (account_id,))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'message': 'Error: Account not found.'}), 404

    return jsonify({'message': 'Account rejected successfully!'}), 200

# Route for the owner dashboard
@app.route('/owner_dashboard', methods=['GET', 'POST'])
def owner_dashboard():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        max_stock_level = int(request.form['max_stock_level'])
        in_stock_level = int(request.form['in_stock_level'])
        reorder_level = int(request.form['reorder_level'])

        if in_stock_level >= max_stock_level or reorder_level >= max_stock_level:
            return "Error: In-Stock Level and Reorder Level must be smaller than Max Stock Level.", 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO items (name, category, max_stock_level, in_stock_level, reorder_level) VALUES (?, ?, ?, ?, ?)',
                               (name, category, max_stock_level, in_stock_level, reorder_level))
                conn.commit()
            except sqlite3.IntegrityError:
                return "Error: Item name must be unique.", 400

        return redirect(url_for('owner_dashboard'))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM items')
        items = cursor.fetchall()
    return render_template('owner_dashboard.html', items=items)

@app.route('/manager_dashboard', methods=['GET', 'POST'])
def manager_dashboard():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        max_stock_level = int(request.form['max_stock_level'])
        in_stock_level = int(request.form['in_stock_level'])
        reorder_level = int(request.form['reorder_level'])

        if in_stock_level >= max_stock_level or reorder_level >= max_stock_level:
            return "Error: In-Stock Level and Reorder Level must be smaller than Max Stock Level.", 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    'INSERT INTO items (name, category, max_stock_level, in_stock_level, reorder_level) VALUES (?, ?, ?, ?, ?)',
                    (name, category, max_stock_level, in_stock_level, reorder_level)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                return "Error: Item name must be unique.", 400

        return redirect(url_for('manager_dashboard'))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM items')
        items = cursor.fetchall()
    return render_template('manager_dashboard.html', items=items)

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

        if request.method == 'POST':  # 删除账户逻辑
            user_id = request.json.get('id')

            # 检查用户是否存在
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'message': 'Error: User does not exist.'}), 404

            # 禁止删除 Owner 账户
            if user['role'] == 'owner':
                return jsonify({'message': 'Error: Cannot delete the owner account.'}), 403

            # 删除用户
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()

            if cursor.rowcount == 0:  # 确保删除成功
                return jsonify({'message': 'Error: Failed to delete account.'}), 500

            return jsonify({'message': 'Account deleted successfully!'}), 200

        # 获取已授权账户
        cursor.execute('SELECT id, username, role, employee_name, store_address, phone_number, email FROM users WHERE is_authorized = 1')
        authorized_accounts = [
            {
                'id': account['id'],
                'username': account['username'],
                'role': account['role'],
                'employee_name': account['employee_name'] if account['employee_name'] else 'N/A',
                'store_address': account['store_address'] if account['store_address'] else 'N/A',
                'phone_number': account['phone_number'] if account['phone_number'] else 'N/A',
                'email': account['email'] if account['email'] else 'N/A',
            }
            for account in cursor.fetchall()
        ]

        # 获取待授权账户
        cursor.execute('SELECT id, username, employee_name, store_address, phone_number, email FROM users WHERE is_authorized = 0')
        pending_accounts = [
            {
                'id': account['id'],
                'username': account['username'],
                'employee_name': account['employee_name'] if account['employee_name'] else 'N/A',
                'store_address': account['store_address'] if account['store_address'] else 'N/A',
                'phone_number': account['phone_number'] if account['phone_number'] else 'N/A',
                'email': account['email'] if account['email'] else 'N/A',
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
    phone_number = data.get('phone_number')  # 获取手机号
    email = data.get('email')  # 获取邮箱

    # 输入验证
    if not username or not role or not employee_name or not store_address or not phone_number or not email:
        return jsonify({'message': 'Error: Missing or invalid input.'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # 更新账户信息
            cursor.execute('''
                UPDATE users 
                SET username = ?, role = ?, employee_name = ?, store_address = ?, password = ?, phone_number = ?, email = ? 
                WHERE id = ?
            ''', (username, role, employee_name, store_address, password, phone_number, email, account_id))
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
                'reorder_level': item['reorder_level']
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
    phone_number = data.get('phone_number')  # 获取手机号
    email = data.get('email')  # 获取邮箱
    password = data.get('password')

    if not username or not role or not employee_name or not store_address or not phone_number or not email or not password:
        return jsonify({'message': 'Error: Missing or invalid input.'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, role, employee_name, store_address, phone_number, email, password)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, role, employee_name, store_address, phone_number, email, password))
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
        cursor.execute('SELECT * FROM items WHERE id = ?', (item_id,))
        item = cursor.fetchone()

        if not item:
            return jsonify({'message': 'Item not found.'}), 404

        if new_stock_level > item['max_stock_level']:
            return jsonify({'message': f'Error: Cannot exceed Max Stock Level ({item["max_stock_level"]}).'}), 400

        cursor.execute('UPDATE items SET in_stock_level = ? WHERE id = ?', (new_stock_level, item_id))
        conn.commit()

        message = f'Stock updated successfully! New stock level: {new_stock_level}.'
        if new_stock_level <= item['reorder_level']:
            message += f' Warning: Stock has hit Reorder Level ({item["reorder_level"]}).'

        return jsonify({'message': message}), 200

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


if __name__ == '__main__':
    app.run(debug=True)
