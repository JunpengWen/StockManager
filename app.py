from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3

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
        # Add a default category if the table is empty
        cursor.execute('SELECT COUNT(*) FROM categories')
        if cursor.fetchone()[0] == 0:
            cursor.execute('INSERT INTO categories (name) VALUES (?)', ("Default",))
        conn.commit()

init_db()

# Route for the login page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'owner' and password == 'ownerpass':
            return redirect(url_for('owner_dashboard'))
        elif username == 'employee' and password == 'employeepass':
            return redirect(url_for('employee_dashboard'))
        else:
            return "Invalid credentials, please try again."
    return render_template('userlogin.html')

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


if __name__ == '__main__':
    app.run(debug=True)
