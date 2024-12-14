from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Route for the login page (also set as the home page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Replace the following with real authentication logic
        if username == 'owner' and password == 'ownerpass':
            return redirect(url_for('owner_dashboard'))
        elif username == 'employee' and password == 'employeepass':
            return redirect(url_for('employee_dashboard'))
        else:
            return "Invalid credentials, please try again."
    return render_template('userlogin.html')

# Route for the owner dashboard page
@app.route('/owner_dashboard')
def owner_dashboard():
    return render_template('owner_dashboard.html')

# Route for the employee dashboard page
@app.route('/employee_dashboard')
def employee_dashboard():
    return render_template('employee_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
