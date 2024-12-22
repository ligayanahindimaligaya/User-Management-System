from flask import Flask, flash, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = '65b0b774279de460f1cc5c92'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///data.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = 'filesystem'
db = SQLAlchemy(app)
Session(app)

# User Class
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(255), nullable=False)
    lname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    edu = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)

# Admin Class
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Create table
with app.app_context():
    db.create_all()

# Main index
@app.route('/')
def index():
    return render_template('index.html', title="")

# Admin login
@app.route('/admin/', methods=["POST", "GET"])
def adminIndex():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == "" or password == "":
            flash('Please fill all the fields', 'danger')
            return redirect('/admin/')
        else:
            admin = Admin.query.filter_by(username=username).first()
            if admin and check_password_hash(admin.password, password):
                session['admin_id'] = admin.id
                session['admin_name'] = admin.username
                flash('Login Successfully', 'success')
                return redirect('/admin/dashboard')
            else:
                flash('Invalid Username or Password', 'danger')
                return redirect('/admin/')
    return render_template('admin/index.html', title="Admin Login")

# Admin dashboard
@app.route('/admin/dashboard')
def adminDashboard():
    if not session.get('admin_id'):
        return redirect('/admin/')
    totalUser = User.query.count()
    totalApprove = User.query.filter_by(status=1).count()
    notTotalApprove = User.query.filter_by(status=0).count()
    return render_template('admin/dashboard.html', title="Admin Dashboard", totalUser=totalUser, totalApprove=totalApprove, notTotalApprove=notTotalApprove)

# Admin get all users
@app.route('/admin/get-all-user', methods=["POST", "GET"])
def adminGetAllUser():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if request.method == "POST":
        search = request.form.get('search')
        users = User.query.filter(User.username.like('%' + search + '%')).all()
        return render_template('admin/all-user.html', title='Approve User', users=users)
    else:
        users = User.query.all()
        return render_template('admin/all-user.html', title='Approve User', users=users)

@app.route('/admin/approve-user/<int:id>')
def adminApprove(id):
    if not session.get('admin_id'):
        return redirect('/admin/')
    User.query.filter_by(id=id).update(dict(status=1))
    db.session.commit()
    flash('Approved Successfully', 'success')
    return redirect('/admin/get-all-user')

# Change admin password
@app.route('/admin/change-admin-password', methods=["POST", "GET"])
def adminChangePassword():
    admin = Admin.query.get(1)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == "" or password == "":
            flash('Please fill all the fields', 'danger')
            return redirect('/admin/change-admin-password')
        else:
            Admin.query.filter_by(username=username).update(dict(password=generate_password_hash(password, 10)))
            db.session.commit()
            flash('Admin Password updated successfully', 'success')
            return redirect('/admin/change-admin-password')
    else:
        return render_template('admin/admin-change-password.html', title='Admin Change Password', admin=admin)

# Admin logout
@app.route('/admin/logout')
def adminLogout():
    if not session.get('admin_id'):
        return redirect('/admin/')
    session.clear()
    return redirect('/')

# User login
@app.route('/user/', methods=["POST", "GET"])
def userIndex():
    if session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        users = User.query.filter_by(email=email).first()
        if users and check_password_hash(users.password, password):
            if users.status == 0:
                flash('Your Account is not approved by Admin', 'danger')
                return redirect('/user/')
            else:
                session['user_id'] = users.id
                session['username'] = users.username
                flash('Login Successfully', 'success')
                return redirect('/user/dashboard')
        else:
            flash('Invalid Email and Password', 'danger')
            return redirect('/user/')
    else:
        return render_template('user/index.html', title="User Login")

# User register
# User register
@app.route('/user/signup', methods=['POST', 'GET'])
def userSignup():
    if session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        username = request.form.get('username')
        edu = request.form.get('edu')
        password = request.form.get('password')
        if fname == "" or lname == "" or email == "" or password == "" or username == "" or edu == "":
            flash('Please fill all the fields', 'danger')
            return redirect('/user/signup')
        else:
            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return redirect('/user/signup')
            else:
                # Proceed to hash the password and create the user if email is not duplicated
                hash_password = generate_password_hash(password, method='pbkdf2:sha256')
                user = User(fname=fname, lname=lname, email=email, password=hash_password, edu=edu, username=username)
                db.session.add(user)
                db.session.commit()
                flash('Account created successfully. Admin will approve your account in 10 to 30 minutes.', 'success')
                return redirect('/user/')
    else:
        return render_template('user/signup.html', title="User Signup")


@app.route('/user/dashboard')
def userDashboard():
    if not session.get('user_id'):
        return redirect('/user/')
    
    id = session.get('user_id')
    user = User.query.filter_by(id=id).first()  # Use 'user' here (singular)
    
    if not user:
        # Handle case where user is not found in the database
        return redirect('/user/')
    
    return render_template('user/dashboard.html', title="User Dashboard", user=user)  # Pass 'user' here

# User logout
@app.route('/user/logout')
def userLogout():
    if not session.get('user_id'):
        return redirect('/user/')
    session.clear()
    return redirect('/')

# User change password
@app.route('/user/change-password', methods=['POST', 'GET'])
def userChangePassword():
    users = User.query.get(session.get('user_id'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirmPassword = request.form.get('confirmPassword')
        if password == "" or confirmPassword == "":
            flash('Please fill all the fields', 'danger')
            return redirect('/user/change-password')
        else:
            if password != confirmPassword:
                flash('Password and confirm password do not match', 'danger')
                return redirect('/user/change-password')
            else:
                hash_password = generate_password_hash(password, 10)
                User.query.filter_by(id=session.get('user_id')).update(dict(password=hash_password))
                db.session.commit()
                flash('Password updated successfully', 'success')
                return redirect('/user/change-password')
    else:
        return render_template('user/change-password.html', title="Change Password", user=users)

# User update profile
@app.route('/user/Update-profile', methods=['POST', 'GET'])
def userUpdateProfile():
    user = User.query.get(session.get('user_id'))  # changed users to user
    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        username = request.form.get('username')
        edu = request.form.get('edu')
        if fname == "" or lname == "" or email == "" or username == "" or edu == "":
            flash('Please fill all the fields', 'danger')
            return redirect('/user/Update-profile')
        else:
            User.query.filter_by(id=session.get('user_id')).update(dict(fname=fname, lname=lname, email=email, username=username, edu=edu))
            db.session.commit()
            flash('Profile updated successfully', 'success')
            return redirect('/user/Update-profile')
    else:
        return render_template('user/Update-profile.html', title="Update Profile", user=user)  # changed users to user


if __name__ == '__main__':
    app.run(debug=True)
