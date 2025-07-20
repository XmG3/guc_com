from flask import Flask, render_template, redirect, request, session, flash
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

app = Flask(__name__)

#generate a random secret key for session management
app.secret_key = secrets.token_hex(32)

#initializing imports 
Scss(app)
csrf = CSRFProtect(app)
Login_Manager = LoginManager(app)
Login_Manager.login_view = 'login'
Login_Manager.login_message = 'Please log in.'
Login_Manager.init_app(app)


#database setup
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///whitelist.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

#user model for Flask-login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(12), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)


    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__ (self):
        return f"<user {self.username}>"   


#flask-login user loader
@Login_Manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#csrf protection setup
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

#initialize a whitelist of users in a database
def init_db():
    with app.app_context():
        db.create_all()

    #check existing users
        if User.query.count() == 0:
            print("No users found, creating default user.")
    
            default_user = [{'username': 'Kerem', 'password': '1234', 'is_admin': True}]
            for user_data in default_user:
                user = User(username=user_data['username'])
                user.set_password(user_data['password'])
                user.is_admin = user_data['is_admin']
                db.session.add(user)

            db.session.commit()
            print("Default user created.")
        else:
            print("Database already initialized u dumdum")

#login page
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/nav')
    
    form = LoginForm()
    if form.validate_on_submit():  # This checks CSRF token automatically
        username = form.username.data
        password = form.password.data
        
        user = User.query.filter_by(username=username, is_active=True).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login was successful.')
            return redirect('/nav')
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html', form=form)


#logout sequence
@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    flash('Logout successful!')
    return redirect('/login')

#navigation page
@app.route('/nav')
@login_required
def nav():
    return render_template('nav.html')


#portfolio page
@app.route('/portfolio')
@login_required
def portfolio():
    return render_template('portfolio.html')

#socials page
@app.route('/socials')
def socials():
    return render_template('socials.html')

#api page
@app.route('/playground')
@login_required
def playground():
    return render_template('playground.html')


#ADMIN routes
#admin use, user whitelisting
@app.route('/admin/whitelist')
@login_required
def list_users(): #lists all users
    if not current_user.is_admin:
        flash('Access denied.', 'error')
        return redirect('/nav')
    
    users = User.query.all()
    return render_template('whitelist.html', users=users)

@app.route('/admin/whitelist/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('Access denied.', 'error')
        return redirect('/nav')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password for a new user are required.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash(f'User {username} added to whitelist.', 'success')
            return redirect('/admin/whitelist')
    return render_template('add_user.html')

@app.route('/admin/whitelist/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Access denied.', 'error')
        return redirect('/nav')

    user = User.query.get_or_404(user_id)
    if user.username == 'Kerem':
        flash('Cannot delete Kerem', 'error')
    else: 
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted from whitelist.', 'success')
    return redirect('/admin/whitelist')

#cache deletion
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max_age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/favicon.ico')
def favicon():
    return '', 204


#program run
if __name__ == "__main__":
    init_db() #initialize database
    app.run(debug=True) 