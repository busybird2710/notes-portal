import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from sqlalchemy.orm.exc import NoResultFound

# Create a new Flask application instance
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://dbpgf15365894:1etzU9iX~r]DLGfUMG3D6w@serverless-europe-west2.sysp0000.db2.skysql.com:4011/dbpgf15365894'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLAlchemy extension with the app
db = SQLAlchemy(app)

# Register Google OAuth client
# Use environment variables to handle client ID and secret securely
google_bp = make_google_blueprint(
    client_id=os.getenv('608148768763-0501gdu16rdulen9ots128mrqdfp1plu.apps.googleusercontent.com'),
    client_secret=os.getenv('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'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    scope=['openid', 'email', 'profile']
)
app.register_blueprint(google_bp, url_prefix='/login')

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create the database models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    notes = db.relationship('Note', backref='author', lazy=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user, remember=request.form.get('remember'))
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash('Username already exists. Please choose a different one.', 'error')
        else:
            hashed_password = generate_password_hash(request.form['password'], method='sha256')
            new_user = User(username=request.form['username'], password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    notes = Note.query.filter_by(author=current_user).order_by(Note.date_posted.desc()).all()
    return render_template('dashboard.html', notes=notes, username=current_user.username)

@app.route('/new_note', methods=['GET', 'POST'])
@login_required
def new_note():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        note = Note(title=title, content=content, author=current_user)
        db.session.add(note)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('new_note.html')

@app.route('/edit_note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        return jsonify({'message': 'You are not authorized to edit this note.'}), 403
    
    if request.method == 'POST':
        note.title = request.form['title']
        note.content = request.form['content']
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('edit_note.html', note=note)

@app.route('/delete_note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        return jsonify({'message': 'You are not authorized to delete this note.'}), 403
    
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)