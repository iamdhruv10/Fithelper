from flask import Flask, render_template, request, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required

app = Flask(__name__)
app.secret_key = "fitness_secret_key"
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# Fake user database (Replace with SQLite or PostgreSQL)
users = {"testuser": bcrypt.generate_password_hash("password").decode('utf-8')}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    return User(username) if username in users else None

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def create_user():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        
        if username in users:
            return "User already exists!"
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users[username] = hashed_password
        return redirect(url_for("home"))
    
    return render_template("create.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    
    if username in users and bcrypt.check_password_hash(users[username], password):
        login_user(User(username))
        return redirect(url_for("dashboard"))
    
    return redirect(url_for('create_user'))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template('real.html')


if __name__ == "__main__":
    app.run(debug=True)
