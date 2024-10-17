from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# CREATE DATABASE

class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB


class User(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Check if the email or name already exists
        existing_user = User.query.filter((User.email == email) | (User.name == name)).first()
        if existing_user:
            message = "This email or username is already registered. Please use a different one."
            alert_type = 'danger'  # Set alert type for error
            return render_template("auth/register.html", message=message, alert_type=alert_type)

        
        
        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Create a new user instance
        new_user = User(name=name, email=email, password=hashed_password)

        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()

        # Welcome message after successful registration
        welcome_message = f"Welcome, {name}! Thank you for registering."
        return redirect(url_for('secrets', name=name, welcome_message=welcome_message))  # Redirect to login page after registration

    return render_template("auth/register.html")



@app.route('/login')
def login():
    return render_template("auth/login.html")


@app.route('/secrets')
def secrets():
    name = request.args.get('name')  # Get the name from query parameters
    welcome_message = request.args.get('welcome_message')
    return render_template("secrets.html", name=name, welcome_message=welcome_message)  # Pass it to the template



@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    pass

@app.route('/test')
def test():
    name = request.args.get('name')
    return f"The name is: {name}"


if __name__ == "__main__":
    app.run(debug=True)
