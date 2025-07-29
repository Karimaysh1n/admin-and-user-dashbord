from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session , flash , jsonify
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
app.config['SECRET_KEY'] = 'your_very_secret_key_here'
from flask_jwt_extended import JWTManager
jwt = JWTManager(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(80), nullable=False , default='user')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='posts')

with app.app_context():
    db.create_all()



admins = [
    {"id": 1, "username": "Karim", "password": "123", "role": "admin"},
]
@app.route('/')
def index():
    if "role" in session:
        if session["role"] == 'admin':
            return redirect(url_for('admin'))
        elif session["role"] == 'user':
            return redirect(url_for('user'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already taken")
            return redirect(url_for('register'))
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password, role="user")
            db.session.add(new_user)
            db.session.commit()
            session['role'] = 'user'
            session['username'] = username
            session['user_id'] = new_user.id
            return redirect(url_for('user'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for admin in admins:
            if admin['username'] == username and admin['password'] == password and admin['role'] == 'admin':
                session['role'] = 'admin'
                session['username'] = admin['username']
                session['user_id'] = admin['id']
                return redirect(url_for('admin'))
        exiting_user = User.query.filter_by(username=username).first()
        if exiting_user and check_password_hash(exiting_user.password, password):
            session['role'] = "user"
            session['username'] = username
            session['user_id'] = exiting_user.id
            flash("Login successful")
            return redirect(url_for('user'))
        else:
            flash("Login failed")
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/user')
def user():
    if "role" in session:
        if session["role"] == 'admin':
                return redirect(url_for('admin'))
    else:
        flash("you should login")
        return redirect(url_for('login'))
    all_posts = Post.query.order_by(Post.date_posted.desc()).all()
    user_id = session['user_id']
    return render_template('user.html'  , all_posts=all_posts)

@app.route('/admin' , methods=['GET', 'POST'])
def admin():
    if "role" in session:
        if session["role"] == 'user':
                return redirect(url_for('user'))
    else:
        flash("you do not have premotion to see that page.")
        return redirect(url_for('register'))
    return render_template('admin.html' , username=session['username'])


@app.route('/logout')
def logout():
    if "role" in session:
        session.clear()
        flash("You have been logged out.")
        return redirect(url_for('index'))
    else:
        flash("you should login")
        return redirect(url_for('login'))


@app.route('/display_all_users', methods=['GET'])
def display_all_users():
    if "role" in session:
        if session["role"] == 'admin':
            all_users = User.query.all()
            users_list = []
            for user in all_users:
                users_list.append({"username": user.username, "role": user.role , "id": user.id , "password": user.password})
            return render_template('display_all_users.html', users_list=users_list)
        else:
            flash("you do not have premotion to see that page.")
            return redirect(url_for('user'))
    else:
        flash("you should login")
        return redirect(url_for('login'))

@app.route('/update_user', methods=['POST' , 'GET'])
def update_user():
    if request.method == 'POST':
        if "role" in session:
            if session["role"] == 'admin':
                id = request.form['id']
                id = int(id)
                target_user = User.query.filter_by(id=id).first()
                if target_user:
                    new_username = request.form['username']
                    new_password = request.form['password']
                    new_role = request.form['role']
                    hashed_password = generate_password_hash(new_password)
                    target_user.username = new_username
                    target_user.role = new_role
                    target_user.password = hashed_password
                    db.session.commit()
                    flash("user update successfully")
                    return redirect(url_for('admin'))
                else:
                    flash("user update failed")
                    return redirect(url_for('admin'))
            else:
                flash("you do not have premotion to see that page.")
                return redirect(url_for('user'))
        else:
            flash("you should login")
            return redirect(url_for('login'))
    return render_template('update_user.html')

@app.route('/delete_user', methods=['GET' , 'POST'])
def delete_user():
    if request.method == 'POST':
        if "role" in session:
            if session["role"] == 'admin':
                id = request.form['id']
                id = int(id)
                target_user = User.query.filter_by(id=id).first()
                if target_user:
                    db.session.delete(target_user)
                    db.session.commit()
                    flash("user delete successfully.")
                    return redirect(url_for('admin'))
                else:
                    flash("user not found.")
                    return redirect(url_for('admin'))
            else:
                flash("you do not have premotion to see that page.")
                return redirect(url_for('user'))
    return render_template('delete_user.html')


@app.route('/new_post', methods=['GET' , 'POST'])
def new_post():
    if request.method == 'POST':
        if "role" in session:
            title = request.form['title']
            content = request.form['content']
            user_id = session['user_id']
            new_post = Post(title=title, content=content , date_posted=datetime.now() , user_id=user_id)
            db.session.add(new_post)
            db.session.commit()
            flash("post created successfully")
            if session["role"] == 'admin':
                return redirect(url_for('admin'))
            elif session["role"] == 'user':
                return redirect(url_for('user'))
        else:
            flash("you should login")
            return redirect(url_for('login'))
    return render_template('new_post.html')


@app.route('/delete_any_post', methods=['GET' , 'POST'])
def delete_any_post():
    if request.method == 'POST':
        if "role" in session:
            if session["role"] == 'admin':
                id = request.form['id']
                id = int(id)
                target_post = Post.query.filter_by(id=id).first()
                if target_post:
                    db.session.delete(target_post)
                    db.session.commit()
                    flash("post deleted successfully.")
                    return redirect(url_for('admin'))
                else:
                    flash("post not found.")
                    return redirect(url_for('delete_any_post'))
            else:
                flash("you do not have premotion to see that page.")
                return redirect(url_for('user'))
        else:
            flash("you should login")
            return redirect(url_for('login'))
    return render_template('delete_any_post.html')



@app.route('/display_all_posts', methods=['GET' , 'POST'])
def display_all_posts():
        posts_list = []
        if "role" in session:
            if session["role"] == 'admin':
                all_posts = Post.query.all()
                for post in all_posts:
                    posts_list.append({"id" : post.id , "title" : post.title , "content" : post.content , "date_posted" : post.date_posted, "user_id" : post.user_id , "author" : post.author.username})
                return render_template('display_all_posts.html', posts_list=posts_list)
            else:
                flash("you do not have premotion to see that page.")
                return redirect(url_for('user'))
        else:
            flash("you should login")
            return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
