import werkzeug.security
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from requests import HTTPError
from bs4 import BeautifulSoup
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FloatField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, NumberRange
from functools import wraps
import os
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
print(os.getenv("SECRET_KEY"))
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
print(os.environ.get("DATABASE_URL"))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)



##CONFIGURE TABLES
class Users(UserMixin, db.Model):
    __tablename__ = "user_list"
    comment = relationship("Comment", back_populates="comment_author")
    posts = relationship("BlogPost", back_populates="author")
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    author = relationship("Users", back_populates="posts")
    comment = relationship("Comment", back_populates="blogpost")
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user_list.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    comment_author = relationship("Users", back_populates="comment")
    blogpost = relationship('BlogPost', back_populates='comment')
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user_list.id"))
    parent_post = db.Column(db.String, db.ForeignKey("blog_posts.title"))
    text = db.Column(db.String, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 2:
            raise HTTPError(403, "Access Restricted")
        return f(*args, **kwargs)
    return decorated_function


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    log_in = SubmitField("Log in!")

@app.route('/')
def get_all_posts():
    user = Users()
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, user=user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        if Users.query.filter_by(email=email).first() == None:
            password = request.form.get("password")
            name = request.form.get("name")
            new_user = Users(email=email, password=generate_password_hash(password, salt_length=8,
                                                                                            method="pbkdf2:sha256"),
                             name=name)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        else:
            flash("This user is already registered!")
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        password = request.form.get("password")
        try:
            user = Users.query.filter_by(email=email).first()
            if check_password_hash(user.password, password):
                login_user(user)
                print("logged in")
                return redirect(url_for("get_all_posts"))
            else:
                flash("Incorrect email or password!")
        except Exception:
            flash("Incorrect email or password!")
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def show_post(post_id):
    gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, use_ssl=False)
    editor = CKEditor()
    requested_post = BlogPost.query.get(post_id)
    comment_list = []
    all_comments = Comment.query.all()
    for comment in all_comments:
        html_string = comment.text
        soup = BeautifulSoup(html_string, "html.parser")
        text = soup.get_text().strip("\xa0\n")
        comment_list.append(text)
    if request.method == "POST":
        comment = request.form.get("editor1")
        author_id = current_user.id
        post = BlogPost.query.filter_by(id=post_id).first()
        parent_post = post.title
        new_comment = Comment(text=comment, author_id=author_id, parent_post=parent_post)
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, editor=editor, comments_list=comment_list)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
@admin_only
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    db.create_all()
    app.run(host='0.0.0.0', port=5000)

