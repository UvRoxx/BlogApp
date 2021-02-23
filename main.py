from flask import Flask, render_template, redirect, url_for, flash, request, abort
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

from sqlalchemy.orm import relationship

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateUserForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


is_admin = False


##CONFIGURE TABLES

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    posts = relationship("BlogPost", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Defining the relaitonship here
    author = relationship('User', back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # Decining relationship with comments
    comments = relationship("Comments", back_populates="post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comments(db.Model):
    __tablename__ = "coments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(250), unique=False, nullable=False)
    # Author id and linking
    author_name = db.Column(db.String, nullable=False)
    # adding the relationship with the post to the comment
    post = relationship('BlogPost', back_populates="comments")
    comment_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


is_admin = False
db.create_all()


def admin_only(target):
    @wraps(target)
    def admin_wrapper():
        if is_admin:
            print(f"yes the user is admin at id")
            return target()
        return abort(403)

    return admin_wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    print(current_user.is_authenticated)
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    global is_admin
    user_form = CreateUserForm()
    if user_form.validate_on_submit():
        name = user_form.name.data
        email = user_form.email.data
        password = generate_password_hash(user_form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            name=name,
            email=email,
            password=password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        if new_user.id == 1:
            is_admin = True
    return render_template("register.html", form=user_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    global is_admin
    login_form = LoginForm()
    if login_form.validate_on_submit():
        try:
            email = login_form.email.data
            user = User.query.filter_by(email=email).first()
            print("user found")
            if check_password_hash(user.password, login_form.password.data):
                print("Success")
                user = load_user(user.id)
                login_user(user)
                if user.id == 1:
                    is_admin = True
                return redirect(url_for("get_all_posts"))
            else:
                flash("Wrong Password")
                return redirect(url_for("login"))
        except AttributeError:
            flash("Invalid Email Please Recheck and Try Again")
            return redirect(url_for("login"))

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    global is_admin
    logout_user()
    is_admin = False
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        new_comment = Comments(
            comment_id=post_id,
            comment=comment_form.comment.data,
            author_name=current_user.name
        )
        db.session.add(new_comment)
        db.session.commit()
        print("added comment successfully")
        return redirect(url_for("show_post", post_id=post_id))

    return render_template("post.html", post=requested_post, form=comment_form,
                           comments=Comments.query.filter_by(comment_id=post_id).all())


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
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
@admin_only
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
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
