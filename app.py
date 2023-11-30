from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, validators, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import pyotp
import qrcode
from io import BytesIO
import base64

#Initialize flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)  # Initialize the Bcrypt object

# initializing limiter
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Content Security Policy headers
csp_headers = {
    'default-src': '\'self\'',        # Allow resources from the same origin (self)
    'script-src': '\'self\'',         # Allow inline scripts and scripts from the same origin
}


# Defining the Post model
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    # Defining the relationship with Comment model
    post_comments = db.relationship('Comment', backref='post_association', cascade='all, delete-orphan', lazy=True)


# Defining a form for creating posts
class PostForm(FlaskForm):
    title = StringField('Title', render_kw={"placeholder": "Enter the title"}, validators=[validators.DataRequired()])
    content = TextAreaField('Content', render_kw={"placeholder": "Enter the content"}, validators=[validators.DataRequired()])
    submit = SubmitField('Create Post')

#Defining the comment model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    post = db.relationship('Post', backref=db.backref('comments', lazy=True))

#Defining a form for creating comments
class CommentForm(FlaskForm):
    content = TextAreaField('Comment', render_kw={"placeholder": "Enter your comment"}, validators=[validators.DataRequired()])
    submit = SubmitField('Submit Comment')


#Defining the user model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime, default=None)
    totp_secret = db.Column(db.String(16), nullable=True)  # 16 characters is the standard size for TOTP secrets

    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8') #Encrypt the stored password
        self.failed_login_attempts = 0  # Initialize with 0

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password) #Use bcrypt to check the hashed password
    
    def increment_failed_login_attempts(self):
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1  # Use the default value if it's None
        self.last_login_attempt = datetime.utcnow() #Fetch time

    def reset_failed_login_attempts(self):
        self.failed_login_attempts = 0
        self.last_login_attempt = None

#Defining the registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username): #Function for restricting duplicate usernames
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

#Defining the login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    totp_code = StringField('TOTP Code', validators=[DataRequired()])
    submit = SubmitField('Login')



## Routes for the application

#Home route
@app.route('/')
def home():
    posts = Post.query.all()
    return render_template('index.html', posts=posts)

#Post route with required login
@app.route('/post/<int:post_id>')
@login_required #This blocks the subdirectory if the user is not logged in
def post(post_id):
    post = Post.query.get(post_id)
    form = CommentForm()
    if post:
        if form.validate_on_submit():
            content = form.content.data
            new_comment = Comment(content=content, post=post)
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment added successfully!', 'success')
        return render_template('post.html', post=post, form=form)
    else:
        return 'Post not found', 404

#Add comment route with login required
@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    form = CommentForm()
    post = Post.query.get(post_id)

    if form.validate_on_submit():
        content = form.content.data
        new_comment = Comment(content=content, post=post)
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully!', 'success')

    return redirect(url_for('post', post_id=post_id))

#Create post route with login required
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        new_post = Post(title=title, content=content)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('home'))

    return render_template('create.html', form=form)

#After request function to add Content Security Policy headers
@app.after_request
def add_csp_headers(response):
    # Add Content Security Policy headers to the response
    for header, value in csp_headers.items():
        response.headers[header] = value
    return response

#User loader function for Flask Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Register route with totp generation and implementaion
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')

        # Generate a TOTP secret for the user
        totp = pyotp.TOTP(pyotp.random_base32())
        user.totp_secret = totp.secret
        db.session.commit()

        totp_uri = totp.provisioning_uri(name=user.username, issuer_name='YourApp')

        # Generate QR code
        img = qrcode.make(totp_uri)

        # Save the image as BytesIO and encode to base64
        img_bytes_io = BytesIO()
        img.save(img_bytes_io, format='PNG')
        img_base64 = base64.b64encode(img_bytes_io.getvalue()).decode('utf-8')

        # Pass the base64-encoded image to the template
        return render_template('register.html', title='Register', form=form, qr_code_data=img_base64)

    return render_template('register.html', title='Register', form=form)

#Login route with rate limiting
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("3 per minute") #Sets the limitation of 3 login attempts per minute
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        totp_code = form.totp_code.data
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password): #Validates the password
            if user.totp_secret: #Checks if the user has totp (Some earlier users did not have this at a point)
                totp = pyotp.TOTP(user.totp_secret)
                if totp.verify(totp_code): #Validates the totp code
                    login_user(user)
                    user.reset_failed_login_attempts()  # Reset failed login attempts on successful login
                    db.session.commit()  # Commit the changes to the database
                    return redirect(url_for('home'))
                else:
                    flash('Invalid TOTP code. Please try again.', 'danger')
            else:
                login_user(user)
                user.reset_failed_login_attempts()  # Reset failed login attempts on successful login
                db.session.commit()  # Commit the changes to the database
                return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your username, password, and TOTP code.', 'danger')

            if user:
                user.increment_failed_login_attempts() #Adds one failed login attempt on the user to the db
                db.session.commit()

                if user.failed_login_attempts >= 3: #Checks amount of failed login attempts
                    flash('Too many failed login attempts. Please try again later.', 'danger')
                    return redirect(url_for('login'))

    return render_template('login.html', title='Login', form=form)

#Logout route
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

##Routes for clearing thetables of the database
@app.route('/clear1') #Function for clearing the posts and comments
@login_required
def clear1():
    db.session.query(Comment).delete()
    db.session.commit()
    db.session.query(Post).delete()
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/clear2') #Function for clearing the posts and comments
@login_required
def clear2():
    db.session.query(User).delete()
    db.session.commit()
    return redirect(url_for('home'))


#Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)