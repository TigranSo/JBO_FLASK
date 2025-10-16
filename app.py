from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, url_for, redirect, flash, request, session
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_admin import Admin, expose
from flask_admin.contrib.sqla import ModelView
from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField, validators, SelectField
from wtforms.validators import InputRequired
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import InputRequired
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_admin.form import Select2Widget
from cryptography.fernet import Fernet
from flask_mail import Mail, Message
import random


app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///base.db'
app.config['SECRET_KEY'] = ''
db = SQLAlchemy(app)
admin = Admin(app, template_mode='bootstrap4', name='JBO')
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
admin._menu = admin._menu[1:]


app.config["MAIL_SERVER"] = ''
app.config['MAIL_PORT'] = 
app.config["MAIL_USERNAME"] = ""
app.config['MAIL_PASSWORD'] = ""
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


#Для request.user
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Генерация кода для зашифирования инвормации на базе
# key = Fernet.generate_key()
key = b''
fernet = Fernet(key)


class AdminView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin()
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))
    
    form_extra_fields = {
        'role': SelectField(
            'Role',
            choices=[
                ('admin', 'Admin'), 
                ('user', 'User'), 
                ('moderator', 'Moderator'),
                ('editor', 'Editor'), 
            ],
            widget=Select2Widget(),
            description='Choose user role'
        )
    }


#Формы регистрации, админ -----------------------------------------------------
class Registerform(FlaskForm):
    """Регистрация пользоватля """
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Имя"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Пароль"})
    captcha = StringField('Введите число', validators=[InputRequired(message="Это поле обязательно для заполнения")])
    submit = SubmitField('Зарегистрироваться')
    def validate_username(self,username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            flash('Это имя пользователя уже существует. Пожалуйста, выберите другой вариант.', 'error')
            raise ValidationError('Это имя пользователя уже существует. Пожалуйста, выберите другой вариант.')


class Loginform(FlaskForm):
	"""Вход пользователя """
	username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Имя"})
	password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Пароль"})
	submit = SubmitField('Войти')


#Модели --------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=True) 
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    documents = db.relationship('Document', back_populates='user')
	
    def is_admin(self):
        return self.role == 'admin'
    

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    _name = db.Column('name', db.String(255), nullable=False)
    _description = db.Column('description', db.Text())
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', back_populates='documents')
    
    
    @property
    def name(self):
        if isinstance(self._name, bytes):
            return fernet.decrypt(self._name).decode()
        return self._name

    @name.setter
    def name(self, value):
        self._name = fernet.encrypt(value.encode())

    @property
    def description(self):
        if self._description:
            if isinstance(self._description, bytes):
                return fernet.decrypt(self._description).decode()
            return self._description
        return None

    @description.setter
    def description(self, value):
        if value:
            self._description = fernet.encrypt(value.encode())
        else:
            self._description = None


class Jbo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column('name', db.String(255), nullable=False)
    number = db.Column('number', db.String(55), nullable=False)
    description = db.Column('description', db.Text())


#Добавим модели в админ
admin.add_view(AdminView(User, db.session))
admin.add_view(AdminView(Document, db.session))
admin.add_view(AdminView(Jbo, db.session))


#Страницы templates-------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginform()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registerform()

    if request.method == 'GET':
        num = random.randint(1000, 9999)
        session['captcha'] = str(num)
    else:
        num = session.get('captcha')

    if form.validate_on_submit():
        if form.captcha.data != session.get('captcha'):
            flash('Неправильная капча. Попробуйте еще раз.', 'error')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password) 
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form=form, num=num)




@app.route('/')
def index():
    users = User.query.count()
    jbos = Jbo.query.all()
    documents = Document.query.order_by(Document.created_at.desc()).all()
     # Расшифровка данных
    decrypted_documents = []
    for doc in documents:
        decrypted_doc = {
            'id': doc.id,
            'name': doc.name,
            'description': doc.description,
            'created_at': doc.created_at,
            'user': doc.user
        }
        # Расшифровка данных, если они не пустые
        if doc.name:
            decrypted_doc['name'] = doc.name
        if doc.description:
            decrypted_doc['description'] = doc.description
        
        decrypted_documents.append(decrypted_doc)

    return render_template('index.html', documents=decrypted_documents, users=users, jbos=jbos) 


#Добавляем документ
@app.route('/add_document', methods=['GET', 'POST'])
@login_required
def add_document():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')

        if name:
            new_document = Document(name=name, description=description, user=current_user, created_at=datetime.utcnow())
            # базу данных
            db.session.add(new_document)
            db.session.commit()
            
            flash('Ваша история опубликована!', 'success')
            return redirect(url_for('index'))

    return render_template('add_document.html')



@app.route('/send_message', methods=['GET','POST'])
@login_required
def send_message():
    user = current_user.username
    if request.method == "POST":
        username = request.form['username']
        email = request.form["email"]
        msg = request.form['message']

        message = Message(username, sender= "tikoapotrt78@gmail.com", recipients=[email])

        message.body = ("Имя, " + user + " " + "\nКомментарий: " + msg)

        mail.send(message)

        flash('Отправлено.', 'error')

        return redirect(url_for('index'))

    return render_template("send_message.html")


@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    documents = Document.query.filter_by(user=current_user).order_by(Document.created_at.desc()).all()
     # Расшифровка данных
    decrypted_documents = []
    for doc in documents:
        decrypted_doc = {
            'id': doc.id,
            'name': doc.name,
            'description': doc.description,
            'created_at': doc.created_at,
            'user': doc.user
        }
        # Расшифровка данных, если они не пустые
        if doc.name:
            decrypted_doc['name'] = doc.name
        if doc.description:
            decrypted_doc['description'] = doc.description
        
        decrypted_documents.append(decrypted_doc)
    return render_template("profile.html", documents=decrypted_documents)


@app.route('/delete_document/<int:document_id>', methods=['POST'])
@login_required
def delete_document(document_id):
    document = Document.query.get_or_404(document_id)

    if document.user != current_user:
        return redirect(url_for('profile'))

    db.session.delete(document)
    db.session.commit()

    return redirect(url_for('profile'))


if __name__ == '__main__':
    app.run(debug=True)

