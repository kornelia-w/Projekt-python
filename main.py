#Potrzebne biblioteki i moduły
from flask import Flask, render_template, request, redirect, url_for #do tworzenia aplikacji webowych
from flask_sqlalchemy import SQLAlchemy #do interakcji z bazą danych
from flask_bcrypt import Bcrypt #do przechwowywania haseł
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
#do zarządzania sesjami użytkowników

#Zainicjalizowanie i konfiguracja aplikacji. Ustawienia obejmują lokalizację bazy
#danych i klucz, któy jest wymagany do obsługi sesji
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///baza_danych_tw.db'
app.config['SECRET_KEY'] = 'secretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Zdefiniowanie modelu użytkownika w bazie danych. Każdy użytkownik ma unikalne id,
# nazwę użytkownika oraz hasło. Klasa dziedziczy z UserMixin, co ułatwia integrację
# z Flask-login
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

# Zdefiniowanie modelu postu w bazie danych. Każdy post ma unikalne id, tresć oraz
# id użytkownika, któy go utworzył
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy=True))

# Funkcja, która obsługuje załadowanie użytkownika na podstawie jego id.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Strona główn aplikacji. Wyświetla wszystkie posty w kolejności od najnowszego do najstarszego.
@app.route('/')
def index():
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('index.html', posts=posts)

# Rejestrowanie nowego użytkownika. Zawiera wyświetlanie formularza rejestracji oraz obsługę
# po jego wypełnieniu. Hasło użytkownika jest hashowane za pomocą Brycypt przed zapisaniem
# do bazy danych
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# Logowanie nowego użytkownika. Zawiera formularz weryfikujący dane użytkownika. Jeśli dane
# są poprawne, użytkownik jest logowany do aplikacji, a jego sesja jest zarządzana przez Flask-login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

# Wylogowanie użytkownika. Funkcja usuwa uzytkownika z aktywnej sesji i zostaje on przekierowany
# na stronę główną.
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Dodawanie nowego postu przez zalogowanego użytkownika - treść tego postu pobierana jest z formularza
# i zostaje zapisana w bazie danych (z powiązaniem do użytkownika dodającego post).
@app.route('/add', methods=['POST'])
@login_required
def add_post():
    content = request.form['content']
    if content:
        new_post = Post(content=content, user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
    return redirect(url_for('index'))


# Usuwanie postu - funkcja ta pozwala zalogowanemu użytkownikowi na usunięcie wyłącznie jego postów.
@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id == current_user.id:
        db.session.delete(post)
        db.session.commit()
    return redirect(url_for('index'))

# Zainicjalizowanie bazy danych oraz uruchomienie aplikacji.
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)