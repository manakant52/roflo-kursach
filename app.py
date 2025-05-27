from flask import Flask, render_template, request, redirect, session, url_for, g
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'
DATABASE = os.path.join(os.path.dirname(__file__), 'database.db')

# Функция для подключения к базе данных
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

# Закрытие соединения при завершении
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        is_admin INTEGER DEFAULT 0)''')
        # Добавляем тестового администратора, если его нет
        cursor.execute('SELECT * FROM users WHERE username = "admin"')
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                         ('admin', 'securepassword', 1))
        db.commit()

init_db()



def secure_login(username, password):
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Безопасный параметризованный запрос
        cursor.execute(
            "SELECT * FROM users WHERE username = ?", 
            (username,)
        )
        user = cursor.fetchone()
        
        # Проверка хеша пароля
        if user and bcrypt.checkpw(password.encode(), user["password_hash"]):
            return user
        return None
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return "Please fill all fields", 400
            
        user = vulnerable_login(username, password)
        
        if user:
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('dashboard'))
        return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/register.html', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return "Please fill all fields", 400
        
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                          (username, password))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already exists", 400
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return "Registration failed", 500
    return render_template('register.html')

@app.route('/dashboard.html')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        if session.get('is_admin'):
            cursor.execute("SELECT id, username, is_admin FROM users")
        else:
            cursor.execute("SELECT id, username, is_admin FROM users WHERE id = ?",
                           (session['user_id'],))
        
        users = cursor.fetchall()
        return render_template('dashboard.html',
                              users=users,
                              is_admin=session.get('is_admin'))
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "Database error", 500

@app.route('/logout.html')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)