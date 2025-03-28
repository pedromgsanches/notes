from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
import os
import re
import markdown
from app.database import init_db, get_db
from app.auth import User
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import timedelta

app = Flask(__name__)
# Usar uma chave secreta fixa para manter as sessões entre reinicializações
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-please-change-in-production')
app.permanent_session_lifetime = timedelta(days=7)  # Sessão dura 7 dias

# Configure login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'  # Proteção adicional para a sessão

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Initialize database
with app.app_context():
    init_db()

@app.before_request
def make_session_permanent():
    session.permanent = True  # Torna a sessão permanente

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('notes'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('notes'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.authenticate(username, password)
        if user:
            login_user(user)
            return redirect(url_for('notes'))
        else:
            flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/notes')
@login_required
def notes():
    search_query = request.args.get('search', '')
    
    conn = get_db()
    if search_query:
        cursor = conn.execute('''
            SELECT id, title, content 
            FROM notes 
            WHERE user_id = ? 
            AND (title LIKE ? OR content LIKE ?)
            ORDER BY id DESC
        ''', (current_user.id, f'%{search_query}%', f'%{search_query}%'))
    else:
        cursor = conn.execute('''
            SELECT id, title, content 
            FROM notes 
            WHERE user_id = ? 
            ORDER BY id DESC
        ''', (current_user.id,))
    
    notes = cursor.fetchall()
    conn.close()
    
    return render_template('notes.html', notes=notes, search_query=search_query)

@app.route('/notes/<int:id>')
@login_required
def get_note(id):
    conn = get_db()
    note = conn.execute('''
        SELECT id, title, content 
        FROM notes 
        WHERE id = ? AND user_id = ?
    ''', (id, current_user.id)).fetchone()
    conn.close()
    
    if note is None:
        return {'error': 'Note not found'}, 404
        
    return {
        'id': note[0],
        'title': note[1],
        'content': note[2]
    }

@app.route('/notes/new', methods=['POST'])
@login_required
def new_note():
    title = request.form['title']
    content = request.form['content']
    
    conn = get_db()
    conn.execute('''
        INSERT INTO notes (title, content, user_id)
        VALUES (?, ?, ?)
    ''', (title, content, current_user.id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('notes'))

@app.route('/notes/<int:id>/update', methods=['POST'])
@login_required
def update_note(id):
    title = request.form['title']
    content = request.form['content']
    
    conn = get_db()
    conn.execute('''
        UPDATE notes 
        SET title = ?, content = ?
        WHERE id = ? AND user_id = ?
    ''', (title, content, id, current_user.id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('notes'))

@app.route('/notes/<int:id>/delete', methods=['POST'])
@login_required
def delete_note(id):
    conn = get_db()
    conn.execute('DELETE FROM notes WHERE id = ? AND user_id = ?', (id, current_user.id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('notes'))

# Todo Routes
@app.route('/todos')
@login_required
def todos():
    search_query = request.args.get('search', '')
    db = get_db()
    cursor = db.cursor()
    
    if search_query:
        cursor.execute('''
            SELECT id, title, completed, priority, due_date FROM todos 
            WHERE user_id = ? AND title LIKE ?
        ''', (current_user.id, f'%{search_query}%'))
    else:
        cursor.execute('''
            SELECT id, title, completed, priority, due_date FROM todos 
            WHERE user_id = ? 
            ORDER BY completed, priority DESC, due_date
        ''', (current_user.id,))
    
    todos = cursor.fetchall()
    return render_template('todo.html', todos=todos, search_query=search_query)

@app.route('/todos/new', methods=['POST'])
@login_required
def new_todo():
    title = request.form.get('title', '')
    priority = request.form.get('priority', 0)
    due_date = request.form.get('due_date', '')
    completed = request.form.get('completed', 0)
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO todos (user_id, title, priority, due_date, completed) 
        VALUES (?, ?, ?, ?, ?)
    ''', (current_user.id, title, priority, due_date if due_date else None, completed))
    db.commit()
    
    return redirect(url_for('todos'))

@app.route('/todos/<int:todo_id>', methods=['GET'])
@login_required
def get_todo(todo_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT id, title, priority, due_date, completed 
        FROM todos 
        WHERE id = ? AND user_id = ?
    ''', (todo_id, current_user.id))
    todo = cursor.fetchone()
    
    if todo:
        return {
            'id': todo[0],
            'title': todo[1],
            'priority': todo[2],
            'due_date': todo[3],
            'completed': todo[4]
        }
    return {'error': 'Not found'}, 404

@app.route('/todos/<int:todo_id>/update', methods=['POST'])
@login_required
def update_todo(todo_id):
    title = request.form.get('title', '')
    priority = request.form.get('priority', 0)
    due_date = request.form.get('due_date', '')
    completed = request.form.get('completed', 0)
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        UPDATE todos 
        SET title = ?, priority = ?, due_date = ?, completed = ? 
        WHERE id = ? AND user_id = ?
    ''', (title, priority, due_date if due_date else None, completed, todo_id, current_user.id))
    db.commit()
    
    return redirect(url_for('todos'))

@app.route('/todos/<int:todo_id>/delete', methods=['POST'])
@login_required
def delete_todo(todo_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM todos WHERE id = ? AND user_id = ?', (todo_id, current_user.id))
    db.commit()
    
    return redirect(url_for('todos'))

@app.route('/todos/<int:todo_id>/toggle_completed', methods=['POST'])
@login_required
def toggle_todo_completed(todo_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE todos SET completed = NOT completed WHERE id = ? AND user_id = ?',
                  (todo_id, current_user.id))
    db.commit()
    return redirect(url_for('todos'))

@app.route('/help')
@login_required
def help():
    return render_template('help.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        if User.change_password(current_user.id, current_password, new_password):
            flash('Password changed successfully')
        else:
            flash('Current password is incorrect')
    
    # Se for admin, buscar lista de usuários
    users = None
    if current_user.role == 'admin':
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, username, role, is_active FROM users WHERE username != ?', (current_user.username,))
        users = cursor.fetchall()
    
    return render_template('settings.html', users=users)

@app.route('/about')
def about():
    return render_template('about.html')

def is_admin():
    return current_user.is_authenticated and current_user.role == 'admin'

@app.route('/users/new', methods=['POST'])
@login_required
def new_user():
    if not is_admin():
        flash('Access denied')
        return redirect(url_for('notes'))
    
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')
    
    if not username or not password:
        flash('Username and password are required')
        return redirect(url_for('settings'))
    
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                      (username, User.hash_password(password), role))
        db.commit()
        flash('User created successfully')
    except sqlite3.IntegrityError:
        flash('Username already exists')
    except Exception as e:
        flash('Error creating user')
    
    return redirect(url_for('settings'))

@app.route('/users/<int:user_id>/toggle_active', methods=['POST'])
@login_required
def toggle_user_active(user_id):
    if not is_admin():
        flash('Access denied')
        return redirect(url_for('notes'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE users SET is_active = NOT is_active WHERE id = ? AND username != ?',
                  (user_id, current_user.username))
    db.commit()
    
    return redirect(url_for('settings'))

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not is_admin():
        flash('Access denied')
        return redirect(url_for('notes'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM users WHERE id = ? AND username != ?', (user_id, current_user.username))
    db.commit()
    
    return redirect(url_for('settings'))

@app.route('/users/<int:user_id>/change_password', methods=['POST'])
@login_required
def change_user_password(user_id):
    if not is_admin():
        flash('Access denied')
        return redirect(url_for('notes'))
    
    new_password = request.form.get('new_password', '')
    if not new_password:
        flash('New password is required')
        return redirect(url_for('settings'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE users SET password = ? WHERE id = ? AND username != ?',
                  (User.hash_password(new_password), user_id, current_user.username))
    db.commit()
    
    flash('Password changed successfully')
    return redirect(url_for('settings'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)