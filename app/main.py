from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
import os
import re
from app.database import init_db, get_db
from app.auth import User

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Initialize database
with app.app_context():
    init_db()

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
    db = get_db()
    cursor = db.cursor()
    
    if search_query:
        # Simple full-text search implementation
        cursor.execute('''
            SELECT id, title, content FROM notes 
            WHERE user_id = ? AND (title LIKE ? OR content LIKE ?)
        ''', (current_user.id, f'%{search_query}%', f'%{search_query}%'))
    else:
        cursor.execute('SELECT id, title, content FROM notes WHERE user_id = ?', (current_user.id,))
    
    notes = cursor.fetchall()
    return render_template('notes.html', notes=notes, search_query=search_query)

@app.route('/notes/new', methods=['POST'])
@login_required
def new_note():
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)',
                  (current_user.id, title, content))
    db.commit()
    
    return redirect(url_for('notes'))

@app.route('/notes/<int:note_id>', methods=['GET'])
@login_required
def get_note(note_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, title, content FROM notes WHERE id = ? AND user_id = ?',
                  (note_id, current_user.id))
    note = cursor.fetchone()
    
    if note:
        return {'id': note[0], 'title': note[1], 'content': note[2]}
    return {'error': 'Not found'}, 404

@app.route('/notes/<int:note_id>/update', methods=['POST'])
@login_required
def update_note(note_id):
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?',
                  (title, content, note_id, current_user.id))
    db.commit()
    
    return redirect(url_for('notes'))

@app.route('/notes/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM notes WHERE id = ? AND user_id = ?', (note_id, current_user.id))
    db.commit()
    
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

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        if User.change_password(current_user.id, current_password, new_password):
            flash('Password changed')
        else:
            flash('Current password is wrong')
    
    return render_template('settings.html')

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)