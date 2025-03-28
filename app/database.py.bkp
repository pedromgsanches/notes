import sqlite3
import os
from flask import g

DATABASE = 'data/notes.db'

def get_db():
    if 'db' not in g:
        os.makedirs('data', exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cursor = db.cursor()
    
    # Criar tabela de usuários
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # Criar tabela de notas
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Verificar se o usuário admin já existe
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if cursor.fetchone() is None:
        # Criar usuário admin padrão
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', 'admin'))
    
    db.commit()