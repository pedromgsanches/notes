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

def migrate_db():
    db = get_db()
    cursor = db.cursor()
    
    # Verifica e cria tabela de usuários se não existir
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not cursor.fetchone():
        try:
            cursor.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    is_active BOOLEAN NOT NULL DEFAULT 1
                )
            ''')
            db.commit()
        except sqlite3.OperationalError as e    :
            print(f"Error creating users table: {e}")
    else:
        # Verifica e adiciona colunas faltantes na tabela users
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'role' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT "user"')
        if 'is_active' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1')
    
    # Verifica e cria tabela de notas se não existir
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notes'")
    if not cursor.fetchone():
        cursor.execute('''
            CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
    else:
        # Verifica e adiciona colunas faltantes na tabela notes
        cursor.execute("PRAGMA table_info(notes)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'created_at' not in columns:
            cursor.execute('ALTER TABLE notes ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
        if 'updated_at' not in columns:
            cursor.execute('ALTER TABLE notes ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
    
    # Verifica e cria tabela de todos se não existir
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='todos'")
    if not cursor.fetchone():
        cursor.execute('''
            CREATE TABLE todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                due_date DATE,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed INTEGER default 0,
                priority INTEGER default 0,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
    else:
        # Verifica e adiciona colunas faltantes na tabela todos
        cursor.execute("PRAGMA table_info(todos)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'description' not in columns:
            cursor.execute('ALTER TABLE todos ADD COLUMN description TEXT')
        if 'due_date' not in columns:
            cursor.execute('ALTER TABLE todos ADD COLUMN due_date DATE')
        if 'completed' not in columns:
            cursor.execute('ALTER TABLE todos ADD COLUMN completed INTEGER default 0')
        if 'priority' not in columns:
            cursor.execute('ALTER TABLE todos ADD COLUMN priority INTEGER default 0')
        if 'status' not in columns:
            cursor.execute('ALTER TABLE todos ADD COLUMN status TEXT NOT NULL DEFAULT "pending"')
        if 'created_at' not in columns:
            cursor.execute('ALTER TABLE todos ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
        if 'updated_at' not in columns:
            cursor.execute('ALTER TABLE todos ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
    
    # Verifica se existe o usuário admin
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        # Importa User aqui para evitar importação circular
        from app.auth import User
        cursor.execute('''
            INSERT INTO users (username, password, role, is_active)
            VALUES (?, ?, ?, ?)
        ''', ('admin', User.hash_password('admin'), 'admin', 1))
    
    db.commit()
    db.close()

def init_db():
    # Verifica se o banco de dados já existe
    if not os.path.exists(DATABASE):
        migrate_db()
    else:
        # Se existir, apenas verifica e atualiza a estrutura
        migrate_db()