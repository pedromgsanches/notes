from flask_login import UserMixin
from app.database import get_db

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password
    
    @staticmethod
    def get(user_id):
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, username, password FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            return User(user[0], user[1], user[2])
        return None
    
    @staticmethod
    def authenticate(username, password):
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, username, password FROM users WHERE username = ? AND password = ?',
                      (username, password))
        user = cursor.fetchone()
        if user:
            return User(user[0], user[1], user[2])
        return None
    
    @staticmethod
    def change_password(user_id, current_password, new_password):
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if user and user[0] == current_password:
            cursor.execute('UPDATE users SET password = ? WHERE id = ?', (new_password, user_id))
            db.commit()
            return True
        return False