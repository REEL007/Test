"""
Mini Réseau Social avec Flask - Version Monofichier

Fonctionnalités:
- Inscription (nom d'utilisateur, email, mot de passe hashé)
- Connexion/Déconnexion
- Profil utilisateur avec biographie modifiable
- Recherche d'autres utilisateurs
- Système d'amis (demandes d'amis, acceptation)
- Messagerie privée entre amis

Base de données: SQLite
Interface: HTML/CSS intégré

Pour exécuter:
1. python app.py
2. Accédez à http://localhost:5000
"""

from flask import Flask, render_template_string, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Clé secrète générée aléatoirement
app.config['DATABASE'] = 'social_network.db'

# CSS commun pour toutes les pages
COMMON_CSS = """
<style>
    * {
        box-sizing: border-box;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    body {
        margin: 0;
        padding: 0;
        background-color: #f5f5f5;
        color: #333;
    }
    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
    }
    header {
        background-color: #4267B2;
        color: white;
        padding: 15px 0;
        margin-bottom: 30px;
    }
    header .container {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    nav a {
        color: white;
        text-decoration: none;
        margin-left: 15px;
    }
    nav a:hover {
        text-decoration: underline;
    }
    .card {
        background-color: white;
        border-radius: 5px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        padding: 20px;
        margin-bottom: 20px;
    }
    .form-group {
        margin-bottom: 15px;
    }
    .form-group label {
        display: block;
        margin-bottom: 5px;
        font-weight: bold;
    }
    .form-group input, .form-group textarea {
        width: 100%;
        padding: 10px;
        border: 1px solid #ddd;
        border-radius: 4px;
    }
    .btn {
        background-color: #4267B2;
        color: white;
        border: none;
        padding: 10px 15px;
        border-radius: 4px;
        cursor: pointer;
        text-decoration: none;
        display: inline-block;
    }
    .btn:hover {
        background-color: #365899;
    }
    .btn-danger {
        background-color: #dc3545;
    }
    .btn-danger:hover {
        background-color: #c82333;
    }
    .btn-success {
        background-color: #28a745;
    }
    .btn-success:hover {
        background-color: #218838;
    }
    .alert {
        padding: 15px;
        margin-bottom: 20px;
        border-radius: 4px;
    }
    .alert-success {
        background-color: #d4edda;
        color: #155724;
    }
    .alert-error {
        background-color: #f8d7da;
        color: #721c24;
    }
    .alert-info {
        background-color: #d1ecf1;
        color: #0c5460;
    }
    .user-list {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
        gap: 20px;
    }
    .user-card {
        border: 1px solid #ddd;
        padding: 15px;
        border-radius: 5px;
        background-color: white;
    }
    .message-container {
        max-height: 400px;
        overflow-y: auto;
        margin-bottom: 20px;
        border: 1px solid #ddd;
        padding: 15px;
        border-radius: 5px;
        background-color: white;
    }
    .message {
        margin-bottom: 15px;
        padding-bottom: 15px;
        border-bottom: 1px solid #eee;
    }
    .message:last-child {
        border-bottom: none;
        margin-bottom: 0;
        padding-bottom: 0;
    }
    .message-sender {
        font-weight: bold;
        color: #4267B2;
    }
    .message-time {
        font-size: 0.8em;
        color: #777;
    }
    .unread-count {
        background-color: #dc3545;
        color: white;
        border-radius: 50%;
        padding: 2px 6px;
        font-size: 0.8em;
        margin-left: 5px;
    }
    .friends-container {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        gap: 20px;
    }
    .friend-section {
        background-color: white;
        padding: 15px;
        border-radius: 5px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
</style>
"""

# Fonctions utilitaires pour la base de données
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        # Création des tables si elles n'existent pas
        db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        db.execute('''
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT NOT NULL, -- 'pending' or 'accepted'
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (friend_id) REFERENCES users (id),
            UNIQUE(user_id, friend_id)
        )
        ''')
        
        db.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )
        ''')
        db.commit()

# Templates HTML
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mini Réseau Social - {{ title }}</title>
    {{ common_css }}
</head>
<body>
    <header>
        <div class="container">
            <h1>Mini Réseau Social</h1>
            <nav>
                {% if 'user_id' in session %}
                    <a href="{{ url_for('index') }}">Accueil</a>
                    <a href="{{ url_for('profile') }}">Profil</a>
                    <a href="{{ url_for('search') }}">Recherche</a>
                    <a href="{{ url_for('friends') }}">Amis</a>
                    <a href="{{ url_for('messages') }}">Messages</a>
                    <a href="{{ url_for('logout') }}">Déconnexion</a>
                {% else %}
                    <a href="{{ url_for('login') }}">Connexion</a>
                    <a href="{{ url_for('register') }}">Inscription</a>
                {% endif %}
            </nav>
        </div>
    </header>
    
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

INDEX_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
    <h2>Bienvenue, {{ user.username }}!</h2>
    
    <div class="card">
        <h3>Votre profil</h3>
        <p>{{ user.bio or "Vous n'avez pas encore de biographie." }}</p>
        <a href="{{ url_for('profile') }}" class="btn">Modifier le profil</a>
    </div>
    
    <div class="card">
        <h3>Vos amis</h3>
        {% if friends %}
            <div class="user-list">
                {% for friend in friends %}
                    <div class="user-card">
                        <h4>{{ friend.username }}</h4>
                        <a href="{{ url_for('messages', friend_id=friend.id) }}" class="btn">Envoyer un message</a>
                    </div>
                {% endfor %}
            </div>
        {% else %}
            <p>Vous n'avez pas encore d'amis. <a href="{{ url_for('search') }}">Rechercher des utilisateurs</a></p>
        {% endif %}
    </div>
    
    {% if friend_requests %}
    <div class="card">
        <h3>Demandes d'amis reçues</h3>
        <div class="user-list">
            {% for request in friend_requests %}
                <div class="user-card">
                    <h4>{{ request.username }}</h4>
                    <a href="{{ url_for('accept_friend', friend_id=request.id) }}" class="btn btn-success">Accepter</a>
                </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}
    
    {% if unread_messages > 0 %}
    <div class="card">
        <p>Vous avez {{ unread_messages }} message(s) non lu(s). <a href="{{ url_for('messages') }}" class="btn">Voir les messages</a></p>
    </div>
    {% endif %}
{% endblock %}
"""

LOGIN_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
    <div class="card">
        <h2>Connexion</h2>
        <form action="{{ url_for('login') }}" method="post">
            <div class="form-group">
                <label for="username">Nom d'utilisateur</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Mot de passe</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">Se connecter</button>
        </form>
        <p>Pas encore de compte? <a href="{{ url_for('register') }}">S'inscrire</a></p>
    </div>
{% endblock %}
"""

REGISTER_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
    <div class="card">
        <h2>Inscription</h2>
        <form action="{{ url_for('register') }}" method="post">
            <div class="form-group">
                <label for="username">Nom d'utilisateur</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Mot de passe</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirmer le mot de passe</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            <button type="submit" class="btn">S'inscrire</button>
        </form>
        <p>Déjà un compte? <a href="{{ url_for('login') }}">Se connecter</a></p>
    </div>
{% endblock %}
"""

PROFILE_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
    <div class="card">
        <h2>Votre profil</h2>
        <form action="{{ url_for('profile') }}" method="post">
            <div class="form-group">
                <label for="username">Nom d'utilisateur</label>
                <input type="text" id="username" value="{{ user.username }}" disabled>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" value="{{ user.email }}" disabled>
            </div>
            <div class="form-group">
                <label for="bio">Biographie</label>
                <textarea id="bio" name="bio" rows="4">{{ user.bio or '' }}</textarea>
            </div>
            <button type="submit" class="btn">Mettre à jour</button>
        </form>
    </div>
{% endblock %}
"""

SEARCH_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
    <div class="card">
        <h2>Rechercher des utilisateurs</h2>
        <form action="{{ url_for('search') }}" method="post">
            <div class="form-group">
                <input type="text" name="search_term" placeholder="Rechercher par nom d'utilisateur..." required>
            </div>
            <button type="submit" class="btn">Rechercher</button>
        </form>
    </div>
    
    {% if results %}
    <div class="card">
        <h3>Résultats de la recherche</h3>
        <div class="user-list">
            {% for user in results %}
                <div class="user-card">
                    <h4>{{ user.username }}</h4>
                    <p>{{ user.bio or "Pas de biographie" }}</p>
                    <a href="{{ url_for('add_friend', friend_id=user.id) }}" class="btn">Ajouter comme ami</a>
                </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}
{% endblock %}
"""

FRIENDS_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
    <div class="friends-container">
        <div class="friend-section">
            <h2>Vos amis</h2>
            {% if friends %}
                <div class="user-list">
                    {% for friend in friends %}
                        <div class="user-card">
                            <h4>{{ friend.username }}</h4>
                            <a href="{{ url_for('messages', friend_id=friend.id) }}" class="btn">Envoyer un message</a>
                        </div>
                    {% endfor %}
                </div>
            {% else %}
                <p>Vous n'avez pas encore d'amis.</p>
            {% endif %}
        </div>
        
        <div class="friend-section">
            <h2>Demandes envoyées</h2>
            {% if sent_requests %}
                <div class="user-list">
                    {% for request in sent_requests %}
                        <div class="user-card">
                            <h4>{{ request.username }}</h4>
                            <p class="text-muted">En attente de réponse</p>
                        </div>
                    {% endfor %}
                </div>
            {% else %}
                <p>Aucune demande envoyée.</p>
            {% endif %}
        </div>
        
        <div class="friend-section">
            <h2>Demandes reçues</h2>
            {% if received_requests %}
                <div class="user-list">
                    {% for request in received_requests %}
                        <div class="user-card">
                            <h4>{{ request.username }}</h4>
                            <a href="{{ url_for('accept_friend', friend_id=request.id) }}" class="btn btn-success">Accepter</a>
                        </div>
                    {% endfor %}
                </div>
            {% else %}
                <p>Aucune demande reçue.</p>
            {% endif %}
        </div>
    </div>
{% endblock %}
"""

MESSAGES_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
    <div class="friends-container">
        <div class="friend-section">
            <h2>Conversations</h2>
            {% if friends %}
                <div class="user-list">
                    {% for friend in friends %}
                        <a href="{{ url_for('messages', friend_id=friend.id) }}" class="user-card" style="display: block; text-decoration: none; color: inherit;">
                            <h4>{{ friend.username }}</h4>
                        </a>
                    {% endfor %}
                </div>
            {% else %}
                <p>Vous n'avez pas encore d'amis pour discuter.</p>
            {% endif %}
        </div>
        
        <div class="friend-section" style="flex: 2;">
            {% if current_friend_id %}
                <h2>Conversation avec {{ messages[0].sender_name if messages and messages[0].sender_id == current_friend_id else friend_username }}</h2>
                
                <div class="message-container">
                    {% if messages %}
                        {% for message in messages %}
                            <div class="message">
                                <div class="message-sender">{{ message.sender_name }}</div>
                                <div class="message-content">{{ message.content }}</div>
                                <div class="message-time">{{ message.created_at }}</div>
                            </div>
                        {% endfor %}
                    {% else %}
                        <p>Aucun message échangé pour le moment.</p>
                    {% endif %}
                </div>
                
                <form action="{{ url_for('send_message') }}" method="post">
                    <input type="hidden" name="friend_id" value="{{ current_friend_id }}">
                    <div class="form-group">
                        <textarea name="content" rows="3" placeholder="Votre message..." required></textarea>
                    </div>
                    <button type="submit" class="btn">Envoyer</button>
                </form>
            {% else %}
                <h2>Sélectionnez une conversation</h2>
                <p>Choisissez un ami dans la liste pour commencer à discuter.</p>
            {% endif %}
        </div>
    </div>
{% endblock %}
"""

# Routes de l'application
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Récupérer les amis
    friends = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON (friendships.friend_id = users.id AND friendships.user_id = ? AND friendships.status = 'accepted')
    OR (friendships.user_id = users.id AND friendships.friend_id = ? AND friendships.status = 'accepted')
    ''', (session['user_id'], session['user_id'])).fetchall()
    
    # Récupérer les demandes d'amis reçues
    friend_requests = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON friendships.user_id = users.id 
    WHERE friendships.friend_id = ? AND friendships.status = 'pending'
    ''', (session['user_id'],)).fetchall()
    
    # Récupérer les messages non lus
    unread_messages = db.execute('''
    SELECT COUNT(*) as count FROM messages 
    WHERE receiver_id = ? AND is_read = FALSE
    ''', (session['user_id'],)).fetchone()['count']
    
    return render_template_string(BASE_TEMPLATE + INDEX_TEMPLATE, 
                               title="Accueil",
                               common_css=COMMON_CSS,
                               user=user, 
                               friends=friends, 
                               friend_requests=friend_requests, 
                               unread_messages=unread_messages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                       (username, email, hashed_password))
            db.commit()
            flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Nom d\'utilisateur ou email déjà utilisé', 'error')
            return redirect(url_for('register'))
    
    return render_template_string(BASE_TEMPLATE + REGISTER_TEMPLATE, 
                               title="Inscription",
                               common_css=COMMON_CSS)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Connexion réussie!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')
            return redirect(url_for('login'))
    
    return render_template_string(BASE_TEMPLATE + LOGIN_TEMPLATE, 
                               title="Connexion",
                               common_css=COMMON_CSS)

@app.route('/logout')
def logout():
    session.clear()
    flash('Vous avez été déconnecté', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    if request.method == 'POST':
        bio = request.form['bio']
        db.execute('UPDATE users SET bio = ? WHERE id = ?', (bio, session['user_id']))
        db.commit()
        flash('Profil mis à jour!', 'success')
        return redirect(url_for('profile'))
    
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return render_template_string(BASE_TEMPLATE + PROFILE_TEMPLATE, 
                               title="Profil",
                               common_css=COMMON_CSS,
                               user=user)

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    results = []
    
    if request.method == 'POST':
        search_term = f"%{request.form['search_term']}%"
        results = db.execute('''
        SELECT id, username, bio FROM users 
        WHERE username LIKE ? AND id != ?
        ''', (search_term, session['user_id'])).fetchall()
    
    return render_template_string(BASE_TEMPLATE + SEARCH_TEMPLATE, 
                               title="Recherche",
                               common_css=COMMON_CSS,
                               results=results)

@app.route('/add_friend/<int:friend_id>')
def add_friend(friend_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Vérifier si la demande d'ami existe déjà
    existing = db.execute('''
    SELECT * FROM friendships 
    WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
    ''', (session['user_id'], friend_id, friend_id, session['user_id'])).fetchone()
    
    if existing:
        flash('Demande d\'ami déjà envoyée ou déjà ami', 'info')
    else:
        db.execute('''
        INSERT INTO friendships (user_id, friend_id, status) 
        VALUES (?, ?, 'pending')
        ''', (session['user_id'], friend_id))
        db.commit()
        flash('Demande d\'ami envoyée!', 'success')
    
    return redirect(url_for('search'))

@app.route('/accept_friend/<int:friend_id>')
def accept_friend(friend_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Vérifier que la demande existe et est en attente
    request_exists = db.execute('''
    SELECT * FROM friendships 
    WHERE user_id = ? AND friend_id = ? AND status = 'pending'
    ''', (friend_id, session['user_id'])).fetchone()
    
    if request_exists:
        db.execute('''
        UPDATE friendships SET status = 'accepted' 
        WHERE user_id = ? AND friend_id = ?
        ''', (friend_id, session['user_id']))
        db.commit()
        flash('Demande d\'ami acceptée!', 'success')
    else:
        flash('Demande d\'ami non trouvée', 'error')
    
    return redirect(url_for('friends'))

@app.route('/friends')
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Amis acceptés
    friends = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON (friendships.friend_id = users.id AND friendships.user_id = ? AND friendships.status = 'accepted')
    OR (friendships.user_id = users.id AND friendships.friend_id = ? AND friendships.status = 'accepted')
    ''', (session['user_id'], session['user_id'])).fetchall()
    
    # Demandes envoyées en attente
    sent_requests = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON friendships.friend_id = users.id 
    WHERE friendships.user_id = ? AND friendships.status = 'pending'
    ''', (session['user_id'],)).fetchall()
    
    # Demandes reçues en attente
    received_requests = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON friendships.user_id = users.id 
    WHERE friendships.friend_id = ? AND friendships.status = 'pending'
    ''', (session['user_id'],)).fetchall()
    
    return render_template_string(BASE_TEMPLATE + FRIENDS_TEMPLATE, 
                               title="Amis",
                               common_css=COMMON_CSS,
                               friends=friends, 
                               sent_requests=sent_requests, 
                               received_requests=received_requests)

@app.route('/messages')
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    friend_id = request.args.get('friend_id', type=int)
    
    # Liste des amis pour le menu
    friends = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON (friendships.friend_id = users.id AND friendships.user_id = ? AND friendships.status = 'accepted')
    OR (friendships.user_id = users.id AND friendships.friend_id = ? AND friendships.status = 'accepted')
    ''', (session['user_id'], session['user_id'])).fetchall()
    
    messages = []
    friend_username = ""
    if friend_id:
        # Marquer les messages comme lus
        db.execute('''
        UPDATE messages SET is_read = TRUE 
        WHERE sender_id = ? AND receiver_id = ? AND is_read = FALSE
        ''', (friend_id, session['user_id']))
        db.commit()
        
        # Récupérer le nom d'utilisateur de l'ami
        friend = db.execute('SELECT username FROM users WHERE id = ?', (friend_id,)).fetchone()
        if friend:
            friend_username = friend['username']
        
        # Récupérer la conversation
        messages = db.execute('''
        SELECT m.*, u.username as sender_name FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.created_at
        ''', (session['user_id'], friend_id, friend_id, session['user_id'])).fetchall()
    
    return render_template_string(BASE_TEMPLATE + MESSAGES_TEMPLATE, 
                               title="Messages",
                               common_css=COMMON_CSS,
                               friends=friends, 
                               messages=messages, 
                               current_friend_id=friend_id,
                               friend_username=friend_username)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    friend_id = request.form['friend_id']
    content = request.form['content']
    
    if not content:
        flash('Le message ne peut pas être vide', 'error')
        return redirect(url_for('messages', friend_id=friend_id))
    
    db = get_db()
    
    # Vérifier que les utilisateurs sont amis
    are_friends = db.execute('''
    SELECT * FROM friendships 
    WHERE ((user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)) 
    AND status = 'accepted'
    ''', (session['user_id'], friend_id, friend_id, session['user_id'])).fetchone()
    
    if not are_friends:
        flash('Vous ne pouvez envoyer des messages qu\'à vos amis', 'error')
        return redirect(url_for('messages', friend_id=friend_id))
    
    db.execute('''
    INSERT INTO messages (sender_id, receiver_id, content) 
    VALUES (?, ?, ?)
    ''', (session['user_id'], friend_id, content))
    db.commit()
    
    return redirect(url_for('messages', friend_id=friend_id))

if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    app.run(debug=False)