from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length
import sqlite3
import bcrypt
import jwt
import pyotp
import datetime
from functools import wraps
import re
import json
import Levenshtein

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'  # Change in production
app.config['JWT_SECRET'] = 'your-jwt-secret-change-this'  # Change in production

# Initialize databases
def init_db():
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            totp_secret TEXT NOT NULL
        )''')
        conn.commit()
    
    with sqlite3.connect('mappings.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS vocabularies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            standard TEXT NOT NULL,
            term TEXT NOT NULL,
            description TEXT,
            uri TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS user_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            input_term TEXT,
            standard TEXT,
            mapped_term TEXT,
            uri TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        # Seed some sample vocabulary data
        sample_vocab = [
            ('SeaDataNet', 'TEMP', 'Sea water temperature', 'http://vocab.nerc.ac.uk/collection/P01/current/TEMPPR01/'),
            ('SeaDataNet', 'PSAL', 'Practical salinity', 'http://vocab.nerc.ac.uk/collection/P01/current/PSALST01/'),
            ('CF', 'sea_water_temperature', 'Sea water temperature', 'http://cfconventions.org/Data/cf-standard-names/77/'),
            ('CF', 'sea_water_practical_salinity', 'Practical salinity', 'http://cfconventions.org/Data/cf-standard-names/77/')
        ]
        c.executemany('INSERT OR IGNORE INTO vocabularies (standard, term, description, uri) VALUES (?, ?, ?, ?)', sample_vocab)
        conn.commit()

# Input sanitization
def sanitize_input(input_str):
    if not input_str:
        return input_str
    return re.sub(r'[^\w\s@.-]', '', input_str)[:100]

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        try:
            jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    totp = StringField('2FA Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Login')

class MappingForm(FlaskForm):
    input_terms = TextAreaField('Input Terms (one per line)', validators=[DataRequired()])
    standard = StringField('Target Standard (SeaDataNet or CF)', validators=[DataRequired()])
    submit = SubmitField('Map Terms')

# Vocabulary mapping logic
class VocabularyMapper:
    def __init__(self):
        self.vocab_cache = self.load_vocab()

    def load_vocab(self):
        with sqlite3.connect('mappings.db') as conn:
            c = conn.cursor()
            c.execute('SELECT standard, term, description, uri FROM vocabularies')
            return c.fetchall()

    def map_term(self, input_term, target_standard):
        input_term = input_term.lower().strip()
        best_match = None
        best_score = 0
        threshold = 0.8  # Similarity threshold

        for standard, term, description, uri in self.vocab_cache:
            if standard.lower() != target_standard.lower():
                continue
            score = Levenshtein.ratio(input_term, term.lower())
            if score > best_score and score >= threshold:
                best_score = score
                best_match = {'term': term, 'description': description, 'uri': uri, 'score': score}

        return best_match or {'term': input_term, 'description': 'No match found', 'uri': '', 'score': 0}

    def save_mapping(self, user_id, input_term, standard, mapped_term, uri):
        with sqlite3.connect('mappings.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO user_mappings (user_id, input_term, standard, mapped_term, uri) VALUES (?, ?, ?, ?, ?)',
                      (user_id, input_term, standard, mapped_term, uri))
            conn.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        password = form.password.data
        totp_code = form.totp.data

        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = c.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                totp = pyotp.TOTP(user[3])
                if totp.verify(totp_code):
                    token = jwt.encode({
                        'user_id': user[0],
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                    }, app.config['JWT_SECRET'])
                    session['token'] = token
                    return redirect(url_for('mapper'))
                else:
                    return render_template('login.html', form=form, error='Invalid 2FA code')
            else:
                return render_template('login.html', form=form, error='Invalid credentials')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = LoginForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        password = form.password.data
        totp_secret = pyotp.random_base32()

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                c.execute('INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)',
                         (username, hashed_password.decode('utf-8'), totp_secret))
                conn.commit()
            return render_template('register.html', form=form, totp_secret=totp_secret,
                                 message='Registration successful. Save this TOTP secret for 2FA.')
        except sqlite3.IntegrityError:
            return render_template('register.html', form=form, error='Username already exists')
    return render_template('register.html', form=form)

@app.route('/mapper', methods=['GET', 'POST'])
@token_required
def mapper():
    form = MappingForm()
    if form.validate_on_submit():
        input_terms = form.input_terms.data.split('\n')
        target_standard = sanitize_input(form.standard.data)
        mapper = VocabularyMapper()
        user_id = jwt.decode(session['token'], app.config['JWT_SECRET'], algorithms=['HS256'])['user_id']
        
        results = []
        for term in input_terms:
            term = term.strip()
            if term:
                result = mapper.map_term(term, target_standard)
                if result['score'] > 0:
                    mapper.save_mapping(user_id, term, target_standard, result['term'], result['uri'])
                results.append(result)
        
        # Generate JSON-LD output
        jsonld = {
            "@context": "http://schema.org",
            "@graph": [
                {
                    "@id": f"_:mapping_{i}",
                    "inputTerm": term,
                    "standard": target_standard,
                    "mappedTerm": result['term'],
                    "description": result['description'],
                    "uri": result['uri']
                } for i, (term, result) in enumerate(zip(input_terms, results))
            ]
        }
        
        return render_template('mapper.html', form=form, results=results, jsonld=json.dumps(jsonld, indent=2))
    return render_template('mapper.html', form=form)

@app.route('/export', methods=['GET'])
@token_required
def export():
    user_id = jwt.decode(session['token'], app.config['JWT_SECRET'], algorithms=['HS256'])['user_id']
    with sqlite3.connect('mappings.db') as conn:
        c = conn.cursor()
        c.execute('SELECT input_term, standard, mapped_term, uri FROM user_mappings WHERE user_id = ?', (user_id,))
        mappings = c.fetchall()
    
    jsonld = {
        "@context": "http://schema.org",
        "@graph": [
            {
                "@id": f"_:mapping_{i}",
                "inputTerm": mapping[0],
                "standard": mapping[1],
                "mappedTerm": mapping[2],
                "uri": mapping[3]
            } for i, mapping in enumerate(mappings)
        ]
    }
    
    return jsonify(jsonld)

if __name__ == '__main__':
    import os
    init_db()
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)
