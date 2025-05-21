from flask import Flask, request, jsonify, redirect, url_for, session, render_template
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
import sqlite3
from datetime import datetime
from pyngrok import ngrok, conf
from flask_socketio import SocketIO
import threading
import time
from smartcard.System import readers
from smartcard.Exceptions import NoCardException
from smartcard.util import toHexString
import hashlib
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from scripts.czech_lunch_scraper import main as scrape_lunch_pdfs

# Load environment variables
load_dotenv()

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure the app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Kill any existing ngrok tunnels
ngrok.kill()

# Start ngrok tunnel
public_url = ngrok.connect(addr="http://127.0.0.1:5000", domain="lamb-kind-preferably.ngrok-free.app")
print(f" * ngrok tunnel \"{public_url}\" -> \"http://127.0.0.1:5000\"")

# Global variable to store the scanned card UID
scanned_card_uid = None

# Add these constants after other app configurations
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH', generate_password_hash('admin123'))  # Change this in production!
ALLOWED_ADMIN_EMAILS = ["1143@student.itgymnazium.cz"]

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session['user'].get('email') not in ALLOWED_ADMIN_EMAILS:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def nfc_card_scanner():
    """Continuously scans for NFC cards and emits event via WebSocket."""
    r = readers()
    if not r:
        print("No NFC reader detected.")
        return

    reader = r[0]
    connection = reader.createConnection()
    last_uid = None

    while True:
        try:
            connection.connect()
            GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            response, sw1, sw2 = connection.transmit(GET_UID)

            if sw1 == 0x90 and sw2 == 0x00:
                uid = toHexString(response)

                if uid != last_uid:
                    last_uid = uid
                    print(f"Card detected: {uid}")

                    hashed_uid = hashlib.sha256(uid.encode()).hexdigest()

                    with app.app_context():
                        conn = get_db()
                        c = conn.cursor()
                        
                        # Get student info
                        c.execute("SELECT * FROM students WHERE card_id = ?", (hashed_uid,))
                        student = c.fetchone()
                        
                        if student:
                            # Get today's lunch info for this student
                            today = datetime.now().strftime("%Y-%m-%d")
                            c.execute("SELECT * FROM obed WHERE jmeno = ? AND datum = ?", (student['name'], today))
                            lunch = c.fetchone()
                            
                            lunch_number = None
                            if lunch:
                                if lunch['obed_1'] == 1:
                                    lunch_number = 1
                                elif lunch['obed_2'] == 1:
                                    lunch_number = 2
                                elif lunch['obed_3'] == 1:
                                    lunch_number = 3
                            
                            print(f"Card belongs to student: {student['name']}, Lunch: {lunch_number}")
                            socketio.emit('card_scanned', {
                                'student_id': student['id'],
                                'student_name': student['name'],
                                'lunch_number': lunch_number
                            })
                        else:
                            print("Card not assigned, emitting raw UID")
                            socketio.emit('card_scanned', {'uid': uid})
                        
                        conn.close()

            else:
                last_uid = None

        except NoCardException:
            last_uid = None
        except Exception as e:
            print(f"[NFC ERROR] {e}")
            time.sleep(0.1)

# Start the card reader thread
threading.Thread(target=nfc_card_scanner, daemon=True).start()

@app.route('/check_card', methods=['GET'])
def check_card():
    """Checks if an NFC card has been scanned and returns the student info."""
    global scanned_card_uid
    if scanned_card_uid:
        uid = hashlib.sha256(scanned_card_uid.encode()).hexdigest()
        scanned_card_uid = None  # Reset the UID after processing
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM students WHERE card_id = ?", (uid,))
        student = c.fetchone()
        conn.close()
        
        if student:
            return jsonify({'success': True, 'student': dict(student)})
    return jsonify({'success': False})

@app.route('/check_card_uid', methods=['GET'])
def check_card_uid():
    """Returns the raw UID of the last scanned card."""
    global scanned_card_uid
    if scanned_card_uid:
        uid = scanned_card_uid
        scanned_card_uid = None  # Reset after reading
        return jsonify({'uid': uid})
    return jsonify({'uid': None})

def get_db():
    """Get database connection"""
    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, 'icanteen.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables"""
    conn = get_db()
    c = conn.cursor()
    # Create obed table
    c.execute('''
        CREATE TABLE IF NOT EXISTS obed (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jmeno TEXT,
            obed_1 INTEGER,
            obed_2 INTEGER,
            obed_3 INTEGER,
            datum TEXT
        )
    ''')
    # Create students table
    c.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            card_id TEXT UNIQUE NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized successfully")

# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://openidconnect.googleapis.com/v1/',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post',
        'prompt': 'select_account',
        'hd': None  # Allow any Google account, not just organization accounts
    }
)

def normalize_name(name):
    """Normalize a name for comparison"""
    return ' '.join(name.lower().split())

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    print("\n=== LOGIN ATTEMPT ===")
    try:
        redirect_uri = url_for('authorize', _external=True)
        print(f"Redirect URI: {redirect_uri}")
        print(f"Client ID: {os.getenv('GOOGLE_CLIENT_ID')}")
        print(f"Client Secret exists: {bool(os.getenv('GOOGLE_CLIENT_SECRET'))}")
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        print(f"Login error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return redirect(url_for('index'))

@app.route('/authorize')
def authorize():
    print("\n=== AUTHORIZATION START ===")
    try:
        print("Getting access token...")
        token = google.authorize_access_token()
        if not token:
            print("No token received from Google")
            return redirect(url_for('login'))
        print(f"Token received: {token}")
            
        print("Getting user info...")
        user_info = google.get('userinfo').json()
        if not user_info:
            print("No user info received from Google")
            return redirect(url_for('login'))
        print(f"User info received: {user_info}")
            
        full_name = user_info.get('name')
        email = user_info.get('email')
        if not full_name:
            print("No name in user info")
            return redirect(url_for('login'))
        print(f"Full name: {full_name}")
        print(f"Email: {email}")

        # Store user info in session
        print("\nStoring session data...")
        session.clear()  # Clear any existing session data
        session['user'] = user_info
        session['token'] = token
        print(f"Session data stored: {session}")

        # If admin email, redirect to admin panel
        if email in ALLOWED_ADMIN_EMAILS:
            print(f"Admin user detected ({email}), redirecting to admin panel")
            return redirect(url_for('admin'))
        
        # Otherwise proceed with normal student flow
        # Debug print
        print(f"\n=== NAME MATCHING DEBUG ===")
        print(f"Google name: {full_name}")
        normalized_name = normalize_name(full_name)
        print(f"Normalized name: {normalized_name}")

        # Get student's lunch from icanteen.db
        print("\nChecking database...")
        conn = get_db()
        c = conn.cursor()
        
        # Try to find student in database - using today's date
        today = datetime.now().strftime("%Y-%m-%d")
        c.execute("SELECT * FROM obed WHERE jmeno = ? AND datum = ?", (full_name, today))
        student = c.fetchone()
        print(f"Direct match result: {student}")
        
        if not student:
            print("No direct match, trying normalized name...")
            # Try normalized name
            c.execute("SELECT * FROM obed WHERE datum = ?", (today,))
            all_students = c.fetchall()
            print("\nAll students in DB for today:")
            for s in all_students:
                print(f"Name: {s['jmeno']}, O1: {s['obed_1']}, O2: {s['obed_2']}, O3: {s['obed_3']}")
                if normalize_name(s['jmeno']) == normalize_name(full_name):
                    student = s
                    print(f"Found normalized match: {s}")
                    break

        # Get lunch info
        lunch_info = None
        if student:
            print(f"\nChecking lunch numbers for {student['jmeno']}:")
            print(f"Obed 1: {student['obed_1']}")
            print(f"Obed 2: {student['obed_2']}")
            print(f"Obed 3: {student['obed_3']}")
            
            # Check which lunch number the student has ordered (1, 2, or 3)
            lunch_number = None
            if student['obed_1'] == 1:
                lunch_number = 1
                print("Found lunch #1")
            elif student['obed_2'] == 1:
                lunch_number = 2
                print("Found lunch #2")
            elif student['obed_3'] == 1:
                lunch_number = 3
                print("Found lunch #3")
            
            lunch_info = {
                'has_lunch': lunch_number is not None,
                'lunch_number': lunch_number
            }
            print(f"Final lunch info: {lunch_info}")
        else:
            lunch_info = {
                'has_lunch': False,
                'lunch_number': None
            }
            print(f"Student has no lunch: {lunch_info}")
        
        conn.close()
        print("\nRedirecting to dashboard...")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"\nAuthorization error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    print("\n=== DASHBOARD ACCESS ===")
    if 'user' not in session:
        print("No user in session, redirecting to login")
        return redirect(url_for('login'))
    
    print(f"Session data: {session}")
    user_info = session['user']
    full_name = user_info.get('name')
    print(f"User name: {full_name}")
    
    # Get student's lunch from icanteen.db
    conn = get_db()
    c = conn.cursor()
    
    # Try to find student in database - using today's date
    today = datetime.now().strftime("%Y-%m-%d")
    c.execute("SELECT * FROM obed WHERE jmeno = ? AND datum = ?", (full_name, today))
    student = c.fetchone()
    print(f"Direct match result: {student}")
    
    if not student:
        print("No direct match, trying normalized name...")
        # Try normalized name
        c.execute("SELECT * FROM obed WHERE datum = ?", (today,))
        all_students = c.fetchall()
        print("\nAll students in DB for today:")
        for s in all_students:
            print(f"Name: {s['jmeno']}, O1: {s['obed_1']}, O2: {s['obed_2']}, O3: {s['obed_3']}")
            if normalize_name(s['jmeno']) == normalize_name(full_name):
                student = s
                print(f"Found normalized match: {s}")
                break
    
    # Get lunch info
    lunch_info = None
    if student:
        print(f"\nChecking lunch numbers for {student['jmeno']}:")
        print(f"Obed 1: {student['obed_1']}")
        print(f"Obed 2: {student['obed_2']}")
        print(f"Obed 3: {student['obed_3']}")
        
        # Check which lunch number the student has ordered (1, 2, or 3)
        lunch_number = None
        if student['obed_1'] == 1:
            lunch_number = 1
            print("Found lunch #1")
        elif student['obed_2'] == 1:
            lunch_number = 2
            print("Found lunch #2")
        elif student['obed_3'] == 1:
            lunch_number = 3
            print("Found lunch #3")
        
        lunch_info = {
            'has_lunch': lunch_number is not None,
            'lunch_number': lunch_number
        }
        print(f"Final lunch info: {lunch_info}")
    else:
        lunch_info = {
            'has_lunch': False,
            'lunch_number': None
        }
        print(f"Student has no lunch: {lunch_info}")
    
    conn.close()
    return render_template('dashboard.html', user=user_info, lunch_info=lunch_info)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    """Admin panel route"""
    if 'user' not in session or session['user'].get('email') not in ALLOWED_ADMIN_EMAILS:
        return "<script>window.history.back();</script>", 200
    return render_template('admin.html')

@app.route('/assign-card', methods=['GET', 'POST'])
def assign_card():
    """Route for assigning NFC cards to students"""
    if 'user' not in session or session['user'].get('email') not in ALLOWED_ADMIN_EMAILS:
        return "<script>window.history.back();</script>", 200
        
    if request.method == 'POST':
        student_name = request.form.get('student_name')
        card_uid = request.form.get('card_uid')
        
        if not student_name or not card_uid:
            return render_template('assign_card.html', error="Please provide both student name and card UID")
        
        try:
            # Hash the card UID
            hashed_uid = hashlib.sha256(card_uid.encode()).hexdigest()
            
            # Check if card is already assigned
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT * FROM students WHERE card_id = ?", (hashed_uid,))
            existing = c.fetchone()
            
            if existing:
                conn.close()
                return render_template('assign_card.html', error="This card is already assigned to a student")
            
            # Add new student-card assignment
            c.execute("INSERT INTO students (name, card_id) VALUES (?, ?)", (student_name, hashed_uid))
            conn.commit()
            conn.close()
            
            return render_template('assign_card.html', success="Card successfully assigned to student")
            
        except Exception as e:
            print(f"Error assigning card: {str(e)}")
            return render_template('assign_card.html', error="An error occurred while assigning the card")
    
    # GET request - show the assignment form
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM students ORDER BY id DESC LIMIT 10")
    students = c.fetchall()
    conn.close()
    
    return render_template('assign_card.html', students=students)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    # Scrape PDFs and update the database after tables are created
    scrape_lunch_pdfs()
    socketio.run(app, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)