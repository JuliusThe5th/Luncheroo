from flask import Flask, request, jsonify, redirect, url_for, session, render_template
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
import sqlite3
from datetime import datetime
from pyngrok import ngrok, conf

# Load environment variables
load_dotenv()

app = Flask(__name__)

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
    
    # Create obed table if it doesn't exist - matching the working script's structure
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
        'prompt': 'select_account'
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
        if not full_name:
            print("No name in user info")
            return redirect(url_for('login'))
        print(f"Full name: {full_name}")

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

        # Store user info in session
        print("\nStoring session data...")
        session.clear()  # Clear any existing session data
        session['user'] = user_info
        session['token'] = token
        print(f"Session data stored: {session}")
        
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

if __name__ == '__main__':
    with app.app_context():
        init_db()  # Initialize database once when app starts

    app.run(debug=True, use_reloader=False)