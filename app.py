from flask import Flask, request, jsonify, redirect, url_for, session, render_template
from models import db, Student, TodayLunch, AvailableLunch, GivenLunch
from flask_migrate import Migrate
from pyngrok import ngrok, conf
from authlib.integrations.flask_client import OAuth
import pandas as pd
import hashlib
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize the database
db.init_app(app)
migrate = Migrate(app, db)

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
        'token_endpoint_auth_method': 'client_secret_post'
    }
)

# Set ngrok authtoken
conf.get_default().auth_token = os.getenv('NGROK_AUTH_TOKEN')

# Reusable token validation function
def validate_token(google):
    """Validates the Authorization token and returns the logged-in user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, jsonify({'error': 'Authorization header missing or invalid'}), 401

    token = auth_header.split(' ')[1]

    try:
        user_info = google.get('userinfo', token={'access_token': token}).json()
        if 'error' in user_info:
            return None, jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        return None, jsonify({'error': 'Token validation failed', 'details': str(e)}), 401

    full_name = user_info.get('name')
    student = Student.query.filter_by(name=full_name).first()
    if not student:
        return None, jsonify({'error': 'Student not found'}), 404

    return student, None, None

def assign_card_uid_by_id(student_id, card_uid):
    """Assign a hashed card UID to a student by their ID."""
    hashed_card_uid = hashlib.sha256(card_uid.encode()).hexdigest()
    student = Student.query.filter_by(id=student_id).first()

    if not student:
        return {'error': f'Student with ID {student_id} not found'}

    # Assign the hashed UID to the correct field `card_id`
    student.card_id = hashed_card_uid
    db.session.commit()
    return {'message': f'Card UID assigned to student with ID {student_id} successfully'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard', methods=['GET'])
def dashboard():
    token = request.args.get('token')
    if not token:
        return "Access token is missing", 400
    return f"Welcome to the dashboard! Your token: {token}"

# Route to upload Excel file
@app.route('/upload', methods=['POST'])
def upload_excel():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file and file.filename.endswith('.xlsx'):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        try:
            # Debugging: Log file save location
            print(f"Uploaded file saved to: {filepath}")

            # Create LunchHistory folder if it doesn't exist
            history_folder = 'LunchHistory'
            os.makedirs(history_folder, exist_ok=True)

            # Query the given lunches and join with student data
            given_lunches = db.session.query(
                Student.name, GivenLunch.lunch_id, GivenLunch.timestamp
            ).join(Student, Student.id == GivenLunch.student_id) \
                .order_by(Student.name).all()

            print(f"Given lunches data: {given_lunches}")  # Debugging

            if given_lunches:
                # Convert the data to a DataFrame with time in 24-hour format
                data = [
                    {
                        'name': name,
                        'lunch': lunch_id,
                        'timestamp': timestamp.strftime('%H:%M:%S')  # Time in 24-hour format
                    }
                    for name, lunch_id, timestamp in given_lunches
                ]
                df = pd.DataFrame(data)

                # Get the date of the first given lunch
                first_given_lunch = db.session.query(GivenLunch.timestamp).order_by(GivenLunch.timestamp).first()
                print(f"First given lunch timestamp: {first_given_lunch}")  # Debugging

                if first_given_lunch:
                    date_str = first_given_lunch.timestamp.strftime('%d-%m-%Y')  # EU format for the file name
                    file_name = f"lunches {date_str}.xlsx"
                    file_path = os.path.join(history_folder, file_name)

                    # Save the DataFrame to an Excel file
                    print(f"Saving file to: {file_path}")  # Debugging
                    df.to_excel(file_path, index=False)
                else:
                    print("No given lunches found to export.")
            else:
                print("No given lunches data available.")

            # Delete existing data
            db.session.query(TodayLunch).delete()
            db.session.commit()

            db.session.query(AvailableLunch).delete()
            db.session.commit()

            db.session.query(GivenLunch).delete()
            db.session.commit()

            # Process the uploaded file
            df = pd.read_excel(filepath)
            for _, row in df.iterrows():
                student = Student.query.filter_by(name=row['Name']).first()
                if not student:
                    student = Student(name=row['Name'])
                    db.session.add(student)
                    db.session.commit()

                daily_lunch = TodayLunch(student_id=student.id, lunch_id=row['LunchNumber'])
                db.session.add(daily_lunch)

            db.session.commit()
            return jsonify({'message': 'File processed and database updated successfully'}), 200
        except Exception as e:
            print(f"Error during file processing: {e}")  # Debugging
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Invalid file type. Only .xlsx files are allowed'}), 400

# Route to get lunch data for a student
import hashlib

@app.route('/lunch', methods=['POST'])
def get_lunch_by_card():
    data = request.get_json()
    card_uid = data.get('card_uid')
    if not card_uid:
        return jsonify({'error': 'card_uid is required'}), 400

    # Convert card_uid to a string and hash it
    hashed_card_uid = hashlib.sha256(str(card_uid).encode()).hexdigest()

    # Find the student by the correct field `card_id`
    student = Student.query.filter_by(card_id=hashed_card_uid).first()
    if not student:
        return jsonify({'error': 'Student not found for the provided card UID'}), 404

    # Find the lunch assigned to the student
    daily_lunch = TodayLunch.query.filter_by(student_id=student.id).first()
    if not daily_lunch:
        return jsonify({'error': 'Lunch data not found for the student'}), 404

    lunch_id = daily_lunch.lunch_id

    # Remove the lunch from TodayLunch
    db.session.delete(daily_lunch)

    # Add the lunch to GivenLunch
    given_lunch = GivenLunch(student_id=student.id, lunch_id=lunch_id)
    db.session.add(given_lunch)

    # Commit the changes
    db.session.commit()

    return jsonify({'message': f'Lunch {lunch_id} given to student {student.name} successfully'}), 200

@app.route('/lunches', methods=['GET'])
def get_lunches():
    student, error_response, status_code = validate_token(google)
    if error_response:
        return error_response, status_code

    lunches = AvailableLunch.query.all()
    return jsonify({f"lunch {lunch.lunch_id}": lunch.quantity for lunch in lunches}), 200

@app.route('/give_lunch', methods=['POST'])
def give_lunch():
    student, error_response, status_code = validate_token(google)
    if error_response:
        return error_response, status_code

    daily_lunch = TodayLunch.query.filter_by(student_id=student.id).first()
    if not daily_lunch:
        return jsonify({'error': 'No lunch found for the user'}), 404

    lunch_id = daily_lunch.lunch_id
    db.session.delete(daily_lunch)

    available_lunch = AvailableLunch.query.filter_by(lunch_id=lunch_id).first()
    if available_lunch:
        available_lunch.quantity += 1
    else:
        available_lunch = AvailableLunch(lunch_id=lunch_id, quantity=1)
        db.session.add(available_lunch)

    db.session.commit()
    return jsonify({'message': f'Lunch {lunch_id} given successfully'}), 200

@app.route('/request_lunch', methods=['POST'])
def request_lunch():
    student, error_response, status_code = validate_token(google)
    if error_response:
        return error_response, status_code

    data = request.get_json()
    lunch_id = data.get('lunch_id')
    if not lunch_id:
        return jsonify({'error': 'lunch_id is required'}), 400

    available_lunch = AvailableLunch.query.filter_by(lunch_id=lunch_id).with_for_update().first()
    if not available_lunch or available_lunch.quantity <= 0:
        return jsonify({'error': 'Requested lunch is not available'}), 404

    daily_lunch = TodayLunch.query.filter_by(student_id=student.id).first()
    if daily_lunch:
        return jsonify({'error': 'Student already has a lunch assigned'}), 400

    available_lunch.quantity -= 1
    if available_lunch.quantity == 0:
        db.session.delete(available_lunch)

    new_daily_lunch = TodayLunch(student_id=student.id, lunch_id=lunch_id)
    db.session.add(new_daily_lunch)

    db.session.commit()
    return jsonify({'message': f'Lunch {lunch_id} assigned to {student.name} successfully'}), 200

# Google Sign-In routes
@app.route('/login', methods=['GET'])
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri, prompt='select_account')

@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    print(f"Access Token: {token}")
    user_info = google.get('userinfo').json()
    full_name = user_info.get('name')

    student = Student.query.filter_by(name=full_name).first()
    if not student:
        student = Student(name=full_name)
        db.session.add(student)
        db.session.commit()

    session['user'] = user_info

    # Render the dashboard.html template
    return render_template('dashboard.html', user=user_info)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

# Start ngrok tunnel
public_url = ngrok.connect(addr="http://127.0.0.1:5000", domain="lamb-kind-preferably.ngrok-free.app")
print(f" * ngrok tunnel \"{public_url}\" -> \"http://127.0.0.1:5000\"")

if __name__ == '__main__':
    with app.app_context():
        pass

    app.run(debug=True, use_reloader=False)