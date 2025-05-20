from flask import Flask, redirect, url_for
from config import SECRET_KEY, SQLALCHEMY_DATABASE_URI, SQLALCHEMY_TRACK_MODIFICATIONS, SESSION_TYPE, UPLOAD_FOLDER
from extensions import init_extensions, db
from routes.auth import auth_bp
from routes.lunch import lunch_bp
from routes.upload import upload_bp
from pyngrok import ngrok

from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

# Configure the app
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLALCHEMY_TRACK_MODIFICATIONS
app.config['SESSION_TYPE'] = SESSION_TYPE
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

# Initialize extensions
google = init_extensions(app)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(lunch_bp)
app.register_blueprint(upload_bp)

# Start ngrok tunnel
public_url = ngrok.connect(addr="http://127.0.0.1:5000", domain="lamb-kind-preferably.ngrok-free.app")
print(f" * ngrok tunnel \"{public_url}\" -> \"http://127.0.0.1:5000\"")
print(f"GOOGLE_CLIENT_ID: {app.config.get('GOOGLE_CLIENT_ID')}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True, use_reloader=False)