from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from pyngrok import ngrok, conf
from config import NGROK_AUTH_TOKEN

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
oauth = OAuth()

# Configure ngrok
conf.get_default().auth_token = NGROK_AUTH_TOKEN

def init_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)
    oauth.init_app(app)
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        access_token_url='https://oauth2.googleapis.com/token',
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        api_base_url='https://openidconnect.googleapis.com/v1/',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile',
            'token_endpoint_auth_method': 'client_secret_post'
        }
    )
    return google 