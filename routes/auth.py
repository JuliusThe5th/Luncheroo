from flask import Blueprint, request, jsonify, redirect, url_for, session, render_template
from extensions import oauth, db
from models import Student

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def index():
    return render_template('index.html')

@auth_bp.route('/dashboard', methods=['GET'])
def dashboard():
    token = request.args.get('token')
    if not token:
        return "Access token is missing", 400
    return render_template('dashboard.html', user=session.get('user'))

@auth_bp.route('/login', methods=['GET'])
def login():
    redirect_uri = url_for('auth.authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, prompt='select_account')

@auth_bp.route('/authorize')
def authorize():
    token = oauth.google.authorize_access_token()
    print(f"Access Token: {token}")
    user_info = oauth.google.get('userinfo').json()
    full_name = user_info.get('name')

    student = Student.query.filter_by(name=full_name).first()
    if not student:
        student = Student(name=full_name)
        db.session.add(student)
        db.session.commit()

    session['user'] = user_info
    session['access_token'] = token['access_token']

    # Redirect to dashboard with the token
    return redirect(url_for('auth.dashboard', token=token['access_token']))

@auth_bp.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('access_token', None)
    return redirect(url_for('auth.index')) 