from flask import request, jsonify
import hashlib
from models import Student

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