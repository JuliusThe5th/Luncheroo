from flask import Blueprint, request, jsonify
from extensions import db, oauth
from models import Student, TodayLunch, AvailableLunch, GivenLunch
from routes.utils import validate_token
import hashlib

lunch_bp = Blueprint('lunch', __name__)

@lunch_bp.route('/lunch', methods=['POST'])
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

@lunch_bp.route('/lunches', methods=['GET'])
def get_lunches():
    student, error_response, status_code = validate_token(oauth.google)
    if error_response:
        return error_response, status_code

    # Get user's lunch
    user_lunch = TodayLunch.query.filter_by(student_id=student.id).first()
    user_lunch_id = user_lunch.lunch_id if user_lunch else None

    # Get available lunches
    available_lunches = AvailableLunch.query.all()
    available_lunches_dict = {f"lunch {lunch.lunch_id}": lunch.quantity for lunch in available_lunches}

    return jsonify({
        'user_lunch': user_lunch_id,
        'available_lunches': available_lunches_dict
    }), 200

@lunch_bp.route('/give_lunch', methods=['POST'])
def give_lunch():
    student, error_response, status_code = validate_token(oauth.google)
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

@lunch_bp.route('/request_lunch', methods=['POST'])
def request_lunch():
    student, error_response, status_code = validate_token(oauth.google)
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