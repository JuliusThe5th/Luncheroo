from flask import Blueprint, request, jsonify, current_app
from extensions import db
from models import Student, TodayLunch, AvailableLunch, GivenLunch
import pandas as pd
import os

upload_bp = Blueprint('upload', __name__)

@upload_bp.route('/upload', methods=['POST'])
def upload_excel():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file and file.filename.endswith('.xlsx'):
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
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