# Lunch Management System

This project is a Flask-based web application designed to manage student lunches. It allows administrators to upload lunch data, assign lunches to students, and track lunch history. The application integrates with Google OAuth for authentication and uses SQLAlchemy for database management.

## Features

- **Student Management**: Manage student data, including assigning unique card IDs.
- **Lunch Assignment**: Assign lunches to students and track their distribution.
- **Excel Upload**: Upload `.xlsx` files to update lunch data.
- **Lunch History**: Export lunch history to an Excel file with timestamps.
- **Google OAuth Integration**: Authenticate users using Google Sign-In.
- **Real-Time Updates**: Use ngrok to expose the application for testing.

## Technologies Used

- **Backend**: Flask, Flask-SQLAlchemy, Flask-Migrate
- **Authentication**: Google OAuth
- **Database**: SQLite
- **File Handling**: Pandas for Excel file processing
- **Environment Management**: Python-dotenv
- **Tunneling**: Pyngrok

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-folder>

2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   
4. Set up environment variables:
   - Create a `.env` file in the project root.
   - Add the following variables:
     ```
     SQLALCHEMY_DATABASE_URI=sqlite:///lunch_app.db
     SECRET_KEY=<your-secret-key>
     GOOGLE_CLIENT_ID=<your-google-client-id>
     GOOGLE_CLIENT_SECRET=<your-google-client-secret>
     NGROK_AUTH_TOKEN=<your-ngrok-auth-token>
     UPLOAD_FOLDER=uploads
     ```

5. Initialize the database:
   ```bash
   flask db upgrade
   
6. Start the application:
   ```bash
   python app.py
   
7. Access the application:
   - Local: `http://127.0.0.1:5000`
   - Ngrok: The public URL displayed in the terminal.

8. Log in to the application:
   - Use the `/login` endpoint to authenticate with Google OAuth.

9. Upload lunch data:
   - Use the `/upload` endpoint to upload an Excel file containing lunch data.

10. Manage lunches:
    - Assign lunches to students using the `/request_lunch` endpoint.
    - Track and export lunch history using the `/lunch` and `/give_lunch` endpoints.