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

## API Endpoints

### 1. `/upload` (POST)
- **Description**: Upload an Excel file to update lunch data.
- **Request**:
  - Content-Type: `multipart/form-data`
  - File: `.xlsx` file containing lunch data.
- **Response**:
  - `200 OK`: File processed and database updated successfully.
  - `400 Bad Request`: Invalid file type.
  - `500 Internal Server Error`: Error during file processing.

### 2. `/lunch` (POST)
- **Description**: Retrieve and assign a lunch to a student using their card UID.
- **Request**:
  - Content-Type: `application/json`
  - Body:
    ```json
    {
      "card_uid": "<hashed_card_uid>"
    }
    ```
- **Response**:
  - `200 OK`: Lunch assigned successfully.
  - `400 Bad Request`: Missing `card_uid`.
  - `404 Not Found`: Student or lunch data not found.

### 3. `/lunches` (GET)
- **Description**: Retrieve all available lunches and their quantities.
- **Response**:
  - `200 OK`: JSON object with lunch IDs and quantities.

### 4. `/give_lunch` (POST)
- **Description**: Mark a lunch as given to the authenticated student.
- **Authentication**: Requires Google OAuth token.
- **Response**:
  - `200 OK`: Lunch given successfully.
  - `404 Not Found`: No lunch found for the user.

### 5. `/request_lunch` (POST)
- **Description**: Request a specific lunch for the authenticated student.
- **Authentication**: Requires Google OAuth token.
- **Request**:
  - Content-Type: `application/json`
  - Body:
    ```json
    {
      "lunch_id": "<lunch_id>"
    }
    ```
- **Response**:
  - `200 OK`: Lunch assigned successfully.
  - `400 Bad Request`: Missing `lunch_id` or student already has a lunch.
  - `404 Not Found`: Requested lunch is not available.

### 6. `/login` (GET)
- **Description**: Redirect to Google OAuth for user authentication.
- **Response**:
  - Redirects to Google Sign-In page.

### 7. `/authorize` (GET)
- **Description**: Handle Google OAuth callback and create a student if not already registered.
- **Response**:
  - `200 OK`: JSON object with user information.

### 8. `/logout` (GET)
- **Description**: Log out the authenticated user.
- **Response**:
  - Redirects to the `/login` page.