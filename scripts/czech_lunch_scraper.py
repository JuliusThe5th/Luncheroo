import imaplib
import email
import os
import pdfplumber
import sqlite3
import re
from datetime import datetime

# --- CONFIGURATION ---
EMAIL_USER = "obidky@gmail.com"
EMAIL_PASS = "xrru qiwr iwdd ajlp"
IMAP_SERVER = "imap.gmail.com"
SAVE_FOLDER = "icanteen_pdfs"
DB_PATH = "icanteen.db"

def fetch_today_icanteen_pdfs():
    if not os.path.exists(SAVE_FOLDER):
        os.makedirs(SAVE_FOLDER)

    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL_USER, EMAIL_PASS)
    mail.select("inbox")

    today = datetime.now().strftime("%d-%b-%Y")
    print(f"Searching for emails since {today}")
    result, data = mail.search(None, f'(SINCE "{today}")')

    if result != "OK" or not data[0]:
        print("Žádný vhodný e-mail nenalezen.")
        return []

    pdf_files = []
    email_count = 0
    for num in data[0].split():
        result, msg_data = mail.fetch(num, "(RFC822)")
        if result != "OK":
            continue

        msg = email.message_from_bytes(msg_data[0][1])
        subject = email.header.decode_header(msg["Subject"])[0][0]
        if isinstance(subject, bytes):
            subject = subject.decode("utf-8", errors="ignore")
        
        print(f"Found email with subject: {subject}")
        if "Přehled objednaných jídel" not in subject:
            continue

        email_count += 1
        print(f"Processing email #{email_count}")
        pdf_count = 0
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get("Content-Disposition") is None:
                continue
            filename = part.get_filename()
            if filename and filename.lower().endswith(".pdf"):
                pdf_count += 1
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filepath = os.path.join(SAVE_FOLDER, f"{timestamp}_{filename}")
                with open(filepath, "wb") as f:
                    f.write(part.get_payload(decode=True))
                pdf_files.append(filepath)
                print(f"Saved PDF #{pdf_count}: {filename}")
    
    print(f"\nTotal emails processed: {email_count}")
    print(f"Total PDFs found: {len(pdf_files)}")
    mail.logout()
    return pdf_files

def parse_pdf_data(pdf_path):
    students = []
    datum = None
    # Updated regex to match the exact format from the PDF
    line_re = re.compile(
        r"\s*([\wÁČĎÉĚÍŇÓŘŠŤÚŮÝŽáčďéěíňóřšťúůýž\- ]{3,})\s+([\wÁČĎÉĚÍŇÓŘŠŤÚŮÝŽáčďéěíňóřšťúůýž\- ]{3,})\s+(\d)\s+(\d)\s+(\d)\s*$"
    )
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if not text:
                continue
            if not datum:
                match = re.search(r"Datum:\s*(\d{4}-\d{2}-\d{2})", text)
                if match:
                    datum = match.group(1)
            lines = text.splitlines()
            for line in lines:
                m = line_re.match(line)
                if m:
                    # Combine first and last name
                    jmeno = f"{m.group(2).strip()} {m.group(1).strip()}"
                    o1 = int(m.group(3))
                    o2 = int(m.group(4))
                    o3 = int(m.group(5))
                    students.append((jmeno, o1, o2, o3, datum))
    return students

def save_to_db(student_data):
    """
    Saves a list of student meal records to the SQLite database.
    Each record should be a tuple: (jmeno, obed_1, obed_2, obed_3, datum)
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Clear existing data for today
    today = datetime.now().strftime("%Y-%m-%d")
    c.execute("DELETE FROM obed WHERE datum = ?", (today,))
    
    # Create table if it doesn't exist
    c.execute("""
        CREATE TABLE IF NOT EXISTS obed (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jmeno TEXT,
            obed_1 INTEGER,
            obed_2 INTEGER,
            obed_3 INTEGER,
            datum TEXT
        )
    """)
    
    # Insert new data
    c.executemany(
        "INSERT INTO obed (jmeno, obed_1, obed_2, obed_3, datum) VALUES (?, ?, ?, ?, ?)",
        student_data
    )
    conn.commit()
    conn.close()
    print(f"Saved {len(student_data)} students to database")

def cleanup_pdfs():
    """Delete processed PDFs"""
    pdf_dir = "icanteen_pdfs"
    if os.path.exists(pdf_dir):
        for file in os.listdir(pdf_dir):
            if file.endswith('.pdf'):
                os.remove(os.path.join(pdf_dir, file))
        print("Cleaned up PDF files")

def main():
    try:
        # Create PDF directory if it doesn't exist
        os.makedirs("icanteen_pdfs", exist_ok=True)
        
        # Fetch PDFs
        pdf_files = fetch_today_icanteen_pdfs()
        if not pdf_files:
            print("No PDFs found for today")
            return
        
        # Process all PDFs
        all_students = []
        for pdf_file in pdf_files:
            students = parse_pdf_data(pdf_file)
            all_students.extend(students)
        
        # Save to database
        save_to_db(all_students)
        
        # Clean up PDFs after successful processing
        cleanup_pdfs()
        
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main() 