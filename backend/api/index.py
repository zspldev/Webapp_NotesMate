import os
from dotenv import load_dotenv
import psycopg2
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
import random
import traceback
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()  # Load .env file for local development

app = Flask(__name__)

# CORS configuration with permissive settings for testing
CORS(app, resources={r"/api/*": {"origins": ["*"], "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"], "allow_headers": ["*"], "supports_credentials": True}})

# CockroachDB configuration using only environment variables
def get_db_connection():
    conn_params = {
        "host": os.getenv("DB_HOST"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
        "database": os.getenv("DB_NAME"),
        "port": os.getenv("DB_PORT"),
        "sslmode": "require"
    }
    logger.debug(f"Connecting to DB with params: {conn_params}")
    
    try:
        conn = psycopg2.connect(**conn_params)
        logger.debug("Database connection established successfully")
        return conn
    except psycopg2.Error as e:
        logger.error(f"Database connection failed: {str(e)}")
        raise

# Create OTPs table if not exists
def init_db():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS otps (
                key STRING PRIMARY KEY,
                otp STRING,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
            )
        """)
        conn.commit()
        logger.debug("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Delay database initialization until first request
db_initialized = False

@app.before_request
def log_request():
    logger.info(f"Received request: {request.method} {request.path} from {request.remote_addr} with headers {dict(request.headers)}")

@app.before_request
def initialize_database():
    global db_initialized
    if not db_initialized:
        try:
            init_db()
            db_initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            # Allow request to proceed, handle DB failure in endpoints

# OPTIONS handler for preflight requests
@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    logger.info(f"Handling OPTIONS request for {path}")
    response = jsonify({})
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
    response.headers.add("Access-Control-Allow-Headers", "*")
    response.headers.add("Access-Control-Max-Age", "86400")
    return response, 200

# Request OTP
@app.route("/api/request-otp", methods=["POST"])
def request_otp():
    logger.info("Received request-otp request")
    conn = None
    cursor = None
    try:
        data = request.get_json()
        orgid = int(data.get("orgId"))
        empid = int(data.get("empId"))

        if not orgid or not empid:
            logger.warning("Missing orgid or empid in request")
            return jsonify({"error": "orgid and empid are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT empemail FROM employees WHERE orgid = %s AND empid = %s",
            (orgid, empid)
        )
        employee = cursor.fetchone()

        if not employee:
            logger.warning(f"No employee found for orgid={orgid}, empid={empid}")
            return jsonify({"error": "No employee found with this orgid and empid"}), 404

        empemail = employee[0]
        if not empemail:
            logger.warning(f"Employee email not found for orgid={orgid}, empid={empid}")
            return jsonify({"error": "Employee email not found"}), 400

        otp = str(random.randint(1000, 9999))
        otp_key = f"{orgid}-{empid}"

        created_at = datetime.utcnow()

        cursor.execute(
            "INSERT INTO otps (key, otp, created_at) VALUES (%s, %s, %s) ON CONFLICT (key) DO UPDATE SET otp = %s, created_at = %s",
            (otp_key, otp, created_at, otp, created_at)
        )
        conn.commit()
        logger.info(f"Generated OTP {otp} for {empemail}")

        gmail_email = os.getenv("GMAIL_EMAIL")
        gmail_app_password = os.getenv("GMAIL_APP_PASSWORD")
        if gmail_email and gmail_app_password:
            success = send_otp_email(empemail, otp)
            if not success:
                logger.warning(f"Failed to send email to {empemail}")
                return jsonify({
                    "message": "Failed to send OTP via email. Check the server logs for the OTP."
                }), 200
        else:
            logger.warning("Email service not configured")
            return jsonify({
                "message": "Email service not configured. Check the server logs for the OTP."
            }), 200

        response = jsonify({"message": "OTP sent to your registered email address"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 200

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        response = jsonify({"error": f"Unexpected error: {str(e)}"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Send OTP via email
def send_otp_email(to_email, otp):
    try:
        msg = MIMEText(f"Your Notesmate OTP is: {otp}")
        msg["Subject"] = "Notesmate OTP Verification"
        msg["From"] = os.getenv("GMAIL_EMAIL")
        msg["To"] = to_email

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(os.getenv("GMAIL_EMAIL"), os.getenv("GMAIL_APP_PASSWORD"))
            server.sendmail(os.getenv("GMAIL_EMAIL"), to_email, msg.as_string())
            return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        return False

# Validate OTP
@app.route("/api/validate-otp", methods=["POST"])
def validate_otp():
    logger.info("Received validate-otp request")
    conn = None
    cursor = None
    try:
        data = request.get_json()
        orgid = int(data.get("orgId"))
        empid = int(data.get("empId"))
        entered_otp = data.get("otp")

        if not orgid or not empid or not entered_otp:
            logger.warning("Missing orgid, empid, or otp in request")
            return jsonify({"error": "orgid, empid, and OTP are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        otp_key = f"{orgid}-{empid}"
        cursor.execute(
            "SELECT otp, created_at FROM otps WHERE key = %s",
            (otp_key,)
        )
        result = cursor.fetchone()

        if not result:
            logger.warning(f"No OTP found for key {otp_key}")
            return jsonify({"error": "OTP not found or expired"}), 400

        stored_otp, created_at = result
        current_time = datetime.utcnow()
        if current_time - created_at > timedelta(minutes=5):
            cursor.execute("DELETE FROM otps WHERE key = %s", (otp_key,))
            conn.commit()
            logger.warning(f"OTP expired for key {otp_key}")
            return jsonify({"error": "OTP expired"}), 400

        if stored_otp != entered_otp:
            logger.warning(f"Invalid OTP entered for key {otp_key}")
            return jsonify({"error": "Invalid OTP"}), 400

        cursor.execute("DELETE FROM otps WHERE key = %s", (otp_key,))
        conn.commit()

        response = jsonify({
            "message": "OTP validated successfully",
            "orgId": orgid,
            "empId": empid
        })
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 200

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        response = jsonify({"error": f"Unexpected error: {str(e)}"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Register new user
@app.route("/api/register", methods=["POST"])
def register():
    logger.info("Received register request")
    conn = None
    cursor = None
    try:
        data = request.get_json()
        orgid = int(data.get("orgId"))
        orgname = data.get("orgName")
        shortname = data.get("shortname")
        address = data.get("address")
        phone = data.get("orgPhone")
        email = data.get("orgEmail")
        empid = int(data.get("empId"))
        empname = data.get("empName")
        empshortname = data.get("empShortname")
        empphone = data.get("empPhone")
        empemail = data.get("empEmail")

        if not all([orgid, orgname, shortname, address, phone, email, empid, empname, empshortname, empphone, empemail]):
            logger.warning("Missing required fields in register request")
            return jsonify({"error": "All fields are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM organizations WHERE orgid = %s", (orgid,))
        org_exists = cursor.fetchone()

        if not org_exists:
            cursor.execute(
                """INSERT INTO organizations 
                (orgid, orgname, shortname, address, phone, email) 
                VALUES (%s, %s, %s, %s, %s, %s)""",
                (orgid, orgname, shortname, address, phone, email)
            )

        cursor.execute("SELECT * FROM employees WHERE orgid = %s AND empid = %s", (orgid, empid))
        if cursor.fetchone():
            logger.warning(f"Employee with empid={empid} already exists in orgid={orgid}")
            return jsonify({"error": "Employee with this empid already exists in this organization"}), 400

        cursor.execute(
            """INSERT INTO employees 
            (empid, orgid, empname, empshortname, empphone, empemail) 
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (empid, orgid, empname, empshortname, empphone, empemail)
        )

        conn.commit()
        response = jsonify({"message": "Registration successful"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 200

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        response = jsonify({"error": f"Unexpected error: {str(e)}"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Register new client
@app.route("/api/register-client", methods=["POST"])
def register_client():
    logger.info("Received register-client request")
    conn = None
    cursor = None
    try:
        data = request.get_json()
        orgid = int(data.get("orgId"))
        clientname = data.get("clientName")
        clientshortname = data.get("clientShortname")
        clientphone = data.get("clientPhone", "NA")
        clientemail = data.get("clientEmail")

        if not all([orgid, clientname, clientemail]):
            logger.warning("Missing required fields in register-client request")
            return jsonify({"error": "orgid, clientname, and clientemail are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM organizations WHERE orgid = %s", (orgid,))
        org_exists = cursor.fetchone()
        if not org_exists:
            logger.warning(f"Organization not found for orgid={orgid}")
            return jsonify({"error": "Organization not found"}), 404

        cursor.execute("SELECT MAX(clientid) FROM clients WHERE orgid = %s", (orgid,))
        result = cursor.fetchone()
        new_clientid = (result[0] or 0) + 1

        cursor.execute("SELECT * FROM clients WHERE orgid = %s AND clientid = %s", (orgid, new_clientid))
        if cursor.fetchone():
            logger.warning(f"Client with clientid={new_clientid} already exists in orgid={orgid}")
            return jsonify({"error": "Client with this clientid already exists in this organization"}), 400

        cursor.execute(
            """INSERT INTO clients 
            (clientid, orgid, clientname, clientshortname, clientphone, clientemail) 
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (new_clientid, orgid, clientname, clientshortname, clientphone, clientemail)
        )

        conn.commit()
        response = jsonify({
            "message": "Client registered successfully",
            "clientId": new_clientid
        })
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 200

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        response = jsonify({"error": f"Unexpected error: {str(e)}"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Fetch clients
@app.route("/api/fetch-clients", methods=["POST"])
def fetch_clients():
    logger.info("Received fetch-clients request")
    conn = None
    cursor = None
    try:
        data = request.get_json()
        orgid = int(data.get("orgId"))

        if not orgid:
            logger.warning("Missing orgid in fetch-clients request")
            return jsonify({"error": "orgid is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT clientid, clientname, clientshortname FROM clients WHERE orgid = %s",
            (orgid,)
        )
        clients = cursor.fetchall()

        client_list = [{
            "ClientID": row[0],
            "ClientName": row[1],
            "ClientShortname": row[2]
        } for row in clients]

        response = jsonify({"clients": client_list})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 200

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        response = jsonify({"error": f"Unexpected error: {str(e)}"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Save transcription
@app.route("/api/save-transcription", methods=["POST"])
def save_transcription():
    logger.info("Received save-transcription request")
    conn = None
    cursor = None
    try:
        data = request.get_json()
        orgid = int(data.get("orgId"))
        empid = int(data.get("empId"))
        clientid = int(data.get("clientId"))
        transcriptiontext = data.get("transcriptionText")
        audionotes = data.get("audioData")

        if not all([orgid, empid, clientid, transcriptiontext]):
            logger.warning("Missing required fields in save-transcription request")
            return jsonify({"error": "orgid, empid, clientid, and transcriptiontext are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM clients WHERE orgid = %s AND clientid = %s",
            (orgid, clientid)
        )
        if not cursor.fetchone():
            logger.warning(f"Invalid clientid={clientid} for orgid={orgid}")
            return jsonify({"error": "Invalid clientid for this organization"}), 404

        audio_binary = None
        if audionotes:
            import base64
            audio_binary = base64.b64decode(audionotes)

        created_at = datetime.utcnow()

        cursor.execute(
            """INSERT INTO notes 
            (orgid, empid, clientid, meetingid, datetime, audionotes, textnotes) 
            VALUES (%s, %s, %s, nextval('notes_seq'), %s, %s, %s)""",
            (orgid, empid, clientid, created_at, psycopg2.Binary(audio_binary) if audio_binary else None, transcriptiontext)
        )

        conn.commit()
        response = jsonify({"message": "Transcription saved successfully"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 200

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        response = jsonify({"error": f"Unexpected error: {str(e)}"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Fetch notes
@app.route("/api/fetch-notes", methods=["POST"])
def fetch_notes():
    logger.info("Received fetch-notes request")
    conn = None
    cursor = None
    try:
        data = request.get_json()
        orgid = int(data.get("orgId"))
        empid = int(data.get("empId"))
        clientid = int(data.get("clientId"))
        selecteddate = data.get("selectedDate")

        if not all([orgid, empid, clientid]):
            logger.warning("Missing required fields in fetch-notes request")
            return jsonify({"error": "orgid, empid, and clientid are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
            SELECT datetime, textnotes, audionotes
            FROM notes
            WHERE orgid = %s AND empid = %s AND clientid = %s
        """
        params = [orgid, empid, clientid]

        if selecteddate:
            query += " AND DATE(datetime) = %s"
            params.append(selecteddate)

        query += " ORDER BY datetime DESC"
        cursor.execute(query, params)
        notes = cursor.fetchall()

        import base64
        note_list = [{
            "DateTime": row[0].strftime('%Y-%m-%dT%H:%M:%S.%f'),
            "TextNotes": row[1],
            "AudioNotes": base64.b64encode(row[2]).decode("utf-8") if row[2] else None
        } for row in notes]

        response = jsonify({"notes": note_list})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 200

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        response = jsonify({"error": f"Unexpected error: {str(e)}"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Update note transcription
@app.route("/api/update-note", methods=["POST"])
def update_note():
    logger.info("Received update-note request")
    conn = None
    cursor = None
    try:
        data = request.get_json()
        orgid = int(data.get("orgId"))
        empid = int(data.get("empId"))
        clientid = int(data.get("clientId"))
        dateTime = data.get("dateTime")
        newText = data.get("newText")

        if not all([orgid, empid, clientid, dateTime, newText]):
            logger.warning("Missing required fields in update-note request")
            return jsonify({"error": "orgid, empid, clientid, dateTime, and newText are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        dt = datetime.strptime(dateTime, '%Y-%m-%dT%H:%M:%S.%f')

        cursor.execute(
            """UPDATE notes 
            SET textnotes = %s 
            WHERE orgid = %s AND empid = %s AND clientid = %s AND datetime = %s""",
            (newText, orgid, empid, clientid, dt)
        )
        if cursor.rowcount == 0:
            logger.warning(f"No note found to update with datetime={dt}")
            return jsonify({"error": "No matching note found to update"}), 404
        conn.commit()
        logger.info(f"Successfully updated note with datetime={dt}")

        response = jsonify({"message": "Transcription updated successfully"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 200

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        response = jsonify({"error": f"Unexpected error: {str(e)}"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Default route
@app.route("/")
def index():
    logger.info("Received index request")
    response = jsonify({"message": "NotesMate API is running"})
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

# Custom Vercel handler for serverless deployment
def vercel_handler(request):
    from flask import Response
    with app.app_context():
        response = app.full_dispatch_request()
        return Response(
            response=response.get_data(),
            status=response.status_code,
            headers=dict(response.headers)
        )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)