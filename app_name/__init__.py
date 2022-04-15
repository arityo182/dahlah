from . import config as CFG
from flask import Flask, Blueprint, jsonify, request, make_response, render_template
from werkzeug.utils import secure_filename
from flask_cors import cross_origin
from flask_jwt_extended import get_jwt, jwt_required, JWTManager, create_access_token
from flask import Flask, Blueprint
from flask import current_app as app
from flask_jwt_extended import JWTManager
from flask import Flask, Blueprint, jsonify, request, make_response, render_template
from flask_jwt_extended import get_jwt, jwt_required, JWTManager
from flask_cors import cross_origin
from werkzeug.utils import secure_filename
from werkzeug.datastructures import ImmutableMultiDict
import hashlib
import datetime
import random
import string
from time import strftime


from werkzeug.datastructures import ImmutableMultiDict
from.users.models import Data


app = Flask(__name__, static_url_path=None)  # panggil modul flask

# Flask JWT Extended Configuration
app.config['SECRET_KEY'] = CFG.JWT_SECRET_KEY
app.config['JWT_HEADER_TYPE'] = CFG.JWT_HEADER_TYPE
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(
    days=1)  # 1 hari token JWT expired
jwt = JWTManager(app)

# Application Configuration
app.config['PRODUCT_ENVIRONMENT'] = CFG.PRODUCT_ENVIRONMENT
app.config['BACKEND_BASE_URL'] = CFG.BACKEND_BASE_URL

app.config['LOGS'] = CFG.LOGS_FOLDER_PATH


user = Blueprint('users', __name__,)


@app.route('/')
def index():
    return "Hello, World!"


def permission_failed():
    return make_response(jsonify({'error': 'Permission Failed', 'status_code': 403}), 403)


def request_failed():
    return make_response(jsonify({'error': 'Request Failed', 'status_code': 403}), 403)


def defined_error(description, error="Defined Error", status_code=499):
    return make_response(jsonify({'description': description, 'error': error, 'status_code': status_code}), status_code)


def parameter_error(description, error="Parameter Error", status_code=400):
    if app.config['PRODUCT_ENVIRONMENT'] == "DEV":
        return make_response(jsonify({'description': description, 'error': error, 'status_code': status_code}), status_code)
    else:
        return make_response(jsonify({'description': "Terjadi Kesalahan Sistem", 'error': error, 'status_code': status_code}), status_code)


def bad_request(description):
    if app.config['PRODUCT_ENVIRONMENT'] == "DEV":
        # Development
        return make_response(jsonify({'description': description, 'error': 'Bad Request', 'status_code': 400}), 400)
    else:
        # Production
        return make_response(jsonify({'description': "Terjadi Kesalahan Sistem", 'error': 'Bad Request', 'status_code': 400}), 400)


def randomString(stringLength):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


def random_string_number_only(stringLength):
    letters = string.digits
    return ''.join(random.choice(letters) for i in range(stringLength))


def tambahLogs(logs):
    f = open(app.config['LOGS'] + "/" +
             secure_filename(strftime("%Y-%m-%d")) + ".txt", "a")
    f.write(logs)
    f.close()

# endregion ================================= FUNGSI-FUNGSI AREA ===============================================================


@app.route("/users/register", methods=['POST'])
@cross_origin()
def register():
    ROUTE_NAME = request.path

    try:
        dt = Data()
        data = request.json

        # Check mandatory data
        if "nama" not in data:
            return parameter_error("Missing nama in Request Body")
        if "email" not in data:
            return parameter_error("Missing email in Request Body")
        if "no_tlp" not in data:
            return parameter_error("Missing Nomor Telepon in request body")
        if "password" not in data:
            return parameter_error("Missing password in Request Body")
        if "status_id" not in data:
            return parameter_error("Missing status user in request body")

        # mendapat data dari request body
        nama = request.json.get('nama')
        email = request.json.get('email')
        no_tlp = request.json.get('no_tlp')
        password = request.json.get('password')
        status_id = request.json.get('status_id')

        # check if Email already used or not
        query_temp = "SELECT email FROM users WHERE email = %s"
        values_temp = (email, )
        if len(dt.get_data(query_temp, values_temp)) != 0:
            return defined_error("Email Already Registered")

        # Convert password to MD5
        pass_ency = hashlib.md5(password.encode("utf-8")).hexdigest()

        # Insert to table user
        query = "INSERT into users (nama, email, no_tlp, password, status_id) VALUES (%s, %s, %s, %s, %s)"
        values = (nama, email, no_tlp, pass_ency, status_id)
        id_user = dt.insert_data_last_row(query, values)

        if status_id == "guru" :
            # Insert to table customer
            query2 = "INSERT INTO guru (id_user) VALUES (%s)"
            values2 = (id_user, )
            dt.insert_data(query2, values2)

            hasil = "Silakan Login"

            try:
                logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
                    " - id_user = "+str(id_user)+" - roles = "+str(role)+"\n"
            except Exception as e:
                logs = secure_filename(strftime(
                    "%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME+" - id_user = NULL - roles = NULL\n"
            # tambahLogs(logs)
            return make_response(jsonify({'status_code': 200, 'description': hasil}), 200)
        else :
            # Insert to table customer
            query2 = "INSERT INTO murid (id_user) VALUES (%s)"
            values2 = (id_user, )
            dt.insert_data(query2, values2)

            hasil = "Silakan Login"

            try:
                logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
                    " - id_user = "+str(id_user)+" - roles = "+str(role)+"\n"
            except Exception as e:
                logs = secure_filename(strftime(
                    "%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME+" - id_user = NULL - roles = NULL\n"
            # tambahLogs(logs)
            return make_response(jsonify({'status_code': 200, 'description': hasil}), 200)


        
    except Exception as e:
        return bad_request(str(e))

    return jsonify({"status": "berhasil membuat user"})


@app.route("/users/login", methods=["POST"])
@cross_origin()
def login_users():
    ROUTE_NAME = request.path

    data = request.json
    if "email" not in data:
        return parameter_error("Missing username in Request Body")
    if "password" not in data:
        return parameter_error("Missing username in Request Body")

    email = data["email"]
    password = data["password"]

    email = email.lower()
    password_enc = hashlib.md5(password.encode(
        'utf-8')).hexdigest()  # Convert password to md5


    # Check credential in database
    dt = Data()
    query = """ SELECT b.id_user, b.email, b.password, b.status_id  
            FROM guru a LEFT JOIN users b ON a.id_user=b.id_user
            WHERE a.is_aktif = 1 AND a.is_delete != 1 AND b.status_user = 11 AND b.is_delete != 1 AND  
            b.email = %s """
    values = (email, )
    data_user = dt.get_data(query, values)
    if len(data_user) == 0:
        return defined_error("Email not Registered or not Active", "Invalid Credential", 401)
    data_user = data_user[0]
    db_id_user = data_user["id_user"]
    db_password = data_user["password"]
    db_email = data_user['email']
    db_status_guru = data_user['status_id']

    if password_enc != db_password:
        return defined_error("Wrong Password", "Invalid Credential", 401)
    
    if email == db_email and db_status_guru == "guru":
        role = 21
        role_desc = "guru"

        jwt_payload = {
            "id_user": db_id_user,
            "role": role,
            "role_desc": role_desc,
            "email": email
        }

        access_token = create_access_token(email, additional_claims=jwt_payload)

        # Update waktu terakhir login customer
        query_temp = "UPDATE guru SET waktu_terakhir_login = now() WHERE id_user = %s"
        values_temp = (db_id_user, )
        dt.insert_data(query_temp, values_temp)

        try:
            logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
                " - id_user = "+str(db_id_user)+" - roles = "+str(role)+"\n"
        except Exception as e:
            logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S")) + \
                " - "+ROUTE_NAME+" - id_user = NULL - roles = NULL\n"
        # tambahLogs(logs)

        else :
            role = 21
            role_desc = "murid"

            jwt_payload = {
                "id_user": db_id_user,
                "role": role,
                "role_desc": role_desc,
                "email": email
            }

            access_token = create_access_token(email, additional_claims=jwt_payload)

            # Update waktu terakhir login customer
            query_temp = "UPDATE murid SET waktu_terakhir_login = now() WHERE id_user = %s"
            values_temp = (db_id_user, )
            dt.insert_data(query_temp, values_temp)

            try:
                logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
                    " - id_user = "+str(db_id_user)+" - roles = "+str(role)+"\n"
            except Exception as e:
                logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S")) + \
                    " - "+ROUTE_NAME+" - id_user = NULL - roles = NULL\n"
            # tambahLogs(logs)

    return jsonify(access_token=access_token)
