from flask import Flask, Blueprint, jsonify, request, make_response, render_template
from flask import current_app as app
from flask_jwt_extended import get_jwt, jwt_required, JWTManager
from flask_cors import cross_origin
from werkzeug.utils import secure_filename
from werkzeug.datastructures import ImmutableMultiDict
from time import gmtime, strftime
import hashlib
import datetime
import requests
import os
import base64
import random
import json
import warnings
import string


from .models import Data
from ... import app


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

# endregion ================================= FUNGSI-FUNGSI AREA ===============================================================


@app.route("/register", methods=['GET', 'POST'])
@cross_origin()
def register():
    ROUTE_NAME = str(request.path)

    now = datetime.datetime.now()
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
        nama = request.json.get('nama', None)
        email = request.json.get('email', None)
        no_tlp = request.json.get('no_tlp', None)
        password = request.json.get('password', None)
        status_id = request.json.get('user_status', None)

        # check if Email already used or not
        query_temp = "SELECT email FROM user WHERE email = %s, 'email'"
        values_temp = (email, )
        if len(dt.get_data(query_temp, values_temp)) != 0:
            return defined_error("Email Already Registered")

        # Convert password to MD5
        pass_ency = hashlib.md5(password.encode('utf-8')).hexdigest()

        # Insert to table user
        query = "INSERT into users (nama, email, nama, no_tlp, password, status_id) VALUES (%s, %s, %s, %s, %s, %s)"
        values = (nama, email, no_tlp, pass_ency, status_id)
        dt.insert_data_last_row(query, values)

    except Exception as e:
        return bad_request(str(e))
    return jsonify({"status": "berhasil membuat user"})
