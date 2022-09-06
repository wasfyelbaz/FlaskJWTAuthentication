from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager

from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from dotenv import load_dotenv

import datetime
import os

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(minutes=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES")))
app.config["JWT_IDENTITY_CLAIM"] = "public_id"

db = SQLAlchemy(app)
jwt = JWTManager(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
# run db.create_all() to affect the sqlite db


def verify_register_user_data(data):
    """verifies that a list of keys exist in the JSON data and :returns a list of missing keys"""
    keys_to_verify = ["username", "password"]
    missing_kays = []

    # verify JSON data
    for key in keys_to_verify:
        try:
            data[key]
        except KeyError:
            missing_kays.append(key)

    return missing_kays


def check_password_strength(password):
    """:returns False if the password doesn't follow the password policy, True otherwise."""
    # Policy:
    # Minimum length of 8 characters
    if len(list(password)) < 8:
        return False
    return True


@app.route("/register", methods=["GET", "POST"])
def signup_user():
    """handles the user registration process"""
    # get JSON data from request
    try:
        data = request.get_json()
    except Exception:
        return jsonify({"msg": "Invalid JSON format"}), 400

    # verify JSON data
    missing_data = verify_register_user_data(data)
    if len(missing_data) > 0:
        return jsonify({
            "msg": "Missing " + ", ".join(missing_data)
        }), 400

    # chek if user exists
    if Users.query.filter_by(username=data["username"]).first() is not None:
        return jsonify({
            "msg": "User already exists "
        }), 400

    # check password strength
    if not check_password_strength(data["password"]):
        return jsonify({
            "msg": "Weak password"
        }), 400

    # hash the password
    hashed_password = generate_password_hash(data["password"], method="sha256")

    # add user to the database
    new_user = Users(public_id=str(uuid.uuid4()), username=data["username"], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User registered successfully"})


@app.route("/login", methods=["GET", "POST"])
def login_user():
    """handles the user authentication process"""
    # get JSON data from request
    try:
        data = request.get_json()
    except Exception:
        return jsonify({"msg": "Invalid JSON format"}), 400

    user = Users.query.filter_by(username=data["username"]).first()
    # user doesn't exist
    if user is None:
        return jsonify({"msg": "Invalid username or password"}), 401
    # return access token if logged in successfully
    if check_password_hash(user.password, data["password"]):
        access_token = create_access_token(identity=user.public_id)
        return jsonify(access_token=access_token)

    return jsonify({"msg": "Invalid username or password"}), 401


@app.route("/protected")
@jwt_required()
def protected():
    """protected area by JWT"""
    return f"Hello to the protected area, your public id is {get_jwt_identity()}"


if __name__ == "__main__":
    app.run()
