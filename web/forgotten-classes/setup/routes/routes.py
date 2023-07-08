from flask import Blueprint, request, jsonify
from database import hash_password, db
from models import ComputerRoom
from middleware.authorization import create_access_token, verify, admin_required
from utils import merge


bp = Blueprint('bp',__name__)

@bp.before_request
def validate_content_type():
    if request.method != 'GET' and not request.is_json:
        return jsonify({'error': 'Invalid Content-Type. Only JSON requests are accepted.'}), 400


@bp.route('/', methods=['GET'])
@verify
def home(user):
    msg = f"""Hello {user.username}! Here is your card info: 
    ID: {user.id}
    Role: {user.role}
    """
    return msg, 200


@bp.route('/login', methods=['POST'])
def login():

    data = request.json
    username = data.get('username')
    password = hash_password(data.get('password'))

    row = db.login({
        "username":username,
        "password":password
    })
    if row:
        id, username, role = row 
        payload = {
            'id': id,
            'username': username,
            'role': role
        }

        access_token = create_access_token(payload, algorithm='RS256')
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'error': 'Wrong username/password'}), 401


@bp.route('/register', methods=['POST'])
def register():

    data = request.json
    username = data.get('username')
    password = hash_password(data.get('password'))

    data = {
        "username":username,
        "password":password,
        "role": "student"
    }

    if db.user_exists(data):
        return jsonify({'message': 'User exists.'}), 401
    
    db.insert_user(data)

    return jsonify({'message': 'User registered successfully.'}), 201


@bp.route('/update', methods=['POST'])
@verify
def update(user):
    update_info = request.json
    merge(update_info, user)
    return jsonify({'message': "User updated successfully"}), 200

@bp.route('/admin', methods=['GET'])
@verify
@admin_required
def admin(user):
    room = ComputerRoom()

    msg = f"""Welcome {user.username}, here are the stats:
    {room.get_max(40)}
    {room.last_login()}
    """
    return msg, 200