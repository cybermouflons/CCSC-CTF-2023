from flask import current_app, request, jsonify, g
from functools import wraps
from models import Admin, Student, Teacher, Janitor
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = current_app

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def verify(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': "Token is missing"}), 401
       
        token = token.split(" ")[1]
        try:
            alg = jwt.get_unverified_header(token)['alg']
            if alg in ['HS256', 'RS256']:

                token = jwt.decode(token, public_key_pem, algorithms=[alg])
                role  = token.get('role', 'student')

                if role == "admin":
                    user = Admin(token.get('id'), token.get('username'))
                elif role == "student":
                    user = Student(token.get('id'), token.get('username'))
                elif role == "teacher":
                    user = Teacher(token.get('id'), token.get('username'))
                elif role == "janitor":
                    user = Janitor(token.get('id'), token.get('username'))
                else:
                    user = Student(token.get('id'), token.get('username'))

                g.user = user
            else:
                return jsonify({'message': "Invalid algorithm"}), 500
            
        except jwt.ExpiredSignatureError:
            return jsonify({'message': "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': "Invalid token"}), 401
        except Exception:
            return jsonify({'message': "You broke me :("}), 500
            
        return f(user, *args, **kwargs)
    return decorated

def create_access_token(payload, algorithm='HS256'):  
    if algorithm == 'HS256':
        signing_key = app.config['JWT_SECRET_KEY']
    elif algorithm == 'RS256':
        signing_key = private_key_pem.decode()
    else:
        raise ValueError(f'Invalid algorithm: {algorithm}')

    token = jwt.encode(payload, signing_key, algorithm=algorithm)

    return token
      

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = getattr(g, 'user', None)
        if user and user.role == 'admin':
            return f(*args, **kwargs)
        else:
            return jsonify({'message': "Access denied. User is not an admin"}), 403

    return decorated
