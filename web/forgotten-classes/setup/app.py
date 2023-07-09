from flask import Flask
from routes.routes import bp
from database import db
import secrets

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secret_key = secrets.token_hex(32)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///classroom.db'

app.register_blueprint(bp)

db.initialize_database()
db.disconnect()

if __name__ == '__main__':
    from waitress import serve
    serve(app, host="0.0.0.0", port=3000)
    # app.run(host='0.0.0.0', port=3000)
