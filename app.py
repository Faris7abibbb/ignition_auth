from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'ignition-super-secret-dev-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ignition.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

@app.route('/')
def home():
    return "<h1>Ignition Auth Engine is Online.</h1><p>Awaiting telemetry integration...</p>"

if __name__ == '__main__':
    app.run(debug=True, port=5000)