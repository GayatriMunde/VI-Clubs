from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_authorize import Authorize
from flask_mail import Mail, Message

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
authorize = Authorize(app)
mail = Mail(app)

from app import routes, models, errors

if __name__ == "__main__":
    app.run(debug=True)