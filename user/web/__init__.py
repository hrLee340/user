from flask import Flask
from flask_session import Session
from .blue_prints import bp_user


def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('../config.py')

    # session 设置
    Session(app)

    app.register_blueprint(bp_user.BP)
    return app
