from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_migrate import Migrate  # ✅ Add this

db = SQLAlchemy()
csrf = CSRFProtect()
migrate = Migrate()  # ✅ Add this

def create_app():
    app = Flask(__name__, template_folder="templates")
    app.config["SECRET_KEY"] = "your_secret_key"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)  # ✅ Add this

    from app.routes import main_bp
    app.register_blueprint(main_bp)

    with app.app_context():
        db.create_all()

    return app