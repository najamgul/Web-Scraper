# __init__.py
from flask import Flask
from flask_wtf import CSRFProtect
from mongoengine import connect
from dotenv import load_dotenv
import os

# app/__init__.py

app = Flask(__name__)
  # if you have routes.py

# Load environment variables
load_dotenv()

csrf = CSRFProtect()
db = None  # Kept for compatibility



def create_app():
    app = Flask(__name__, template_folder="templates")
    
    # Load config from environment variables
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback-secret-key")
    app.config["MONGODB_URI"] = os.getenv("MONGODB_URI")
    
    # Optional Flask configs
    app.config["DEBUG"] = os.getenv("FLASK_DEBUG", "False") == "True"
    
    # Set CSRF timeout based on an environment variable, defaulting to no expiry
    csrf_timeout = os.getenv("WTF_CSRF_TIME_LIMIT", "").strip()
    if not csrf_timeout or csrf_timeout.lower() == "none":
        app.config["WTF_CSRF_TIME_LIMIT"] = None
    else:
        try:
            app.config["WTF_CSRF_TIME_LIMIT"] = int(csrf_timeout)
        except ValueError:
            app.config["WTF_CSRF_TIME_LIMIT"] = 3600
    
    # Connect to MongoDB Atlas
    try:
        connect(host=app.config["MONGODB_URI"])
        print("✅ Connected to MongoDB Atlas")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        raise
    
    csrf.init_app(app)
    from app import routes
    from app.routes import main_bp
    app.register_blueprint(main_bp)
    
    

    return app