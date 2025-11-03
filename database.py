from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import sys
import os

# Add parent directory to path to import config
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

db = SQLAlchemy()

def init_db(app: Flask):
    """Initialize database connection"""
    app.config.from_object(Config)
    db.init_app(app)
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    return db

