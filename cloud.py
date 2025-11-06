from flask import Flask
from flask_cors import CORS
import sys
import os

# Ensure proper imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db
from config import Config
from app.routes import auth_bp

def create_app():
    """Create and configure Flask app"""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize database
    init_db(app)
    
    # Configure CORS
    CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    
    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint"""
        from flask import jsonify
        return jsonify({'status': 'ok'}), 200
    
    return app

if __name__ == '__main__':
    import os
    from flask import jsonify
    
    app = create_app()
    
    # Get port from environment (Heroku) or use default
    port = int(os.environ.get('PORT', 5001))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    app.run(host=host, port=port, debug=debug)

