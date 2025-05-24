import os
from werkzeug.security import generate_password_hash
from datetime import timedelta

class Config:
    # Base configuration
    FLASK_APP = 'app.py'
    JSON_SORT_KEYS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Admin credentials
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD_HASH') or generate_password_hash('admin123')
    
    # Excel files
    REGISTRATIONS_FILE = 'registrations.xlsx'
    EVENTS_FILE = 'events.xlsx'
    
    # Secret key - Using environment variable or a default secure key
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)
    
    # Store the secret key if it was generated
    if not os.environ.get('FLASK_SECRET_KEY'):
        os.makedirs('instance', exist_ok=True)
        env_file = os.path.join('instance', '.env')
        with open(env_file, 'a') as f:
            if os.path.getsize(env_file) > 0:
                f.write('\n')
            f.write(f'FLASK_SECRET_KEY={SECRET_KEY.hex()}')

    # Security Settings
    SESSION_COOKIE_SECURE = False  # Set to True in production
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # CSRF Settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = SECRET_KEY
    
    # Rate Limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = "memory://"
    RATELIMIT_DEFAULT = "100/hour"
    
    # File Paths
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    LOG_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    
    # Logging Configuration
    LOG_FORMAT = '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    LOG_MAX_BYTES = 10000000  # 10MB
    LOG_BACKUP_COUNT = 10
    
    # Security Constants
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_TIME = 300  # 5 minutes
    PASSWORD_MIN_LENGTH = 12

    @staticmethod
    def init_app(app):
        # Create necessary directories
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.LOG_FOLDER, exist_ok=True)

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = True
    WTF_CSRF_ENABLED = True

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    PROPAGATE_EXCEPTIONS = True
    SESSION_COOKIE_SECURE = True
    
    # In production, these should be set through environment variables
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD_HASH')
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
    
    # Ensure critical configs are set
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        required_vars = ['ADMIN_USERNAME', 'ADMIN_PASSWORD_HASH', 'FLASK_SECRET_KEY']
        missing = [var for var in required_vars if not getattr(cls, var)]
        if missing:
            raise ValueError(
                f"Missing required environment variables for production: {', '.join(missing)}"
            )

# Select configuration based on environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

# Get current configuration
current_config = config[os.environ.get('FLASK_ENV', 'default')]

# Export configuration values
ADMIN_USERNAME = current_config.ADMIN_USERNAME
ADMIN_PASSWORD = current_config.ADMIN_PASSWORD
REGISTRATIONS_FILE = current_config.REGISTRATIONS_FILE
EVENTS_FILE = current_config.EVENTS_FILE
SECRET_KEY = current_config.SECRET_KEY 