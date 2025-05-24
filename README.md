# Event Registration System

A secure Flask-based event registration system for managing student events.

## Features

- Secure user authentication and authorization
- Event management (create, edit, delete)
- Student registration for events
- Rate limiting and CSRF protection
- Secure session management
- Comprehensive logging
- HTTPS support

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Virtual environment (recommended)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd event-registration-system
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Configuration

The application uses different configuration classes for development, testing, and production environments. Set the `FLASK_ENV` environment variable to choose the appropriate configuration:

- Development: `export FLASK_ENV=development`
- Testing: `export FLASK_ENV=testing`
- Production: `export FLASK_ENV=production`

Required environment variables:
- `SECRET_KEY`: Flask secret key
- `ADMIN_USERNAME`: Admin username
- `ADMIN_PASSWORD`: Admin password (hashed)

## Running the Application

### Development
```bash
python app.py
```

### Production
```bash
gunicorn -w 4 -b 0.0.0.0:8080 app:app
```

## Security Features

- CSRF Protection
- Rate Limiting
- Secure Session Management
- Password Hashing
- HTTPS Support
- Security Headers
- Input Validation
- Logging and Monitoring

## Testing

Run tests with pytest:
```bash
pytest tests/
```

Generate coverage report:
```bash
coverage run -m pytest tests/
coverage report
```

## Future Improvements

- Migration to a proper database (e.g., PostgreSQL)
- Email verification
- User management system
- API endpoints
- Docker support

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request 