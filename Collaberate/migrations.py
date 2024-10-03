from app import app, db
from flask_migrate import Migrate

migrate = Migrate(app, db)

if __name__ == '__main__':
    from models import *  # This imports all models to ensure they're recognized by Flask-Migrate