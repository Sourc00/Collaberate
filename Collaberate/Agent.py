from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    instructor = db.Column(db.String(100), nullable=False)
    duration = db.Column(db.Integer)  # in hours
    category = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    curriculum = db.Column(db.Text)
    ai_powered = db.Column(db.Boolean, default=False)
    ai_features = db.Column(db.Text)  # JSON string of AI features

    def __str__(self):
        return self.title

    # ... (keep existing relationships and methods)