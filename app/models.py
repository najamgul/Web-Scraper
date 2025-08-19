# app/models.py
from app import db

class IOCResult(db.Model):
    __tablename__ = "ioc_results"
    id = db.Column(db.Integer, primary_key=True)
    input_value = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    classification = db.Column(db.String(50), nullable=False)
    vt_report = db.Column(db.JSON, nullable=True)
    shodan_report = db.Column(db.JSON, nullable=True)
    scraped_data = db.Column(db.JSON, nullable=True)

    feedbacks = db.relationship("Feedback", back_populates="ioc_result", cascade="all, delete-orphan")

class Feedback(db.Model):
    __tablename__ = "feedback"
    id = db.Column(db.Integer, primary_key=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey("ioc_results.id"), nullable=False)
    correct_classification = db.Column(db.String(50), nullable=False)

    ioc_result = db.relationship("IOCResult", back_populates="feedbacks")
