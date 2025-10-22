# models.py
from . import db
from datetime import datetime
from mongoengine import Document, StringField, DateTimeField, DictField, ListField, IntField, ReferenceField, CASCADE

class User(Document):
    meta = {'collection': 'users'}
    
    email = StringField(required=True, unique=True, max_length=120)
    password = StringField(required=True, max_length=200)
    
    def __repr__(self):
        return f"<User {self.email}>"


class IOCResult(Document):
    meta = {'collection': 'ioc_results'}
    
    input_value = StringField(required=True, max_length=255)
    type = StringField(required=True, max_length=50)
    classification = StringField(required=False, default="Pending")
    vt_report = DictField()
    shodan_report = DictField()
    otx_report = DictField()
    scraped_data = ListField()
    timestamp = DateTimeField(default=datetime.utcnow)
    
    user_id = ReferenceField(User, reverse_delete_rule=CASCADE)
    enrichment_context = DictField()
    def to_dict(self):
        """Helper method for JSON serialization"""
        return {
            'id': str(self.id),
            'input_value': self.input_value,
            'type': self.type,
            'classification': self.classification,
            'vt_report': self.vt_report,
            'shodan_report': self.shodan_report,
            'otx_report': self.otx_report,
            'scraped_data': self.scraped_data,
            'enrichment_context': self.enrichment_context,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'user_id': str(self.user_id.id) if self.user_id else None
        }


class Feedback(Document):
    meta = {'collection': 'feedback'}
    
    ioc_id = ReferenceField(IOCResult, required=True, reverse_delete_rule=CASCADE)
    correct_classification = StringField(required=True, max_length=50)