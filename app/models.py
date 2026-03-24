# models.py
from . import db
from datetime import datetime
from mongoengine import Document, StringField, DateTimeField, DictField, ListField, IntField, ReferenceField, CASCADE, FloatField, BooleanField, EmbeddedDocument, EmbeddedDocumentListField

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
    abuseipdb_report = DictField()
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
            'abuseipdb_report': self.abuseipdb_report,
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BULK SCAN MODEL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class BulkScan(Document):
    meta = {'collection': 'bulk_scans', 'ordering': ['-created_at']}
    
    name = StringField(required=True, max_length=200, default="Untitled Bulk Scan")
    user_id = ReferenceField(User, reverse_delete_rule=CASCADE)
    status = StringField(default="pending", choices=["pending", "running", "completed", "failed"])
    
    total_iocs = IntField(default=0)
    completed_iocs = IntField(default=0)
    
    # Summary stats
    malicious_count = IntField(default=0)
    benign_count = IntField(default=0)
    suspicious_count = IntField(default=0)
    zero_day_count = IntField(default=0)
    unknown_count = IntField(default=0)
    failed_count = IntField(default=0)
    
    # Linked results
    result_ids = ListField(StringField())
    errors = ListField(StringField())
    
    created_at = DateTimeField(default=datetime.utcnow)
    completed_at = DateTimeField()
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'status': self.status,
            'total_iocs': self.total_iocs,
            'completed_iocs': self.completed_iocs,
            'malicious_count': self.malicious_count,
            'benign_count': self.benign_count,
            'suspicious_count': self.suspicious_count,
            'zero_day_count': self.zero_day_count,
            'unknown_count': self.unknown_count,
            'failed_count': self.failed_count,
            'progress': round((self.completed_iocs / self.total_iocs * 100) if self.total_iocs > 0 else 0, 1),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INVESTIGATION / CASE MANAGEMENT MODELS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class InvestigationNote(EmbeddedDocument):
    content = StringField(required=True)
    author = StringField()
    created_at = DateTimeField(default=datetime.utcnow)


class Investigation(Document):
    meta = {'collection': 'investigations', 'ordering': ['-updated_at']}
    
    title = StringField(required=True, max_length=200)
    description = StringField(max_length=2000)
    status = StringField(default="open", choices=["open", "in_progress", "resolved", "closed"])
    severity = StringField(default="medium", choices=["low", "medium", "high", "critical"])
    tags = ListField(StringField(max_length=50))
    
    user_id = ReferenceField(User, reverse_delete_rule=CASCADE)
    linked_scan_ids = ListField(StringField())
    
    notes = EmbeddedDocumentListField(InvestigationNote)
    
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'title': self.title,
            'description': self.description or '',
            'status': self.status,
            'severity': self.severity,
            'tags': self.tags,
            'linked_scan_ids': self.linked_scan_ids,
            'scan_count': len(self.linked_scan_ids),
            'note_count': len(self.notes),
            'notes': [{'content': n.content, 'author': n.author, 'created_at': n.created_at.isoformat() if n.created_at else None} for n in self.notes],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }