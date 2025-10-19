# app/whois_lookup.py
"""
WHOIS Lookup Service
Retrieves domain registration information
"""
import logging
from datetime import datetime
import re

logger = logging.getLogger(__name__)


def get_whois_data(domain):
    """
    Get WHOIS data for a domain
    
    Args:
        domain (str): Domain name to look up
    
    Returns:
        dict: WHOIS information or error
    """
    try:
        import whois
        
        # Clean domain (remove http://, www., etc.)
        clean_domain = clean_domain_for_whois(domain)
        
        logger.info(f"Performing WHOIS lookup for: {clean_domain}")
        
        w = whois.whois(clean_domain)
        
        if not w:
            return {'error': 'WHOIS lookup failed'}
        
        # Parse creation date
        creation_date = None
        days_old = None
        
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            
            if creation_date:
                if isinstance(creation_date, str):
                    creation_str = creation_date
                else:
                    creation_str = creation_date.strftime('%Y-%m-%d')
                    days_old = (datetime.now() - creation_date).days
        
        # Check for privacy protection
        privacy_protected = is_privacy_protected(w)
        
        return {
            'domain': clean_domain,
            'registrar': w.registrar if w.registrar else 'Unknown',
            'creation_date': creation_str if creation_date else 'Unknown',
            'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
            'days_old': days_old,
            'name_servers': w.name_servers if w.name_servers else [],
            'status': w.status if w.status else [],
            'privacy_protected': privacy_protected,
            'registrant_country': w.country if hasattr(w, 'country') else 'Unknown'
        }
    
    except ImportError:
        logger.error("python-whois not installed. Run: pip install python-whois")
        return {'error': 'WHOIS library not available'}
    
    except Exception as e:
        logger.warning(f"WHOIS lookup error for {domain}: {e}")
        return {'error': str(e)}


def clean_domain_for_whois(domain):
    """
    Clean domain string for WHOIS lookup
    Removes http://, https://, www., and paths
    """
    # Remove protocol
    domain = re.sub(r'^https?://', '', domain)
    
    # Remove www.
    domain = re.sub(r'^www\.', '', domain)
    
    # Remove path and query string
    domain = domain.split('/')[0].split('?')[0]
    
    return domain


def is_privacy_protected(whois_data):
    """
    Check if WHOIS data shows privacy protection
    """
    try:
        # Check registrant name/org for privacy keywords
        privacy_keywords = [
            'privacy', 'protected', 'whoisguard', 'domain proxy', 
            'domains by proxy', 'redacted', 'data redacted'
        ]
        
        fields_to_check = []
        
        if hasattr(whois_data, 'name'):
            fields_to_check.append(str(whois_data.name).lower())
        if hasattr(whois_data, 'org'):
            fields_to_check.append(str(whois_data.org).lower())
        if hasattr(whois_data, 'registrant_name'):
            fields_to_check.append(str(whois_data.registrant_name).lower())
        
        for field in fields_to_check:
            if any(keyword in field for keyword in privacy_keywords):
                return True
        
        return False
    except:
        return False