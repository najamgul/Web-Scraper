# app/geolocation.py
"""
IP Geolocation Service with Caching
"""
import requests
import os
import logging
from datetime import datetime
from mongoengine import Document, StringField, FloatField, DateTimeField

logger = logging.getLogger(__name__)

# Optional: Use ipinfo.io API key from environment
IPINFO_API_KEY = os.getenv('IPINFO_API_KEY', '')


class GeoCache(Document):
    """
    Cache geolocation data to avoid repeated API calls
    """
    meta = {'collection': 'geo_cache'}
    
    ip = StringField(required=True, unique=True)
    country = StringField()
    country_code = StringField()
    city = StringField()
    region = StringField()
    latitude = FloatField()
    longitude = FloatField()
    org = StringField()
    cached_at = DateTimeField(default=datetime.utcnow)


def get_ip_geolocation(ip_address):
    """
    Get geolocation data for an IP address
    Uses cache first, then falls back to API
    """
    try:
        # Check cache first
        cached = GeoCache.objects(ip=ip_address).first()
        if cached:
            logger.info(f"Using cached geolocation for {ip_address}")
            return {
                'ip': cached.ip,
                'country': cached.country,
                'country_code': cached.country_code,
                'city': cached.city,
                'region': cached.region,
                'latitude': cached.latitude,
                'longitude': cached.longitude,
                'org': cached.org
            }
        
        # Call API
        logger.info(f"Fetching geolocation for {ip_address} from API")
        
        # Using ipinfo.io (free tier: 50k requests/month)
        url = f"https://ipinfo.io/{ip_address}/json"
        if IPINFO_API_KEY:
            url += f"?token={IPINFO_API_KEY}"
        
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            
            # Parse location
            loc = data.get('loc', '').split(',')
            latitude = float(loc[0]) if len(loc) > 0 else None
            longitude = float(loc[1]) if len(loc) > 1 else None
            
            geo_data = {
                'ip': ip_address,
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('country', ''),
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', ''),
                'latitude': latitude,
                'longitude': longitude,
                'org': data.get('org', '')
            }
            
            # Cache the result
            try:
                GeoCache(
                    ip=ip_address,
                    country=geo_data['country'],
                    country_code=geo_data['country_code'],
                    city=geo_data['city'],
                    region=geo_data['region'],
                    latitude=geo_data['latitude'],
                    longitude=geo_data['longitude'],
                    org=geo_data['org']
                ).save()
            except Exception as cache_error:
                logger.warning(f"Failed to cache geolocation: {cache_error}")
            
            return geo_data
        else:
            logger.warning(f"Geolocation API returned {response.status_code}")
            return None
    
    except Exception as e:
        logger.error(f"Error getting geolocation for {ip_address}: {e}")
        return None


def enrich_ip_results_with_geo():
    """
    Background task: Enrich existing IP results with geolocation data
    Run this once to populate geolocation for historical data
    """
    from app.models import IOCResult
    
    ip_results = IOCResult.objects(type="ip")
    enriched_count = 0
    
    for result in ip_results:
        # Check if we already have geo data cached
        if not GeoCache.objects(ip=result.input_value).first():
            geo_data = get_ip_geolocation(result.input_value)
            if geo_data:
                enriched_count += 1
                logger.info(f"Enriched {result.input_value} with geolocation")
    
    logger.info(f"Enriched {enriched_count} IP addresses with geolocation data")
    return enriched_count