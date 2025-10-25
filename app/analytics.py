# app/analytics.py
"""
Threat Intelligence Analytics and Dashboard Logic
"""
from datetime import datetime, timedelta
from collections import Counter
from app.models import IOCResult, User
from mongoengine import Q
import logging

logger = logging.getLogger(__name__)


def _prepare_aggregate_results(items):
    """Convert aggregation results into JSON-friendly dictionaries."""
    formatted = []
    for item in items:
        if isinstance(item, dict):
            cleaned = dict(item)
            last_seen = cleaned.get('last_seen')
            if isinstance(last_seen, datetime):
                cleaned['last_seen'] = last_seen.isoformat()
            formatted.append(cleaned)
    return formatted


def get_dashboard_stats():
    """
    Get overall dashboard statistics
    """
    try:
        total_scans = IOCResult.objects.count()
        
        # Count by classification
        malicious_count = IOCResult.objects(classification="Malicious").count()
        benign_count = IOCResult.objects(classification="Benign").count()
        suspicious_count = IOCResult.objects(classification="Suspicious").count()
        informational_count = IOCResult.objects(classification="Informational").count()
        unknown_count = IOCResult.objects(classification="Unknown").count()
        
        # Count by type
        ip_count = IOCResult.objects(type="ip").count()
        domain_count = IOCResult.objects(type="domain").count()
        url_count = IOCResult.objects(type="url").count()
        hash_count = IOCResult.objects(type="hash").count()
        keyword_count = IOCResult.objects(type="keyword").count()
        
        # Recent activity (last 24 hours)
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_scans = IOCResult.objects(timestamp__gte=yesterday).count()
        
        return {
            'total_scans': total_scans,
            'malicious': malicious_count,
            'benign': benign_count,
            'suspicious': suspicious_count,
            'informational': informational_count,
            'unknown': unknown_count,
            'ip_count': ip_count,
            'domain_count': domain_count,
            'url_count': url_count,
            'hash_count': hash_count,
            'keyword_count': keyword_count,
            'recent_scans_24h': recent_scans,
            'malicious_percentage': round((malicious_count / total_scans * 100) if total_scans > 0 else 0, 1)
        }
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return None


def get_top_malicious_ips(limit=10):
    """Return top IP activity prioritized by malicious detections."""
    try:
        primary_match = {
            "type": "ip",
            "classification": {"$in": ["Malicious", "Suspicious"]}
        }
        pipeline = [
            {"$match": primary_match},
            {"$group": {
                "_id": "$input_value",
                "count": {"$sum": 1},
                "classification": {"$first": "$classification"},
                "last_seen": {"$max": "$timestamp"}
            }},
            {"$sort": {"count": -1}},
            {"$limit": limit}
        ]

        results = list(IOCResult.objects.aggregate(pipeline))
        if results:
            logger.info(f"📊 Top Malicious IPs: Found {len(results)} malicious/suspicious results")
            return _prepare_aggregate_results(results), "malicious"

        fallback_match = {
            "type": "ip",
            "classification": {"$nin": [None, "", "Pending", "Loading...", "Unknown"]}
        }
        fallback_pipeline = [
            {"$match": fallback_match},
            {"$group": {
                "_id": "$input_value",
                "count": {"$sum": 1},
                "classification": {"$first": "$classification"},
                "last_seen": {"$max": "$timestamp"}
            }},
            {"$sort": {"count": -1}},
            {"$limit": limit}
        ]

        fallback_results = list(IOCResult.objects.aggregate(fallback_pipeline))
        logger.info(f"📊 Top IPs fallback: Showing {len(fallback_results)} results due to no malicious detections")
        return _prepare_aggregate_results(fallback_results), "all"
    except Exception as e:
        logger.error(f"Error getting top malicious IPs: {e}")
        return [], "error"


def get_top_malicious_domains(limit=10):
    """Return top domain/URL activity prioritized by malicious detections."""
    try:
        primary_match = {
            "type": {"$in": ["domain", "url"]},
            "classification": {"$in": ["Malicious", "Suspicious"]}
        }
        pipeline = [
            {"$match": primary_match},
            {"$group": {
                "_id": "$input_value",
                "count": {"$sum": 1},
                "type": {"$first": "$type"},
                "classification": {"$first": "$classification"},
                "last_seen": {"$max": "$timestamp"}
            }},
            {"$sort": {"count": -1}},
            {"$limit": limit}
        ]

        results = list(IOCResult.objects.aggregate(pipeline))
        if results:
            return _prepare_aggregate_results(results), "malicious"

        fallback_match = {
            "type": {"$in": ["domain", "url"]},
            "classification": {"$nin": [None, "", "Pending", "Loading...", "Unknown"]}
        }
        fallback_pipeline = [
            {"$match": fallback_match},
            {"$group": {
                "_id": "$input_value",
                "count": {"$sum": 1},
                "type": {"$first": "$type"},
                "classification": {"$first": "$classification"},
                "last_seen": {"$max": "$timestamp"}
            }},
            {"$sort": {"count": -1}},
            {"$limit": limit}
        ]

        fallback_results = list(IOCResult.objects.aggregate(fallback_pipeline))
        return _prepare_aggregate_results(fallback_results), "all"
    except Exception as e:
        logger.error(f"Error getting top malicious domains: {e}")
        return [], "error"


def get_geolocation_data():
    """
    Get geographic distribution of malicious IPs
    Returns data formatted for chart display
    """
    try:
        from app.geolocation import GeoCache
        
        # Get all malicious/suspicious IPs
        malicious_ips = IOCResult.objects(
            Q(type="ip") & Q(classification__in=["Malicious", "Suspicious"])
        )
        
        logger.info(f"🌍 Geolocation: Analyzing {malicious_ips.count()} malicious/suspicious IPs")
        
        country_counts = Counter()
        ips_without_geo = []
        
        for result in malicious_ips:
            country = None
            
            # First try to get from GeoCache
            geo_cache = GeoCache.objects(ip=result.input_value).first()
            if geo_cache and geo_cache.country:
                country = geo_cache.country
            
            # Try to get country from Shodan report
            if not country and result.shodan_report:
                # Shodan can have nested structure
                if isinstance(result.shodan_report, dict):
                    # Check various possible locations
                    country = (
                        result.shodan_report.get('country') or
                        result.shodan_report.get('country_name') or
                        result.shodan_report.get('details', {}).get('country') or
                        result.shodan_report.get('data', {}).get('country')
                    )
            
            # Fallback to VirusTotal report
            if not country and result.vt_report:
                if isinstance(result.vt_report, dict):
                    country = (
                        result.vt_report.get('country') or
                        result.vt_report.get('details', {}).get('country') or
                        result.vt_report.get('data', {}).get('attributes', {}).get('country')
                    )
            
            # Fallback to OTX report
            if not country and result.otx_report:
                if isinstance(result.otx_report, dict):
                    country = (
                        result.otx_report.get('country') or
                        result.otx_report.get('details', {}).get('country')
                    )
            
            # Only count valid countries
            if country and country.strip() and country not in ["Unknown", "", "N/A", "None"]:
                country_counts[country] += 1
            else:
                ips_without_geo.append(result.input_value)
        
        # Convert to list format for Chart.js
        geo_data = []
        for country, count in country_counts.most_common(20):
            geo_data.append({
                'country': country,
                'count': count
            })
        
        logger.info(f"   Geographic data: {len(geo_data)} countries found")
        logger.info(f"   Top countries: {dict(country_counts.most_common(5))}")
        if len(ips_without_geo) > 0:
            logger.warning(f"   ⚠️ {len(ips_without_geo)} IPs without geolocation data: {ips_without_geo[:5]}")
        
        if len(geo_data) == 0:
            logger.warning("   ℹ️ No geographic data available. This is normal if:")
            logger.warning("      1. No malicious IPs have been scanned yet")
            logger.warning("      2. Shodan/VT didn't return country information")
            logger.warning("      3. All scanned IPs are classified as Benign")
        
        return geo_data
    except Exception as e:
        logger.error(f"Error getting geolocation data: {e}", exc_info=True)
        return []


def get_threat_timeline(days=30):
    """
    Get threat classification timeline for the past N days
    """
    try:
        start_date = datetime.utcnow() - timedelta(days=days)
        
        pipeline = [
            {"$match": {"timestamp": {"$gte": start_date}}},
            {"$group": {
                "_id": {
                    "date": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                    "classification": "$classification"
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id.date": 1}}
        ]
        
        results = list(IOCResult.objects.aggregate(pipeline))
        
        # Format for Chart.js
        timeline_data = {}
        for item in results:
            date = item['_id']['date']
            classification = item['_id']['classification']
            count = item['count']
            
            if date not in timeline_data:
                timeline_data[date] = {
                    'Malicious': 0,
                    'Benign': 0,
                    'Suspicious': 0,
                    'Informational': 0,
                    'Unknown': 0
                }
            
            timeline_data[date][classification] = count
        
        return timeline_data
    except Exception as e:
        logger.error(f"Error getting threat timeline: {e}")
        return {}


def get_recent_threats(limit=20):
    """
    Get most recent threat detections (live feed)
    """
    try:
        recent = IOCResult.objects(
            classification__nin=[None, "", "Pending", "Loading...", "Unknown"]
        ).order_by('-timestamp').limit(limit)
        
        feed = []
        for item in recent:
            classification = item.classification or "Unknown"
            feed.append({
                'id': str(item.id),
                'input': item.input_value,
                'type': item.type,
                'classification': classification,
                'timestamp': item.timestamp.isoformat() if item.timestamp else None,
                'threat_score': item.otx_report.get('threat_score', 0) if item.otx_report else 0
            })
        
        return feed
    except Exception as e:
        logger.error(f"Error getting recent threats: {e}")
        return []


def get_threat_score_trend(ioc_value, days=30):
    """
    Get threat score trend for a specific IOC over time
    """
    try:
        start_date = datetime.utcnow() - timedelta(days=days)
        
        results = IOCResult.objects(
            input_value=ioc_value,
            timestamp__gte=start_date
        ).order_by('timestamp')
        
        trend_data = []
        for result in results:
            threat_score = 0
            if result.otx_report and 'threat_score' in result.otx_report:
                threat_score = result.otx_report['threat_score']
            
            trend_data.append({
                'timestamp': result.timestamp.isoformat() if result.timestamp else None,
                'threat_score': threat_score,
                'classification': result.classification
            })
        
        return trend_data
    except Exception as e:
        logger.error(f"Error getting threat score trend: {e}")
        return []


def get_classification_breakdown():
    """
    Get detailed classification breakdown with percentages
    """
    try:
        total = IOCResult.objects.count()
        if total == 0:
            return {}
        
        classifications = ['Malicious', 'Benign', 'Suspicious', 'Informational', 'Unknown']
        breakdown = {}
        
        for cls in classifications:
            count = IOCResult.objects(classification=cls).count()
            percentage = round((count / total * 100), 1)
            breakdown[cls] = {
                'count': count,
                'percentage': percentage
            }
        
        return breakdown
    except Exception as e:
        logger.error(f"Error getting classification breakdown: {e}")
        return {}


def get_top_threat_tags(limit=15):
    """
    Get most common threat tags from OTX reports
    """
    try:
        malicious_results = IOCResult.objects(
            classification__in=["Malicious", "Suspicious"]
        )
        
        all_tags = []
        for result in malicious_results:
            if result.otx_report and 'details' in result.otx_report:
                tags = result.otx_report['details'].get('top_tags', [])
                all_tags.extend(tags)
        
        tag_counts = Counter(all_tags)
        top_tags = [{'tag': tag, 'count': count} for tag, count in tag_counts.most_common(limit)]
        
        return top_tags
    except Exception as e:
        logger.error(f"Error getting top threat tags: {e}")
        return []