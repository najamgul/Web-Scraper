# app/bulk_investigation_routes.py
# Routes for Bulk IOC Scanning and Investigation Notebook
import logging
import threading
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash
from app.models import User, IOCResult, BulkScan, Investigation, InvestigationNote
from app.decorators import login_required

logger = logging.getLogger(__name__)

bulk_bp = Blueprint('bulk', __name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BULK IOC SCANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@bulk_bp.route("/bulk-scan", methods=["GET"])
@login_required
def bulk_scan_page():
    """Render the bulk scan form page"""
    user = User.objects.get(id=session['user_id'])
    past_scans = BulkScan.objects(user_id=user).limit(20)
    return render_template("bulk_scan.html", past_scans=past_scans)


@bulk_bp.route("/api/bulk-scan", methods=["POST"])
@login_required
def start_bulk_scan():
    """Start a bulk IOC scan job"""
    try:
        data = request.get_json()
        ioc_list_raw = data.get('iocs', '')
        scan_name = data.get('name', '').strip() or f"Bulk Scan {datetime.utcnow().strftime('%b %d %H:%M')}"
        
        # Parse IOCs (one per line, remove empties and dupes)
        iocs = list(dict.fromkeys([
            line.strip() for line in ioc_list_raw.strip().split('\n')
            if line.strip() and len(line.strip()) > 2
        ]))
        
        if not iocs:
            return jsonify({'error': 'No valid IOCs provided'}), 400
        
        if len(iocs) > 500:
            return jsonify({'error': 'Maximum 500 IOCs per batch'}), 400
        
        user = User.objects.get(id=session['user_id'])
        
        # Create bulk scan record
        bulk = BulkScan(
            name=scan_name,
            user_id=user,
            status="running",
            total_iocs=len(iocs),
        )
        bulk.save()
        
        # Run scan in background thread
        thread = threading.Thread(
            target=_run_bulk_scan,
            args=(str(bulk.id), iocs, str(user.id)),
            daemon=True
        )
        thread.start()
        
        return jsonify({
            'status': 'started',
            'bulk_id': str(bulk.id),
            'total': len(iocs)
        })
        
    except Exception as e:
        logger.error(f"Bulk scan error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


def _run_bulk_scan(bulk_id, iocs, user_id):
    """Background worker for bulk IOC scanning"""
    from flask import current_app
    from app import create_app
    
    # We need app context for DB access in background thread
    try:
        from app.orchestrator import orchestrate_threat_intelligence
    except ImportError:
        orchestrate_threat_intelligence = None
    
    try:
        # Import within thread context
        from mongoengine import connect
        import os
        
        bulk = BulkScan.objects.get(id=bulk_id)
        user = User.objects.get(id=user_id)
        
        for i, ioc in enumerate(iocs):
            try:
                logger.info(f"[Bulk {bulk_id}] Scanning {i+1}/{len(iocs)}: {ioc[:50]}")
                
                # Detect IOC type
                ioc_type = _detect_type(ioc)
                
                # Check if already scanned
                existing = IOCResult.objects(input_value=ioc, user_id=user).first()
                if existing and existing.classification not in [None, 'Pending', 'Loading...']:
                    classification = existing.classification
                    result_id = str(existing.id)
                else:
                    # Run lightweight scan (skip slow APIs for bulk)
                    from app.vt_shodan_api import vt_lookup_ip, vt_lookup_domain, vt_lookup_url
                    from app.otx_api import otx_lookup
                    
                    vt_data = {}
                    otx_data = {}
                    
                    try:
                        if ioc_type == 'ip':
                            vt_data = vt_lookup_ip(ioc) or {}
                        elif ioc_type == 'domain':
                            vt_data = vt_lookup_domain(ioc) or {}
                        elif ioc_type == 'url':
                            vt_data = vt_lookup_url(ioc) or {}
                    except Exception:
                        pass
                    
                    try:
                        otx_data = otx_lookup(ioc, ioc_type) or {}
                    except Exception:
                        pass
                    
                    # Classify
                    try:
                        from app.ml_model_improved import classify_threat_with_details
                        classification, details = classify_threat_with_details(
                            vt_data=vt_data, otx_data=otx_data,
                            ioc_type=ioc_type, user_input=ioc
                        )
                    except Exception:
                        classification = "Unknown"
                    
                    # Save result
                    ioc_result = IOCResult(
                        input_value=ioc,
                        type=ioc_type,
                        classification=classification,
                        vt_report=vt_data,
                        otx_report=otx_data,
                        user_id=user,
                        timestamp=datetime.utcnow()
                    )
                    ioc_result.save()
                    result_id = str(ioc_result.id)
                
                # Update bulk scan progress
                bulk.reload()
                bulk.completed_iocs = i + 1
                bulk.result_ids.append(result_id)
                
                # Update counters
                cls_lower = (classification or '').lower()
                if 'malicious' in cls_lower:
                    bulk.malicious_count += 1
                elif 'benign' in cls_lower:
                    bulk.benign_count += 1
                elif 'suspicious' in cls_lower:
                    bulk.suspicious_count += 1
                elif 'zero' in cls_lower:
                    bulk.zero_day_count += 1
                else:
                    bulk.unknown_count += 1
                
                bulk.save()
                
            except Exception as e:
                logger.error(f"[Bulk {bulk_id}] Error scanning {ioc}: {e}")
                bulk.reload()
                bulk.completed_iocs = i + 1
                bulk.failed_count += 1
                bulk.errors.append(f"{ioc}: {str(e)[:100]}")
                bulk.save()
        
        # Mark complete
        bulk.reload()
        bulk.status = "completed"
        bulk.completed_at = datetime.utcnow()
        bulk.save()
        logger.info(f"[Bulk {bulk_id}] Completed: {bulk.completed_iocs}/{bulk.total_iocs}")
        
    except Exception as e:
        logger.error(f"[Bulk {bulk_id}] Fatal error: {e}", exc_info=True)
        try:
            bulk = BulkScan.objects.get(id=bulk_id)
            bulk.status = "failed"
            bulk.errors.append(f"Fatal: {str(e)}")
            bulk.save()
        except Exception:
            pass


def _detect_type(ioc):
    """Quick IOC type detection"""
    import re
    ioc = ioc.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        return 'ip'
    if re.match(r'^[a-fA-F0-9]{32,64}$', ioc):
        return 'hash'
    if re.match(r'^https?://', ioc):
        return 'url'
    if '.' in ioc and not ' ' in ioc and len(ioc) < 255:
        return 'domain'
    return 'keyword'


@bulk_bp.route("/api/bulk-scan/<bulk_id>/status", methods=["GET"])
@login_required
def bulk_scan_status(bulk_id):
    """Poll endpoint for bulk scan progress"""
    try:
        bulk = BulkScan.objects.get(id=bulk_id)
        return jsonify(bulk.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 404


@bulk_bp.route("/bulk-results/<bulk_id>")
@login_required
def bulk_results_page(bulk_id):
    """View results of a completed bulk scan"""
    try:
        bulk = BulkScan.objects.get(id=bulk_id)
        results = []
        for rid in bulk.result_ids:
            try:
                r = IOCResult.objects.get(id=rid)
                results.append(r.to_dict())
            except Exception:
                pass
        return render_template("bulk_results.html", bulk=bulk.to_dict(), results=results)
    except Exception as e:
        flash(f"Bulk scan not found: {e}", "danger")
        return redirect(url_for('bulk.bulk_scan_page'))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INVESTIGATION NOTEBOOK / CASE MANAGEMENT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@bulk_bp.route("/investigations")
@login_required
def investigations_list():
    """List all investigations for the current user"""
    user = User.objects.get(id=session['user_id'])
    investigations = Investigation.objects(user_id=user)
    
    # Get recent scans for the "link scan" modal
    recent_scans = IOCResult.objects(user_id=user).order_by('-timestamp').limit(50)
    
    return render_template("investigations.html",
                           investigations=investigations,
                           recent_scans=recent_scans)


@bulk_bp.route("/api/investigations", methods=["POST"])
@login_required
def create_investigation():
    """Create a new investigation"""
    try:
        data = request.get_json()
        user = User.objects.get(id=session['user_id'])
        
        inv = Investigation(
            title=data.get('title', 'Untitled Investigation'),
            description=data.get('description', ''),
            severity=data.get('severity', 'medium'),
            tags=data.get('tags', []),
            user_id=user,
        )
        inv.save()
        
        return jsonify({'status': 'created', 'id': str(inv.id), 'investigation': inv.to_dict()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bulk_bp.route("/investigation/<inv_id>")
@login_required
def investigation_detail(inv_id):
    """View investigation detail page"""
    try:
        inv = Investigation.objects.get(id=inv_id)
        
        # Get linked scan results
        linked_scans = []
        for sid in inv.linked_scan_ids:
            try:
                r = IOCResult.objects.get(id=sid)
                linked_scans.append(r.to_dict())
            except Exception:
                pass
        
        # Get recent scans for linking
        user = User.objects.get(id=session['user_id'])
        recent_scans = IOCResult.objects(user_id=user).order_by('-timestamp').limit(50)
        
        return render_template("investigation_detail.html",
                               inv=inv.to_dict(),
                               linked_scans=linked_scans,
                               recent_scans=recent_scans)
    except Exception as e:
        flash(f"Investigation not found: {e}", "danger")
        return redirect(url_for('bulk.investigations_list'))


@bulk_bp.route("/api/investigation/<inv_id>/link-scan", methods=["POST"])
@login_required
def link_scan_to_investigation(inv_id):
    """Link a scan result to an investigation"""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        
        inv = Investigation.objects.get(id=inv_id)
        if scan_id not in inv.linked_scan_ids:
            inv.linked_scan_ids.append(scan_id)
            inv.updated_at = datetime.utcnow()
            inv.save()
        
        return jsonify({'status': 'linked', 'scan_count': len(inv.linked_scan_ids)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bulk_bp.route("/api/investigation/<inv_id>/unlink-scan", methods=["POST"])
@login_required
def unlink_scan(inv_id):
    """Remove a scan from an investigation"""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        
        inv = Investigation.objects.get(id=inv_id)
        if scan_id in inv.linked_scan_ids:
            inv.linked_scan_ids.remove(scan_id)
            inv.updated_at = datetime.utcnow()
            inv.save()
        
        return jsonify({'status': 'unlinked'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bulk_bp.route("/api/investigation/<inv_id>/note", methods=["POST"])
@login_required
def add_note(inv_id):
    """Add a note to an investigation"""
    try:
        data = request.get_json()
        user = User.objects.get(id=session['user_id'])
        
        inv = Investigation.objects.get(id=inv_id)
        note = InvestigationNote(
            content=data.get('content', ''),
            author=user.email,
            created_at=datetime.utcnow()
        )
        inv.notes.append(note)
        inv.updated_at = datetime.utcnow()
        inv.save()
        
        return jsonify({
            'status': 'added',
            'note': {
                'content': note.content,
                'author': note.author,
                'created_at': note.created_at.isoformat()
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bulk_bp.route("/api/investigation/<inv_id>/status", methods=["POST"])
@login_required
def update_investigation_status(inv_id):
    """Update investigation status/severity"""
    try:
        data = request.get_json()
        inv = Investigation.objects.get(id=inv_id)
        
        if 'status' in data:
            inv.status = data['status']
        if 'severity' in data:
            inv.severity = data['severity']
        if 'tags' in data:
            inv.tags = data['tags']
        
        inv.updated_at = datetime.utcnow()
        inv.save()
        
        return jsonify({'status': 'updated', 'investigation': inv.to_dict()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bulk_bp.route("/api/investigation/<inv_id>", methods=["DELETE"])
@login_required
def delete_investigation(inv_id):
    """Delete an investigation"""
    try:
        inv = Investigation.objects.get(id=inv_id)
        inv.delete()
        return jsonify({'status': 'deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
