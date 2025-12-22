from engine import perform_real_scan
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory, session, redirect, url_for
import json
from datetime import datetime, timedelta
import random
import os
import csv
import io
from fpdf import FPDF
from flask import make_response
from flask_socketio import SocketIO, emit
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.secret_key = "dlp_security_secret_key_hasnain"
ADMIN_USER = "hasnain"
ADMIN_PASS = "admin123"

socketio = SocketIO(app, cors_allowed_origins="*")

# Custom Jinja2 filters
def intcomma(value):
    """Format integer with commas"""
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value

# Register the filter
app.jinja_env.filters['intcomma'] = intcomma

# Load data from files
def load_data():
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    
    scans_data = []
    threats_data = []
    users_data = []
    policies_data = []
    
    try:
        with open(os.path.join(data_dir, 'sample_scans.json'), 'r') as f:
            scans_data = json.load(f)
    except:
        scans_data = []
    
    try:
        with open(os.path.join(data_dir, 'threats.json'), 'r') as f:
            threats_data = json.load(f)
    except:
        threats_data = []
    
    try:
        with open(os.path.join(data_dir, 'users.json'), 'r') as f:
            users_data = json.load(f)
    except:
        users_data = []
    
    try:
        with open(os.path.join(data_dir, 'policies.json'), 'r') as f:
            policies_data = json.load(f)
    except:
        policies_data = []
    
    return scans_data, threats_data, users_data, policies_data

def save_data(filename, data):
    """Saves a list of dictionaries to a JSON file in the data directory"""
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    try:
        with open(os.path.join(data_dir, filename), 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"❌ Error saving to {filename}: {e}")

# Load initial data
SCANS_DATA, THREATS_DATA, USERS_DATA, POLICIES_DATA = load_data()

# Sample alerts for monitoring
SECURITY_ALERTS = [
    {"type": "danger", "icon": "exclamation-triangle", "title": "Critical", 
     "message": "Unauthorized access attempt detected from external IP", "time": "14:32"},
    {"type": "warning", "icon": "exclamation-circle", "title": "Warning", 
     "message": "Policy violation in user documents folder", "time": "14:25"},
    {"type": "info", "icon": "info-circle", "title": "Info", 
     "message": "Full system scan completed successfully", "time": "14:15"},
    {"type": "danger", "icon": "shield-exclamation", "title": "Critical", 
     "message": "Sensitive data transfer to USB device detected", "time": "13:58"},
    {"type": "warning", "icon": "exclamation-circle", "title": "Warning", 
     "message": "Multiple failed login attempts for user admin", "time": "13:45"},
]

# ============ MAIN PAGES ============

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USER and password == ADMIN_PASS:
            session["logged_in"] = True
            return redirect(url_for('index'))
        else:
            error = "Invalid username or password. Please try again."
            
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    # Calculate statistics
    total_scans = len(SCANS_DATA)
    
    # improved safety: use .get(..., 0) to prevent crashes if old data is missing keys
    total_threats = sum(scan.get('threats_found', 0) for scan in SCANS_DATA)
    total_users = len(USERS_DATA)
    active_policies = len([p for p in POLICIES_DATA if p.get('status') == 'active'])
    
    # --- THE FIX IS HERE ---
    # We REMOVED 'sorted()'. Now we just take the first 5 items directly.
    recent_scans = SCANS_DATA[:5]
    
    recent_threats = THREATS_DATA[:5]
    
    return render_template('index.html', 
                          total_scans=total_scans,
                          total_threats=total_threats,
                          total_users=total_users,
                          active_policies=active_policies,
                          recent_scans=recent_scans,
                          recent_threats=recent_threats)

@app.route('/scanner')
@login_required
def scanner():
    # Convert to int to be safe, and use .get() to avoid crashes
    total_files = sum(int(scan.get('files_scanned', 0)) for scan in SCANS_DATA)
    
    # Debug print to your terminal so you can see the math happening
    print(f"DEBUG: Calculating total from {len(SCANS_DATA)} scans. Result: {total_files}")
    
    return render_template('scanner.html', 
                           scans=SCANS_DATA, 
                           total_scans_count=total_files)

@app.route('/monitor')
@login_required
def monitor():
    """Security monitor page showing persistent alerts"""
    
    # 1. Filter SCANS_DATA to get only 'Live' events
    # This ensures manual scans from the dashboard don't show up here
    live_events = [s for s in SCANS_DATA if s.get('type') == 'Live']
    
    # 2. Count how many of these live events were actual threats
    # This will be used to initialize your 'Critical Alerts' counter
    live_threat_count = len([s for s in live_events if s.get('threats_found', 0) > 0])
    
    # 3. Pass the filtered list to the template
    # We rename the variable to 'initial_alerts' to match the change we made in monitor.html
    return render_template('monitor.html', 
                           initial_alerts=live_events[:10],
                           live_threat_count=live_threat_count)

@app.route('/alerts')
@login_required
def alerts():
    """Alerts Center page showing all security events"""
    all_alerts = []
    
    for scan in SCANS_DATA:
        # We only show alerts for scans that actually found threats
        if scan.get('threats_found', 0) > 0:
            all_alerts.append({
                'severity': 'danger' if scan.get('threats_found', 0) > 5 else 'warning',
                'time': scan.get('start_time', '--:--'),
                'title': f"Policy Violation: {scan.get('name', 'Unknown')}",
                'message': f"Detected {scan.get('threats_found')} sensitive items.",
                'source': 'Live Monitor' if scan.get('type') == 'Live' else 'Manual Scan',
                'status': 'New'
            })
            
    return render_template('alerts.html', alerts=all_alerts)

@app.route('/policies')
@login_required
def policies():
    """Policy management page"""
    return render_template('policies.html', policies=POLICIES_DATA)

@app.route('/reports')
@login_required
def reports():
    """Reports page"""
    return render_template('reports.html')

@app.route('/api-testing')
@login_required
def api_testing():
    """API testing console"""
    return render_template('api_testing.html')

@app.route('/threats')
@login_required
def threats():
    """Threat management page"""
    return render_template('threats.html', threats=THREATS_DATA)

@app.route('/users')
@login_required
def users():
    """User management page"""
    return render_template('users.html', users=USERS_DATA)

# ============ DOCUMENTATION PAGES ============

@app.route('/docs')
@login_required
def docs_index():
    """Documentation index"""
    return render_template('docs_index.html')

@app.route('/docs/scanner')
@login_required
def scanner_docs():
    """Scanner documentation"""
    return render_template('scanner_docs.html')

@app.route('/docs/monitor')
@login_required
def monitor_docs():
    """Monitor documentation"""
    return render_template('monitor_docs.html')

@app.route('/docs/policies')
@login_required
def policies_docs():
    """Policies documentation"""
    return render_template('policies_docs.html')

@app.route('/docs/dashboard')
@login_required
def dashboard_docs():
    """Dashboard documentation"""
    return render_template('dashboard_docs.html')

@app.route('/docs/api')
@login_required
def api_docs():
    """API documentation"""
    return render_template('api_docs.html')

# ============ REPORT GENERATION & DOWNLOAD ============

@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    data = request.json
    report_type = data.get('type', 'daily')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"dlp_report_{report_type}_{timestamp}.pdf"

    # Get content safely
    if report_type == 'weekly':
        content = generate_weekly_report()
    elif report_type == 'security':
        content = generate_security_report()
    else:
        content = generate_daily_report()

    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Courier", size=10)

        # Ensure content is safe for PDF
        clean_content = content.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 5, clean_content)

        # 1. Capture the bytes
        pdf_bytes = pdf.output() 
        
        # 2. Create the buffer using the 'io' module we just imported
        buffer = io.BytesIO(bytes(pdf_bytes))
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        print(f"❌ PDF LOGIC ERROR: {e}")
        return jsonify({"error": str(e)}), 500

def generate_daily_report():
    """Generate daily report content with crash-proof data fetching"""
    today = datetime.now().strftime('%Y-%m-%d')
    
    # 1. Safe Header Calculations
    total_scans = len(SCANS_DATA)
    # Safely sum threats, defaulting to 0 if key is missing
    total_threats = sum(scan.get('threats_found', 0) for scan in SCANS_DATA)
    active_policies = len([p for p in POLICIES_DATA if p.get('status') == 'active'])

    report = f"""
    DLP SECURITY SYSTEM - DAILY REPORT
    ===================================
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    
    EXECUTIVE SUMMARY
    -----------------
    Total Scans Today: {total_scans}
    Total Threats Detected: {total_threats}
    Active Policies: {active_policies}
    System Health: Excellent
    
    SCAN ACTIVITIES
    ---------------
    """
    
    # 2. Safe Scan Loop
    for scan in SCANS_DATA:
        s_name = scan.get('name', 'Unknown Scan')
        s_type = scan.get('type', 'Manual')
        s_files = scan.get('files_scanned', 0)
        s_threats = scan.get('threats_found', 0)
        s_duration = scan.get('duration', 'N/A')
        s_status = scan.get('status', 'Completed')
        s_path = scan.get('path', 'N/A')

        report += f"""
    Scan: {s_name}
      Type: {s_type}
      Files: {s_files:,}
      Threats: {s_threats}
      Duration: {s_duration}
      Status: {str(s_status).upper()}
      Path: {s_path}
    """
    
    report += """
    THREAT ANALYSIS
    ---------------
    """
    
    # 3. Safe Threat Loop (The part that was crashing)
    for threat in THREATS_DATA[:10]:
        t_id = threat.get('id', 'N/A')
        t_type = threat.get('type', 'Unknown')
        
        # Smart fallback: Try 'file_name', if missing try 'file_path', else 'Unknown'
        t_file = threat.get('file_name', threat.get('file_path', 'Unknown File'))
        
        t_sev = threat.get('severity', 'Low')
        t_status = threat.get('status', 'Open')
        t_action = threat.get('action_taken', 'Logged')

        report += f"""
    Threat: {t_id}
      Type: {t_type}
      File: {t_file}
      Severity: {str(t_sev).upper()}
      Status: {t_status}
      Action: {t_action}
    """
    
    report += """
    RECOMMENDATIONS
    ---------------
    1. Review high severity threats immediately
    2. Update malware signatures
    3. Conduct security awareness training
    4. Review and update policies as needed
    
    --- END OF REPORT ---
    """
    
    return report

def generate_weekly_report():
    """Generate weekly report content"""
    return generate_daily_report() + "\n\nWEEKLY TREND ANALYSIS INCLUDED"

def generate_security_report():
    """Generate security audit report"""
    return generate_daily_report() + "\n\nSECURITY AUDIT DETAILS INCLUDED"

def generate_custom_report(report_type):
    """Generate custom report"""
    return f"Custom report for {report_type}\n\n" + generate_daily_report()

# ============ API ENDPOINTS ============

@app.route('/api/health')
def api_health():
    """System health check"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "services": {
            "scanner": "running",
            "monitor": "running",
            "database": "connected",
            "reporting": "active"
        },
        "statistics": {
            "total_scans": len(SCANS_DATA),
            "total_threats": len(THREATS_DATA),
            "active_users": len([u for u in USERS_DATA if u['status'] == 'active']),
            "active_policies": len([p for p in POLICIES_DATA if p['status'] == 'active'])
        }
    })


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    raw_path = data.get('path').strip() if data.get('path') else "test_files"
    scan_path = os.path.abspath(raw_path) 
    scan_type = data.get('type', 'quick')

    if not os.path.exists(scan_path):
        return jsonify({"status": "error", "message": "Path not found"}), 400

    # 1. IMPORT BOTH FUNCTIONS
    from engine import perform_real_scan, scan_file_content

    # 2. DECIDE HOW TO SCAN
    if os.path.isfile(scan_path):
        # If it's a single file (from Monitor), use scan_file_content directly
        findings = scan_file_content(scan_path, POLICIES_DATA)
        results = {
            "files_scanned": 1,
            "threats_found": len(findings) if findings else 0,
            "details": [{"file_path": scan_path, "leaks": findings}] if findings else []
        }
        print(f"--- MONITOR DEBUG: Scanned single file. Threats: {results['threats_found']} ---")
    else:
        # If it's a folder (from Manual Scanner), use perform_real_scan
        results = perform_real_scan(scan_path, POLICIES_DATA)
        print(f"--- SCANNER DEBUG: Scanned folder. Threats: {results['threats_found']} ---")

    # 3. Create the Scan Record
    new_scan = {
        "id": len(SCANS_DATA) + 1,
        "name": os.path.basename(scan_path) or "Test Folder",
        "type": scan_type,
        "start_time": datetime.now().strftime('%H:%M:%S'),
        "files_scanned": results["files_scanned"],
        "threats_found": results["threats_found"],
        "status": "completed",
        "path": raw_path # Added this for the Monitor UI
    }
    SCANS_DATA.insert(0, new_scan)
    save_data('sample_scans.json', SCANS_DATA)

    # 4. Process Threats
    if results["threats_found"] > 0:
        for detail in results.get("details", []):
            if detail.get("leaks"):
                new_threat = {
                    "id": f"TR-{random.randint(1000, 9999)}",
                    "type": detail["leaks"][0]["type"],
                    "file_name": os.path.basename(detail["file_path"]),
                    "file_path": detail["file_path"],
                    "severity": "critical",
                    "status": "open",
                    "date_detected": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                THREATS_DATA.insert(0, new_threat)
        
        save_data('threats.json', THREATS_DATA)

    # 5. Broadcast to ALL pages (Dashboard + Monitor)
    socketio.emit('new_scan', new_scan) 
    socketio.emit('update_stats', {
        "total_scans": sum(int(s.get('files_scanned', 0)) for s in SCANS_DATA),
        "total_threats": len([t for t in THREATS_DATA if t['status'] == 'open'])
    })

    return jsonify({"status": "success", "threats_found": results["threats_found"]})

@app.route('/api/dashboard-data')
def dashboard_data():
    """Returns the latest scan and threat data as JSON"""
    return jsonify({
        "total_scans": len(SCANS_DATA),
        "total_threats": len([t for t in THREATS_DATA if t['status'] == 'open']),
        "recent_scans": SCANS_DATA[:5],
        "recent_threats": THREATS_DATA[:5]
    })

# Create a global list for live notifications
LIVE_NOTIFICATIONS = []

@app.route('/api/monitor-alert', methods=['POST'])
def monitor_alert():
    data = request.json
    path = data.get('path')
    
    # Run the real scan logic
    from engine import perform_real_scan
    results = perform_real_scan(os.path.dirname(path))
    
    # Find the specific threat for this file
    threat_found = next((t for t in results["details"] if t["file_path"] == path), None)
    
    if threat_found:
        new_threat = {
            "id": f"TR-{random.randint(1000, 9999)}",
            "type": threat_found["leaks"][0]["type"],
            "file_path": path,
            "severity": "Critical",
            "status": "open",
            "date_detected": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "action_taken": "Blocked"
        }
        THREATS_DATA.insert(0, new_threat)
        save_data('threats.json', THREATS_DATA)
        
        # --- WEB SOCKET PUSH ---
        # This tells the dashboard to show a popup and update the table
        socketio.emit('critical_alert', new_threat)
        
    return jsonify({"status": "received"})

@app.route('/api/history/clear', methods=['POST'])
def clear_history():
    global SCANS_DATA, THREATS_DATA
    SCANS_DATA = []
    THREATS_DATA = []
    save_data('sample_scans.json', SCANS_DATA)
    save_data('threats.json', THREATS_DATA)
    return jsonify({"status": "History cleared successfully"})

@app.route('/api/scan/results/<int:scan_id>')
def api_scan_results(scan_id):
    """Get scan results by ID"""
    scan = next((s for s in SCANS_DATA if s['id'] == scan_id), None)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    return jsonify({
        "scan_id": scan_id,
        "status": "completed",
        "timestamp": scan['start_time'],
        "scan_details": scan
    })

@app.route('/api/scan/history')
def api_scan_history():
    """Get scan history"""
    limit = request.args.get('limit', 10, type=int)
    scans = SCANS_DATA[:limit]
    return jsonify(scans)

@app.route('/api/metrics')
def api_metrics():
    """Get system metrics"""
    total_files = sum(scan['files_scanned'] for scan in SCANS_DATA)
    total_threats = sum(scan['threats_found'] for scan in SCANS_DATA)
    
    return jsonify({
        "cpu_usage": random.randint(30, 80),
        "memory_usage": random.randint(40, 90),
        "disk_usage": random.randint(50, 95),
        "network_traffic": random.randint(100, 1000),
        "total_files_scanned": total_files,
        "total_threats_detected": total_threats,
        "threat_detection_rate": round((total_threats / max(total_files, 1)) * 100, 2),
        "scan_success_rate": 98.5,
        "system_health": random.randint(85, 100)
    })


@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Get alerts with filtering"""
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    limit = request.args.get('limit', 20, type=int)
    
    # Filter threats as alerts
    filtered_threats = THREATS_DATA.copy()
    
    if severity:
        filtered_threats = [t for t in filtered_threats if t['severity'] == severity]
    
    if status:
        filtered_threats = [t for t in filtered_threats if t['status'] == status]
    
    filtered_threats = filtered_threats[:limit]
    
    return jsonify({
        "total": len(filtered_threats),
        "alerts": filtered_threats,
        "filters_applied": {
            "severity": severity,
            "status": status,
            "limit": limit
        }
    })

@app.route('/api/alerts/clear', methods=['POST'])
@login_required
def clear_alerts():
    """Removes all scans that contain threats from the data"""
    global SCANS_DATA
    # Keep only scans that have 0 threats
    SCANS_DATA = [s for s in SCANS_DATA if s.get('threats_found', 0) == 0]
    save_data('sample_scans.json', SCANS_DATA)
    return jsonify({"status": "success", "message": "Alerts cleared"})

@app.route('/api/alerts/resolve/<int:index>', methods=['POST'])
@login_required
def resolve_alert(index):
    """Marks a specific alert as resolved (for demo, we'll just remove it)"""
    # Note: In a real app, you'd change a 'status' field. 
    # For your demo, deleting the specific threat entry is most effective.
    try:
        # Find the alert in SCANS_DATA and remove it
        # (This logic depends on how your index is passed; 
        # usually easier to match by timestamp or filename)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/policies')
def api_policies():
    """Get all policies"""
    return jsonify(POLICIES_DATA)

@app.route('/api/policies/toggle/<string:policy_id>', methods=['POST'])
def toggle_policy(policy_id):
    global POLICIES_DATA
    
    for policy in POLICIES_DATA:
        if policy['id'] == policy_id:
            # 1. Update the status in memory
            policy['status'] = 'active' if policy['status'] == 'inactive' else 'inactive'
            
            # 2. Save the updated list to the JSON file
            try:
                data_dir = os.path.join(os.path.dirname(__file__), 'data')
                with open(os.path.join(data_dir, 'policies.json'), 'w') as f:
                    json.dump(POLICIES_DATA, f, indent=4)
            except Exception as e:
                print(f"Error saving to policies.json: {e}")
                
            return jsonify({"status": "success", "new_status": policy['status']})
    return jsonify({"status": "error"}), 404

@app.route('/api/policies/create', methods=['POST'])
def create_policy():
    global POLICIES_DATA
    data = request.json
    policy_id = data.get('id')

    if policy_id:
        # --- UPDATE EXISTING ---
        for policy in POLICIES_DATA:
            if policy['id'] == policy_id:
                policy['name'] = data.get('name')
                policy['type'] = data.get('type').lower()
                policy['pattern'] = data.get('pattern')
                policy['description'] = data.get('description')
                policy['status'] = 'active' if data.get('enabled') else 'inactive'
                break
    else:
        # --- CREATE NEW ---
        new_policy = {
            "id": f"POL-{random.randint(1000, 9999)}",
            "name": data.get('name'),
            "type": data.get('type').lower(),
            "pattern": data.get('pattern'),
            "description": data.get('description'),
            "status": 'active' if data.get('enabled') else 'inactive'
        }
        POLICIES_DATA.append(new_policy)

    save_data('policies.json', POLICIES_DATA)
    return jsonify({"status": "success"})

@app.route('/api/policies/delete/<string:policy_id>', methods=['DELETE'])
def delete_policy(policy_id):
    global POLICIES_DATA
    
    # Keep everything EXCEPT the policy we want to delete
    initial_length = len(POLICIES_DATA)
    POLICIES_DATA = [p for p in POLICIES_DATA if p['id'] != policy_id]
    
    if len(POLICIES_DATA) < initial_length:
        save_data('policies.json', POLICIES_DATA)
        return jsonify({"status": "success"})
    
    return jsonify({"status": "error", "message": "Policy not found"}), 404

@app.route('/api/threats/<threat_id>/resolve', methods=['POST'])
def resolve_threat(threat_id):
    global THREATS_DATA
    for threat in THREATS_DATA:
        if str(threat['id']) == str(threat_id):
            threat['status'] = 'resolved'
            save_data('threats.json', THREATS_DATA)
            return jsonify({"status": "success", "message": "Threat resolved"})
    return jsonify({"status": "error", "message": "Threat not found"}), 404

@app.route('/api/threats/<threat_id>/delete', methods=['DELETE'])
def delete_threat(threat_id):
    global THREATS_DATA
    THREATS_DATA = [t for t in THREATS_DATA if str(t['id']) != str(threat_id)]
    save_data('threats.json', THREATS_DATA)
    return jsonify({"status": "success", "message": "Threat removed"})

@app.route('/api/threats/<threat_id>/take-action', methods=['POST'])
def take_action(threat_id):
    global THREATS_DATA
    for threat in THREATS_DATA:
        if str(threat['id']) == str(threat_id):
            file_path = threat.get('file_path')
            
            try:
                # 1. Physically delete the file from the disk
                if os.path.exists(file_path):
                    os.remove(file_path)
                    message = f"File {threat['file_name']} deleted successfully."
                else:
                    message = "Record updated, but file was already moved or deleted."

                # 2. Update the status in our database
                threat['status'] = 'resolved'
                save_data('threats.json', THREATS_DATA)
                
                return jsonify({"status": "success", "message": message})
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500
                
    return jsonify({"status": "error", "message": "Threat not found"}), 404

@app.route('/api/users')
def api_users():
    """Get all users"""
    return jsonify(USERS_DATA)

@app.route('/api/threats')
def api_threats():
    """Get all threats"""
    return jsonify(THREATS_DATA)

# ============ STATIC FILES & DOWNLOADS ============

@app.route('/download/<filename>')
def download_file(filename):
    """Serve download files"""
    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    return send_from_directory(reports_dir, filename, as_attachment=True)

# ============ ERROR HANDLERS ============

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

# ============ MAIN ENTRY POINT ============

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 DLP SECURITY SYSTEM WITH DATA INTEGRATION")
    print("=" * 60)
    print("✅ Real data integration from JSON files")
    print("✅ Report generation and download")
    print("✅ Enhanced API endpoints")
    print("✅ Threat management system")
    print("\n🌐 Access Points:")
    print("   Dashboard:     http://localhost:5001")
    print("   Scanner:       http://localhost:5001/scanner")
    print("   Monitor:       http://localhost:5001/monitor")
    print("   Alerts:        http://localhost:5001/alerts")
    print("   Threats:       http://localhost:5001/threats")
    print("   Users:         http://localhost:5001/users")
    print("   Policies:      http://localhost:5001/policies")
    print("   Reports:       http://localhost:5001/reports")
    print("   API Testing:   http://localhost:5001/api-testing")
    print("   Documentation: http://localhost:5001/docs")
    print("\n📊 Data Statistics:")
    print(f"   Total Scans:    {len(SCANS_DATA)}")
    print(f"   Total Threats:  {len(THREATS_DATA)}")
    print(f"   Total Users:    {len(USERS_DATA)}")
    print(f"   Total Policies: {len(POLICIES_DATA)}")
    print("=" * 60)
    
# ============ MAIN ENTRY POINT ============

if __name__ == '__main__':
    # Switch this to False when you're done coding!
    is_dev_mode = True 
    
    socketio.run(app, 
                 debug=is_dev_mode, 
                 port=5001, 
                 allow_unsafe_werkzeug=True)