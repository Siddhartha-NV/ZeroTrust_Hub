import os
import json
import hmac
import hashlib
import shutil
import threading
import socket
import bcrypt
import mysql.connector
from datetime import datetime, timedelta
from flask import Flask, request, session, jsonify
from functools import wraps
from getmac import get_mac_address
import time

# ===============================
# 1. IMMUTABLE LEDGER (BLOCKCHAIN)
# ===============================
class ImmutableAuditLedger:
    def __init__(self, file_path="secure_logs_chain.json", secret_key="LEDGER_HMAC_SECRET"):
        self.file_path = file_path
        self.secret_key = secret_key.encode()
        self.lock = threading.Lock()
        if not os.path.exists(self.file_path):
            self._create_genesis_block()

    def _calculate_hash(self, index, timestamp, data, previous_hash):
        data_string = json.dumps(data, sort_keys=True)
        raw = f"{index}{timestamp}{data_string}{previous_hash}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _sign_hash(self, block_hash):
        return hmac.new(self.secret_key, block_hash.encode(), hashlib.sha256).hexdigest()

    def _create_genesis_block(self):
        ts = datetime.utcnow().isoformat()
        data = {"event": "GENESIS", "msg": "Audit chain initialized"}
        h = self._calculate_hash(0, ts, data, "0")
        block = {
            "index": 0, "timestamp": ts, "data": data,
            "previous_hash": "0", "hash": h, "signature": self._sign_hash(h)
        }
        self._atomic_save([block])

    def load_chain(self):
        try:
            with open(self.file_path, "r") as f: return json.load(f)
        except: return []

    def _atomic_save(self, chain):
        temp = f"{self.file_path}.tmp"
        with open(temp, "w") as f: json.dump(chain, f, indent=4)
        shutil.move(temp, self.file_path)

    def verify_chain(self):
        chain = self.load_chain()
        if not chain: return False, "Chain empty"
        for i in range(len(chain)):
            b = chain[i]
            if b["hash"] != self._calculate_hash(b["index"], b["timestamp"], b["data"], b["previous_hash"]):
                return False, f"Hash mismatch at block {i}"
            if b["signature"] != self._sign_hash(b["hash"]):
                return False, f"Sig mismatch at block {i}"
            if i > 0 and b["previous_hash"] != chain[i-1]["hash"]:
                return False, f"Broken link at block {i}"
        return True, "Valid"

    def add_block(self, event_type, payload):
        with self.lock:
            # Verify integrity before adding new records
            valid, msg = self.verify_chain()
            if not valid: 
                print(f"[CRITICAL] Ledger Corrupted: {msg}")
                return False
            
            chain = self.load_chain()
            prev = chain[-1]
            ts = datetime.utcnow().isoformat()
            data = {"event_type": event_type, "payload": payload}
            h = self._calculate_hash(prev["index"]+1, ts, data, prev["hash"])
            new_block = {
                "index": prev["index"]+1, "timestamp": ts, "data": data,
                "previous_hash": prev["hash"], "hash": h, "signature": self._sign_hash(h)
            }
            chain.append(new_block)
            self._atomic_save(chain)
            return True

# ===============================
# 2. CORE CONFIGURATION
# ===============================
app = Flask(__name__)
app.secret_key = "highly_secure_and_random_key"

ledger = ImmutableAuditLedger()

db_config = {
    "host": "localhost",
    "user": "root", 
    "password": "youpassword", 
    "database": "network_monitor"
}

INFRA_DEVICES = {
    "HR_Printer": {"ip": "192.168.1.50", "port": 9100, "priority": "low", "mac": "00:1A:2B:3C:4D:5E"},
    "ID_Scanner": {"ip": "192.168.1.60", "port": 4370, "priority": "high", "mac": "AA:BB:CC:DD:EE:FF"},
    "Core_Switch": {"ip": "192.168.1.1", "port": 80, "priority": "critical", "mac": "FF:FF:FF:FF:FF:FE"}
}

device_health = {}
threat_alerts = []
active_admin_sessions = {}

# ===============================
# 3. HELPERS & SECURITY
# ===============================
def get_db_connection():
    return mysql.connector.connect(**db_config)

def log_event(user, ip, status, event_type, msg, fingerprint=None):
    """Logs to both MySQL and the Blockchain Ledger."""
    try:
        # 1. MySQL Logging
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO access_logs (username, ip_address, login_time, status, fingerprint) 
            VALUES (%s, %s, %s, %s, %s)
        """, (user, ip, datetime.now(), status, fingerprint))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[ERROR] MySQL Log Failed: {e}")

    try:
        # 2. Blockchain Logging
        ledger.add_block(event_type, {"user": user, "ip": ip, "msg": msg})
    except Exception as e:
        print(f"[ERROR] Blockchain Log Failed: {e}")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin_user" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def get_fingerprint():
    """Generates a hardware/browser-specific fingerprint."""
    raw = f"{request.remote_addr}{request.headers.get('User-Agent')}"
    return hashlib.sha256(raw.encode()).hexdigest()

def tcp_ping(host, port):
    try:
        s = socket.create_connection((host, port), timeout=2)
        s.close()
        return True
    except:
        return False

# ===============================
# 4. MONITORING ENGINE
# ===============================
def monitor_engine():
    while True:
        for name, cfg in INFRA_DEVICES.items():
            is_up = tcp_ping(cfg["ip"], cfg["port"])
            current_mac = get_mac_address(ip=cfg["ip"]) or "UNKNOWN"

            # 1. Threat Detection: MAC Spoofing
            if is_up and current_mac != "UNKNOWN":
                if current_mac.upper() != cfg["mac"].upper():
                    msg = f"SPOOFING ALERT: {name} IP {cfg['ip']} has unauthorized MAC {current_mac}"
                    threat_alerts.append({"type": "MAC_SPOOFING", "device": name, "msg": msg, "time": datetime.now().isoformat()})
                    ledger.add_block("THREAT_DETECTED", {"type": "MAC_SPOOFING", "details": msg})

            # 2. Threat Detection: Connectivity Loss
            if not is_up and cfg["priority"] in ["high", "critical"]:
                msg = f"CRITICAL OFFLINE: {name} ({cfg['ip']}) is down."
                threat_alerts.append({"type": "CONN_LOSS", "device": name, "msg": msg, "time": datetime.now().isoformat()})
                ledger.add_block("DEVICE_ALERT", {"type": "CONN_LOSS", "details": msg})

            device_health[name] = {"status": is_up, "mac": current_mac, "ts": datetime.now().isoformat()}
        time.sleep(20)

threading.Thread(target=monitor_engine, daemon=True).start()

# ===============================
# 5. AUTHENTICATION ROUTES
# ===============================

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    print(f"\n--- AUTH ATTEMPT ---")
    
    if not data:
        return jsonify({"error": "No JSON received"}), 400

    username = data.get("username")
    password = data.get("password")
    ip = request.remote_addr

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM admins WHERE username = %s", (username,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if not row:
            print(f"FAILED: User '{username}' not found.")
            return jsonify({"error": "Access Denied"}), 401

        stored_hash = row[0]
        # Handle MySQL string/byte return types
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')

        # Bcrypt Check
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            print(f"SUCCESS: {username} authenticated.")
            
            fp = get_fingerprint()
            session["admin_user"] = username
            session["fingerprint"] = fp
            session["login_time"] = datetime.now().isoformat()
            
            active_admin_sessions[ip] = {"user": username, "login": session["login_time"]}
            
            log_event(username, ip, "SUCCESS", "LOGIN", "Successful admin login", fp)
            return jsonify({"message": "Access Granted"})
        else:
            print("FAILED: Password mismatch.")
            log_event(username, ip, "FAILED", "AUTH_FAILURE", "Invalid password")
            return jsonify({"error": "Access Denied"}), 401
            
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        return jsonify({"error": "Server connection error"}), 500

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    ip = request.remote_addr
    username = session.get("admin_user")
    start_time_str = session.get("login_time")
    
    if start_time_str:
        start_time = datetime.fromisoformat(start_time_str)
        duration = int((datetime.now() - start_time).total_seconds())
        
        # Update MySQL Log with duration
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE access_logs SET logout_time=%s, duration_seconds=%s 
                WHERE username=%s AND logout_time IS NULL ORDER BY login_time DESC LIMIT 1
            """, (datetime.now(), duration, username))
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Logout SQL update error: {e}")

        log_event(username, ip, "LOGOUT", "LOGOUT", f"Session ended. Duration: {duration}s")

    active_admin_sessions.pop(ip, None)
    session.clear()
    return jsonify({"message": "Logged out successfully"})

# ===============================
# 6. MONITORING DATA API
# ===============================

@app.route("/api/monitor", methods=["GET"])
@login_required
def api_monitor():
    # Session Hijack Protection: Check Fingerprint
    if session.get("fingerprint") != get_fingerprint():
        log_event(session.get("admin_user"), request.remote_addr, "THREAT", "SESSION_HIJACK", "Fingerprint changed mid-session!")
        session.clear()
        return jsonify({"error": "Security violation detected"}), 403

    valid, ledger_msg = ledger.verify_chain()
    
    return jsonify({
        "infrastructure": device_health,
        "threats": threat_alerts[-15:], # Last 15 threats
        "ledger_integrity": {"status": "SECURE" if valid else "CORRUPTED", "details": ledger_msg},
        "active_sessions": active_admin_sessions
    })

if __name__ == "__main__":
    # RUN ON PORT 5001 PER USER REQUEST
    app.run(host="0.0.0.0", port=5001, debug=True)