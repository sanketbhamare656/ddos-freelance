# app.py - UPDATED with persistent storage fix

from flask import Flask, render_template, request, jsonify
import json
import os
from datetime import datetime
import pandas as pd
import numpy as np

app = Flask(__name__)
app.secret_key = "ddos_detection_secret_key_2024"

# Better file path handling for Vercel
def get_history_path():
    """Get proper history file path for different environments"""
    # For Vercel, use /tmp
    # For local, use current directory
    if os.environ.get('VERCEL') or os.environ.get('RENDER'):
        return '/tmp/ddos_history.json'
    else:
        return os.path.join(os.path.dirname(__file__), 'ddos_history.json')

HISTORY_FILE = get_history_path()

# Rule-based DDoS Detection Algorithm
class DDoSDetector:
    def __init__(self):
        self.rules = {
            'packet_rate': {
                'normal_max': 500,
                'warning_min': 500,
                'attack_min': 1000,
                'critical_min': 5000
            },
            'byte_rate': {
                'normal_max': 1000,
                'warning_min': 1000,
                'attack_min': 5000,
                'critical_min': 10000
            },
            'connection_count': {
                'normal_max': 50,
                'warning_min': 50,
                'attack_min': 100,
                'critical_min': 300
            }
        }
        
    def analyze_traffic(self, packet_rate, byte_rate, connection_count, syn_flag, ack_flag):
        score = 0
        reasons = []
        severity = "Normal"
        
        # Rule 1: Packet Rate Analysis
        if packet_rate > self.rules['packet_rate']['critical_min']:
            score += 40
            reasons.append(f"Extremely high packet rate: {packet_rate} packets/sec")
            severity = "Critical"
        elif packet_rate > self.rules['packet_rate']['attack_min']:
            score += 25
            reasons.append(f"High packet rate: {packet_rate} packets/sec")
            if severity != "Critical":
                severity = "Attack"
        elif packet_rate > self.rules['packet_rate']['warning_min']:
            score += 10
            reasons.append(f"Elevated packet rate: {packet_rate} packets/sec")
        
        # Rule 2: Byte Rate Analysis
        if byte_rate > self.rules['byte_rate']['critical_min']:
            score += 35
            reasons.append(f"Extremely high byte rate: {byte_rate} bytes/sec")
            severity = "Critical"
        elif byte_rate > self.rules['byte_rate']['attack_min']:
            score += 20
            reasons.append(f"High byte rate: {byte_rate} bytes/sec")
            if severity != "Critical":
                severity = "Attack"
        elif byte_rate > self.rules['byte_rate']['warning_min']:
            score += 8
            reasons.append(f"Elevated byte rate: {byte_rate} bytes/sec")
        
        # Rule 3: Connection Count Analysis
        if connection_count > self.rules['connection_count']['critical_min']:
            score += 35
            reasons.append(f"Extremely high connection count: {connection_count}")
            severity = "Critical"
        elif connection_count > self.rules['connection_count']['attack_min']:
            score += 20
            reasons.append(f"High connection count: {connection_count}")
            if severity != "Critical":
                severity = "Attack"
        elif connection_count > self.rules['connection_count']['warning_min']:
            score += 8
            reasons.append(f"Elevated connection count: {connection_count}")
        
        # Rule 4: SYN Flag Analysis
        if syn_flag == 1 and ack_flag == 0:
            if packet_rate > 1000 or connection_count > 200:
                score += 20
                reasons.append("SYN flood pattern detected (SYN=1, ACK=0 with high traffic)")
        
        # Rule 5: ACK Flag Analysis
        if ack_flag == 0 and packet_rate > 800:
            score += 10
            reasons.append("Missing ACK flags in high traffic - possible attack")
        
        # Rule 6: Traffic Ratio Analysis
        if packet_rate > 0 and byte_rate / packet_rate < 2:
            if packet_rate > 500:
                score += 15
                reasons.append("Small packet flood detected (DoS attack pattern)")
        
        is_attack = score >= 50
        confidence = min(score, 100)
        
        if not is_attack and score >= 30:
            severity = "Warning"
        elif not is_attack:
            severity = "Normal"
        
        return {
            'is_attack': is_attack,
            'severity': severity,
            'reasons': reasons,
            'confidence': confidence,
            'score': score
        }
    
    def get_recommendations(self, analysis):
        recommendations = []
        
        if analysis['severity'] == 'Critical':
            recommendations.extend([
                "🚨 IMMEDIATE ACTION REQUIRED",
                "• Block suspicious IP addresses immediately",
                "• Enable rate limiting on all incoming traffic",
                "• Activate DDoS mitigation service",
                "• Contact your ISP for upstream filtering"
            ])
        elif analysis['severity'] == 'Attack':
            recommendations.extend([
                "⚠️ Attack Detected - Take Action",
                "• Implement rate limiting for affected services",
                "• Add SYN cookies to prevent SYN flood",
                "• Increase connection tracking limits",
                "• Monitor traffic patterns continuously"
            ])
        elif analysis['severity'] == 'Warning':
            recommendations.extend([
                "⚡ Elevated Traffic - Preventive Measures",
                "• Monitor traffic closely for next 30 minutes",
                "• Review firewall rules and access controls",
                "• Ensure rate limiting is properly configured"
            ])
        else:
            recommendations.extend([
                "✅ Traffic Normal - Best Practices",
                "• Maintain regular monitoring",
                "• Keep firewall rules updated",
                "• Conduct periodic security audits"
            ])
        
        return recommendations

# Load history with error handling
def load_history():
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"✅ Loaded {len(data)} history records")  # Debug log
                return data
        else:
            print(f"📁 History file not found, creating new one at {HISTORY_FILE}")
            return []
    except Exception as e:
        print(f"❌ Error loading history: {e}")
        return []

# Save history with error handling
def save_history(history):
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
        
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
        print(f"💾 Saved {len(history)} history records")  # Debug log
        return True
    except Exception as e:
        print(f"❌ Error saving history: {e}")
        return False

detector = DDoSDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect')
def detect_page():
    return render_template('detect.html')

@app.route('/api/detect', methods=['POST'])
def detect():
    try:
        data = request.json
        packet_rate = float(data.get('packet_rate', 0))
        byte_rate = float(data.get('byte_rate', 0))
        connection_count = float(data.get('connection_count', 0))
        syn_flag = int(data.get('syn_flag', 0))
        ack_flag = int(data.get('ack_flag', 0))
        
        # Analyze traffic
        analysis = detector.analyze_traffic(
            packet_rate, byte_rate, connection_count, 
            syn_flag, ack_flag
        )
        
        recommendations = detector.get_recommendations(analysis)
        
        # Save to history
        history = load_history()
        
        history_entry = {
            'id': len(history) + 1,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'connection_count': connection_count,
            'syn_flag': syn_flag,
            'ack_flag': ack_flag,
            'is_attack': analysis['is_attack'],
            'severity': analysis['severity'],
            'confidence': analysis['confidence'],
            'reasons': analysis['reasons'][:3]
        }
        
        history.insert(0, history_entry)
        history = history[:100]  # Keep last 100 records
        save_history(history)
        
        return jsonify({
            'success': True,
            'analysis': analysis,
            'recommendations': recommendations
        })
        
    except Exception as e:
        print(f"❌ Detection error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/history')
def get_history():
    history = load_history()
    print(f"📜 Returning {len(history)} history entries")  # Debug log
    return jsonify({'history': history, 'count': len(history)})

@app.route('/api/clear_history', methods=['POST'])
def clear_history():
    save_history([])
    return jsonify({'success': True, 'message': 'History cleared'})

@app.route('/api/stats')
def get_stats():
    history = load_history()
    total = len(history)
    attacks = sum(1 for h in history if h['is_attack'])
    warnings = sum(1 for h in history if h['severity'] == 'Warning')
    normal = total - attacks - warnings
    
    return jsonify({
        'total_detections': total,
        'attacks_detected': attacks,
        'warnings': warnings,
        'normal_traffic': normal
    })

@app.route('/history')
def history_page():
    return render_template('history.html')

@app.route('/about')
def about_page():
    return render_template('about.html')

if __name__ == '__main__':
    print(f"🚀 Starting DDoS Detection System")
    print(f"📁 History file path: {HISTORY_FILE}")
    app.run(debug=True, host='0.0.0.0', port=5000)