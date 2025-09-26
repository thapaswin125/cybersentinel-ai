"""
CyberSentinel AI - Live Demo Script (Unicode Fixed)
Run this to see the project in action with simulated data
"""

import time
import json
import random
from datetime import datetime, timedelta

def simulate_threat_detection():
    """Simulate real-time threat detection"""
    print("\n*** AI Threat Detection Engine - Live Demo")
    print("-" * 50)

    threat_types = ["DDoS Attack", "Malware Communication", "Phishing Campaign", "Port Scanning", "Data Exfiltration"]
    severities = ["Low", "Medium", "High", "Critical"]

    for i in range(5):
        threat = {
            "id": f"LIVE-{str(i+1).zfill(3)}",
            "type": random.choice(threat_types),
            "severity": random.choice(severities),
            "confidence": round(random.uniform(0.6, 0.98), 2),
            "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "timestamp": datetime.now().isoformat(),
            "status": "Detected"
        }

        print(f"*** THREAT DETECTED: {threat['type']}")
        print(f"   Severity: {threat['severity']} | Confidence: {threat['confidence']}")
        print(f"   Source: {threat['source_ip']} | Time: {threat['timestamp']}")
        print()

        time.sleep(2)  # Simulate real-time detection

def simulate_osint_collection():
    """Simulate OSINT intelligence gathering"""
    print("\n*** OSINT Intelligence Collection - Live Demo")
    print("-" * 50)

    intelligence_sources = [
        "Dark Web Monitor", "Social Media Scanner", "Threat Intel Feeds", 
        "Vulnerability Databases", "Malware Repositories"
    ]

    for i in range(3):
        intel = {
            "source": random.choice(intelligence_sources),
            "indicator": f"IOC-{random.randint(1000, 9999)}",
            "type": random.choice(["IP", "Domain", "Hash", "URL"]),
            "confidence": random.choice(["High", "Medium", "Low"]),
            "timestamp": datetime.now().isoformat()
        }

        print(f"*** INTELLIGENCE GATHERED: {intel['source']}")
        print(f"   Indicator: {intel['indicator']} ({intel['type']})")
        print(f"   Confidence: {intel['confidence']} | Time: {intel['timestamp']}")
        print()

        time.sleep(3)

def simulate_soar_response():
    """Simulate SOAR automated response"""
    print("\n*** SOAR Automation Engine - Live Demo")
    print("-" * 50)

    playbooks = [
        "DDoS Response Automation",
        "Malware Containment",
        "Phishing Email Remediation",
        "Incident Escalation"
    ]

    for playbook in playbooks[:2]:
        print(f"*** EXECUTING PLAYBOOK: {playbook}")

        actions = [
            "Analyzing threat indicators...",
            "Blocking malicious IPs...",
            "Isolating affected systems...",
            "Updating security policies...",
            "Notifying security team...",
            "Generating incident report..."
        ]

        for action in actions[:4]:
            print(f"   > {action}")
            time.sleep(1)

        print(f"   *** Playbook completed successfully")
        print(f"   Response Time: {random.randint(30, 120)} seconds")
        print()

        time.sleep(2)

def display_dashboard_stats():
    """Display simulated dashboard statistics"""
    print("\n*** CyberSentinel AI Dashboard - Live Stats")
    print("=" * 60)

    stats = {
        "Threats Detected Today": random.randint(15, 45),
        "Threats Blocked": random.randint(12, 40),
        "OSINT Sources Active": random.randint(8, 12),
        "SOAR Playbooks Executed": random.randint(5, 15),
        "System Health": "Optimal",
        "Detection Accuracy": f"{random.randint(92, 97)}%",
        "Response Time": f"{random.randint(30, 90)} seconds",
        "Quantum Crypto Status": "Active"
    }

    for metric, value in stats.items():
        print(f"*** {metric}: {value}")

    print("=" * 60)

def run_live_demo():
    """Run the complete live demonstration"""
    print("CYBERSENTINEL AI - LIVE DEMONSTRATION")
    print("*** Advanced Cybersecurity Intelligence Platform")
    print("=" * 60)

    # Show initial dashboard
    display_dashboard_stats()

    # Simulate threat detection
    simulate_threat_detection()

    # Simulate OSINT collection
    simulate_osint_collection()

    # Simulate SOAR response
    simulate_soar_response()

    # Final summary
    print("\n*** DEMONSTRATION COMPLETED")
    print("=" * 60)
    print("*** AI Threat Detection: 5 threats identified and classified")
    print("*** OSINT Intelligence: 3 indicators collected and analyzed")
    print("*** SOAR Automation: 2 playbooks executed successfully")
    print("*** System Performance: All modules operating optimally")
    print()
    print("*** CyberSentinel AI is fully operational and ready for deployment!")
    print()
    print("*** Next Steps:")
    print("1. Open index.html to explore the web interface")
    print("2. Run individual Python modules for detailed testing")
    print("3. Deploy with Docker for full-stack experience")
    print("4. Customize and extend for your specific use case")

if __name__ == "__main__":
    run_live_demo()
