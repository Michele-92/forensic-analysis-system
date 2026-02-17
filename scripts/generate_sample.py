#!/usr/bin/env python3
"""
Generiert Test-Sample-Daten für die Pipeline.
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
import random

OUTPUT_DIR = Path("data/samples")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def generate_timeline(num_events: int = 100) -> list:
    """Generiert Test-Timeline mit normalen und verdächtigen Events."""
    timeline = []
    base_time = datetime.now() - timedelta(days=1)
    
    normal_events = [
        "User logged in via SSH",
        "File opened: /home/user/document.txt",
        "Process started: firefox",
        "Network connection to google.com",
    ]
    
    suspicious_events = [
        "Root SSH login from 192.168.1.100",
        "Cron job modified: /tmp/.hidden",
        "File accessed: /etc/shadow",
        "Large download from 10.0.0.50",
        "Base64 encoded command executed",
    ]
    
    for i in range(num_events):
        timestamp = base_time + timedelta(minutes=i*5)
        
        # 10% verdächtige Events
        if random.random() < 0.1:
            desc = random.choice(suspicious_events)
            is_suspicious = True
        else:
            desc = random.choice(normal_events)
            is_suspicious = False
        
        event = {
            "event_id": f"evt_{i:04d}",
            "timestamp": timestamp.isoformat(),
            "event_type": "file_system",
            "source": "tsk",
            "description": desc,
            "metadata": {
                "size": random.randint(1000, 10000000),
                "is_suspicious": is_suspicious
            }
        }
        
        timeline.append(event)
    
    return timeline


def generate_ground_truth(timeline: list) -> list:
    """Generiert Ground-Truth-Labels für Evaluation."""
    ground_truth = []
    
    for event in timeline:
        gt = {
            "event_id": event["event_id"],
            "is_anomaly": event["metadata"]["is_suspicious"],
            "true_risk": 0.9 if event["metadata"]["is_suspicious"] else 0.1
        }
        ground_truth.append(gt)
    
    return ground_truth


if __name__ == "__main__":
    print("🔧 Generiere Test-Samples...")
    
    # Generiere Timeline
    timeline = generate_timeline(200)
    with open(OUTPUT_DIR / "sample_timeline.json", "w") as f:
        json.dump(timeline, f, indent=2)
    print(f"✅ Timeline: {OUTPUT_DIR / 'sample_timeline.json'}")
    
    # Generiere Ground Truth
    ground_truth = generate_ground_truth(timeline)
    with open(OUTPUT_DIR / "sample_ground_truth.json", "w") as f:
        json.dump(ground_truth, f, indent=2)
    print(f"✅ Ground Truth: {OUTPUT_DIR / 'sample_ground_truth.json'}")
    
    print("\n📊 Statistik:")
    suspicious = sum(1 for e in timeline if e["metadata"]["is_suspicious"])
    print(f"  Total Events: {len(timeline)}")
    print(f"  Suspicious: {suspicious} ({suspicious/len(timeline)*100:.1f}%)")