import random
import time
import json
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models import SecurityEvent, Alert
from app.detection import DetectionEngine
from app.database import SessionLocal

# Sample attacker profiles and user lists
ATTACKER_IPS = [
    "192.168.1.22",
    "192.168.1.105",
    "10.0.0.45",
    "45.33.32.156",
    "185.220.101.5",
    "198.51.100.42",
    "203.0.113.19"
]

BENIGN_IPS = [
    "192.168.1.10",
    "192.168.1.15",
    "192.168.1.50",
    "10.0.0.12",
    "10.0.0.18"
]

USERNAMES = ["admin", "root", "analyst", "jsmith", "mchen", "operator", "dbadmin", "devuser"]
PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]

class AttackSimulator:
    """Generates realistic attack scenarios and benign noise for SOC demonstrations."""

    def __init__(self, db: Session):
        self.db = db
        self.engine = DetectionEngine(db)

    def trigger_scenario(self, scenario: str, target_ip: Optional[str] = None, intensity: int = 1) -> Dict[str, Any]:
        scenario = scenario.lower()
        if scenario == "brute_force":
            return self._scenario_brute_force(target_ip, intensity)
        elif scenario == "port_scan":
            return self._scenario_port_scan(target_ip, intensity)
        elif scenario == "suspicious_login":
            return self._scenario_suspicious_login(target_ip, intensity)
        elif scenario == "flood":
            return self._scenario_event_flood(target_ip, intensity)
        elif scenario == "anomaly":
            return self._scenario_ml_anomaly(target_ip, intensity)
        elif scenario == "known_bad":
            return self._scenario_known_bad(target_ip, intensity)
        elif scenario == "benign":
            return self._scenario_benign(target_ip, intensity)
        else:
            raise ValueError(f"Unknown scenario: {scenario}")

    def _scenario_brute_force(self, ip: Optional[str], intensity: int) -> Dict[str, Any]:
        attacker_ip = ip or random.choice(["192.168.1.105", "45.33.32.156", "185.220.101.5"])
        target_user = random.choice(["admin", "root", "soc_manager"])
        attempts = 6 * max(1, intensity)
        
        events_created = 0
        alerts_triggered = 0

        for i in range(attempts):
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                event_type="LOGIN_FAILED",
                source_ip=attacker_ip,
                destination_ip="10.0.0.1",
                port=22 if i % 2 == 0 else 443,
                username=target_user if i % 3 != 0 else random.choice(USERNAMES),
                status="FAILURE",
                raw_log=f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} LOGIN_FAILED user={target_user} ip={attacker_ip} port=22 status=FAILURE",
                metadata_json=json.dumps({"service": "ssh_auth" if i % 2 == 0 else "web_portal", "attempt_number": i + 1})
            )
            self.db.add(event)
            self.db.commit()
            self.db.refresh(event)
            events_created += 1

            alerts = self.engine.evaluate_event(event)
            alerts_triggered += len(alerts)

        return {
            "status": "success",
            "scenario": "brute_force",
            "events_generated": events_created,
            "alerts_triggered": alerts_triggered,
            "message": f"Simulated {events_created} brute force login attempts from {attacker_ip}. Generated {alerts_triggered} alert(s)."
        }

    def _scenario_port_scan(self, ip: Optional[str], intensity: int) -> Dict[str, Any]:
        attacker_ip = ip or random.choice(["192.168.1.130", "198.51.100.42", "203.0.113.19"])
        scan_ports = random.sample(PORTS, min(len(PORTS), 12 * max(1, intensity)))
        
        events_created = 0
        alerts_triggered = 0

        for port in scan_ports:
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                event_type="PORT_SCAN",
                source_ip=attacker_ip,
                destination_ip="10.0.0.5",
                port=port,
                username=None,
                status="BLOCKED" if port not in [80, 443] else "SUCCESS",
                raw_log=f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} PORT_SCAN src={attacker_ip} dst=10.0.0.5 port={port} status=BLOCKED",
                metadata_json=json.dumps({"probe_type": "SYN_SCAN", "target_port": port})
            )
            self.db.add(event)
            self.db.commit()
            self.db.refresh(event)
            events_created += 1

            alerts = self.engine.evaluate_event(event)
            alerts_triggered += len(alerts)

        return {
            "status": "success",
            "scenario": "port_scan",
            "events_generated": events_created,
            "alerts_triggered": alerts_triggered,
            "message": f"Simulated port scan across {events_created} distinct ports from {attacker_ip}. Generated {alerts_triggered} alert(s)."
        }

    def _scenario_suspicious_login(self, ip: Optional[str], intensity: int) -> Dict[str, Any]:
        attacker_ip = ip or random.choice(["192.168.1.88", "10.0.0.45", "185.220.101.5"])
        compromised_user = random.choice(["mchen", "jsmith", "operator"])
        
        events_created = 0
        alerts_triggered = 0

        # Step 1: 4 failed logins
        for i in range(4):
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                event_type="LOGIN_FAILED",
                source_ip=attacker_ip,
                destination_ip="10.0.0.10",
                port=443,
                username=compromised_user,
                status="FAILURE",
                raw_log=f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} LOGIN_FAILED user={compromised_user} ip={attacker_ip} port=443 status=FAILURE",
                metadata_json=json.dumps({"reason": "invalid_password", "attempt": i + 1})
            )
            self.db.add(event)
            self.db.commit()
            self.db.refresh(event)
            events_created += 1

        # Step 2: 1 successful login immediately after
        success_event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_type="LOGIN_SUCCESS",
            source_ip=attacker_ip,
            destination_ip="10.0.0.10",
            port=443,
            username=compromised_user,
            status="SUCCESS",
            raw_log=f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} LOGIN_SUCCESS user={compromised_user} ip={attacker_ip} port=443 status=SUCCESS",
            metadata_json=json.dumps({"auth_method": "password_bypass", "user_agent": "Mozilla/5.0 (Kali Linux)"})
        )
        self.db.add(success_event)
        self.db.commit()
        self.db.refresh(success_event)
        events_created += 1

        alerts = self.engine.evaluate_event(success_event)
        alerts_triggered += len(alerts)

        return {
            "status": "success",
            "scenario": "suspicious_login",
            "events_generated": events_created,
            "alerts_triggered": alerts_triggered,
            "message": f"Simulated credential stuffing (4 fails + 1 success) for user '{compromised_user}' from {attacker_ip}. Generated {alerts_triggered} alert(s)."
        }

    def _scenario_event_flood(self, ip: Optional[str], intensity: int) -> Dict[str, Any]:
        attacker_ip = ip or "10.0.0.99"
        total_burst = 105 * max(1, intensity)
        
        events_created = 0
        alerts_triggered = 0

        for i in range(total_burst):
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                event_type="NETWORK_CONNECTION",
                source_ip=attacker_ip,
                destination_ip="10.0.0.1",
                port=80,
                username=None,
                status="SUCCESS",
                raw_log=f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} NETWORK_CONNECTION src={attacker_ip} dst=10.0.0.1 port=80 status=SUCCESS",
                metadata_json=json.dumps({"endpoint": "/api/v1/search", "burst_id": i})
            )
            self.db.add(event)
            events_created += 1

        self.db.commit()
        self.db.refresh(event)

        alerts = self.engine.evaluate_event(event)
        alerts_triggered += len(alerts)

        return {
            "status": "success",
            "scenario": "flood",
            "events_generated": events_created,
            "alerts_triggered": alerts_triggered,
            "message": f"Simulated flood of {events_created} requests from {attacker_ip}. Generated {alerts_triggered} alert(s)."
        }

    def _scenario_ml_anomaly(self, ip: Optional[str], intensity: int) -> Dict[str, Any]:
        attacker_ip = ip or "194.26.29.112"
        events_created = 0
        alerts_triggered = 0

        # Create unusual combination of high failed rate across multi-port targets
        for i in range(12 * max(1, intensity)):
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                event_type="UNAUTHORIZED_ACCESS",
                source_ip=attacker_ip,
                destination_ip="10.0.0.5",
                port=random.choice([8080, 8443, 9000, 9200, 27017, 6379]),
                username=random.choice(["admin", "oracle", "postgres", "guest"]),
                status="FAILURE",
                raw_log=f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UNAUTHORIZED_ACCESS src={attacker_ip} dst=10.0.0.5 status=FAILURE",
                metadata_json=json.dumps({"anomaly_indicator": "unusual_service_probe", "payload_entropy": 7.8})
            )
            self.db.add(event)
            self.db.commit()
            self.db.refresh(event)
            events_created += 1

            alerts = self.engine.evaluate_event(event)
            alerts_triggered += len(alerts)

        return {
            "status": "success",
            "scenario": "anomaly",
            "events_generated": events_created,
            "alerts_triggered": alerts_triggered,
            "message": f"Simulated ML statistical anomaly burst of {events_created} events from {attacker_ip}. Triggered {alerts_triggered} alert(s)."
        }

    def _scenario_known_bad(self, ip: Optional[str], intensity: int) -> Dict[str, Any]:
        attacker_ip = ip or "185.220.101.5"
        events_created = 0
        alerts_triggered = 0

        for i in range(3 * max(1, intensity)):
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                event_type="NETWORK_CONNECTION",
                source_ip=attacker_ip,
                destination_ip="10.0.0.2",
                port=443,
                username="root",
                status="ATTEMPT",
                raw_log=f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} NETWORK_CONNECTION src={attacker_ip} dst=10.0.0.2 port=443 status=ATTEMPT",
                metadata_json=json.dumps({"c2_probe": True, "feed_match": "Tor Exit Node Network"})
            )
            self.db.add(event)
            self.db.commit()
            self.db.refresh(event)
            events_created += 1

            alerts = self.engine.evaluate_event(event)
            alerts_triggered += len(alerts)

        return {
            "status": "success",
            "scenario": "known_bad",
            "events_generated": events_created,
            "alerts_triggered": alerts_triggered,
            "message": f"Simulated connection attempt from Known Threat Feed IP {attacker_ip}. Triggered {alerts_triggered} alert(s)."
        }

    def _scenario_benign(self, ip: Optional[str], intensity: int) -> Dict[str, Any]:
        user_ip = ip or random.choice(BENIGN_IPS)
        user = random.choice(USERNAMES)
        
        events_created = 0
        for _ in range(5 * max(1, intensity)):
            event_type = random.choice(["LOGIN_SUCCESS", "FILE_ACCESS", "NETWORK_CONNECTION"])
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                event_type=event_type,
                source_ip=user_ip,
                destination_ip="10.0.0.1",
                port=random.choice([80, 443, 22]),
                username=user,
                status="SUCCESS",
                raw_log=f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} {event_type} user={user} ip={user_ip} status=SUCCESS",
                metadata_json=json.dumps({"action": "normal_workstation_activity"})
            )
            self.db.add(event)
            events_created += 1
            
        self.db.commit()

        return {
            "status": "success",
            "scenario": "benign",
            "events_generated": events_created,
            "alerts_triggered": 0,
            "message": f"Emitted {events_created} normal operational log events from {user_ip}."
        }


# Global background simulation stream state
live_stream_active = False

async def background_simulation_loop():
    """Continuously generates random realistic background security events when live stream is active."""
    global live_stream_active
    while True:
        if live_stream_active:
            try:
                db = SessionLocal()
                sim = AttackSimulator(db)
                
                rand_val = random.random()
                if rand_val < 0.65:
                    sim._scenario_benign(None, 1)
                elif rand_val < 0.76:
                    sim._scenario_brute_force(None, 1)
                elif rand_val < 0.86:
                    sim._scenario_port_scan(None, 1)
                elif rand_val < 0.94:
                    sim._scenario_ml_anomaly(None, 1)
                else:
                    sim._scenario_known_bad(None, 1)
                
                db.close()
            except Exception as e:
                print(f"[Simulator] Error in background stream: {e}")
        await asyncio.sleep(4)
