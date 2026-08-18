import json
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from app.models import SecurityEvent, Alert, DetectionRule
from app.schemas import AlertCreate

class DetectionEngine:
    """
    Threat Detection Engine for SentinelX SOC.
    Evaluates incoming events against active detection rules.
    """

    def __init__(self, db: Session):
        self.db = db

    def evaluate_event(self, event: SecurityEvent) -> List[Alert]:
        """
        Evaluate a single newly ingested event against all active rules.
        Returns a list of created or updated Alert instances.
        """
        rules = self.db.query(DetectionRule).filter(DetectionRule.is_enabled == True).all()
        rule_map = {r.code: r for r in rules}
        
        triggered_alerts = []

        # 1. Evaluate Brute Force Rule
        if "RULE_BRUTE_FORCE" in rule_map and (
            event.event_type in ["LOGIN_FAILED", "AUTH_FAILURE", "SSH_FAILED"] or
            (event.status == "FAILURE" and "LOGIN" in event.event_type)
        ):
            alert = self._check_brute_force(event, rule_map["RULE_BRUTE_FORCE"])
            if alert:
                triggered_alerts.append(alert)

        # 2. Evaluate Port Scan Rule
        if "RULE_PORT_SCAN" in rule_map:
            alert = self._check_port_scan(event, rule_map["RULE_PORT_SCAN"])
            if alert:
                triggered_alerts.append(alert)

        # 3. Evaluate Suspicious Login Sequence (Failed attempts followed by Success)
        if "RULE_SUSPICIOUS_LOGIN" in rule_map and (
            event.event_type in ["LOGIN_SUCCESS", "AUTH_SUCCESS"] or
            (event.status == "SUCCESS" and "LOGIN" in event.event_type)
        ):
            alert = self._check_suspicious_login(event, rule_map["RULE_SUSPICIOUS_LOGIN"])
            if alert:
                triggered_alerts.append(alert)

        # 4. Evaluate Event Flood Rule
        if "RULE_EVENT_FLOOD" in rule_map:
            alert = self._check_event_flood(event, rule_map["RULE_EVENT_FLOOD"])
            if alert:
                triggered_alerts.append(alert)

        return triggered_alerts

    def _check_brute_force(self, event: SecurityEvent, rule: DetectionRule) -> Optional[Alert]:
        window_start = (event.timestamp or datetime.utcnow()) - timedelta(minutes=rule.window_minutes)
        
        # Count failed login events for this IP in the window
        fail_count = self.db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.timestamp >= window_start,
            (
                (SecurityEvent.event_type.in_(["LOGIN_FAILED", "AUTH_FAILURE", "SSH_FAILED"])) |
                (SecurityEvent.status == "FAILURE")
            )
        ).scalar() or 0

        if fail_count >= rule.threshold:
            severity = "CRITICAL" if fail_count >= (rule.threshold * 3) else rule.severity
            desc = (
                f"Brute Force attack detected from {event.source_ip}: "
                f"{fail_count} failed login attempts recorded within {rule.window_minutes} minutes. "
                f"Targeted user: {event.username or 'unknown'}."
            )
            return self._create_or_deduplicate_alert(
                alert_type="BRUTE_FORCE",
                source_ip=event.source_ip,
                severity=severity,
                description=desc,
                rule=rule.code,
                details={
                    "failed_count": fail_count,
                    "threshold": rule.threshold,
                    "window_minutes": rule.window_minutes,
                    "target_user": event.username,
                    "target_port": event.port
                }
            )
        return None

    def _check_port_scan(self, event: SecurityEvent, rule: DetectionRule) -> Optional[Alert]:
        window_start = (event.timestamp or datetime.utcnow()) - timedelta(minutes=rule.window_minutes)
        
        # Count distinct destination ports accessed by this IP in the window
        distinct_ports = self.db.query(func.count(distinct(SecurityEvent.port))).filter(
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.port.isnot(None)
        ).scalar() or 0

        # Also check if event type itself is explicitly PORT_SCAN
        is_port_scan_event = (event.event_type == "PORT_SCAN")

        if distinct_ports >= rule.threshold or is_port_scan_event:
            severity = rule.severity
            desc = (
                f"Potential Port Scanning detected from {event.source_ip}: "
                f"Probed {distinct_ports} distinct ports within {rule.window_minutes} minute(s)."
            )
            return self._create_or_deduplicate_alert(
                alert_type="PORT_SCAN",
                source_ip=event.source_ip,
                severity=severity,
                description=desc,
                rule=rule.code,
                details={
                    "distinct_ports_count": distinct_ports,
                    "threshold": rule.threshold,
                    "window_minutes": rule.window_minutes,
                    "last_scanned_port": event.port
                }
            )
        return None

    def _check_suspicious_login(self, event: SecurityEvent, rule: DetectionRule) -> Optional[Alert]:
        window_start = (event.timestamp or datetime.utcnow()) - timedelta(minutes=rule.window_minutes)
        
        # Count failed logins prior to this successful login
        prior_fails = self.db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.timestamp < event.timestamp,
            (
                (SecurityEvent.event_type.in_(["LOGIN_FAILED", "AUTH_FAILURE"])) |
                (SecurityEvent.status == "FAILURE")
            )
        ).scalar() or 0

        if prior_fails >= rule.threshold:
            desc = (
                f"Suspicious Login Sequence detected from {event.source_ip}: "
                f"Successful login for user '{event.username or 'unknown'}' immediately following {prior_fails} failed login attempts."
            )
            return self._create_or_deduplicate_alert(
                alert_type="SUSPICIOUS_LOGIN",
                source_ip=event.source_ip,
                severity=rule.severity,
                description=desc,
                rule=rule.code,
                details={
                    "prior_failed_attempts": prior_fails,
                    "successful_user": event.username,
                    "window_minutes": rule.window_minutes
                }
            )
        return None

    def _check_event_flood(self, event: SecurityEvent, rule: DetectionRule) -> Optional[Alert]:
        window_start = (event.timestamp or datetime.utcnow()) - timedelta(minutes=rule.window_minutes)
        
        event_count = self.db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.timestamp >= window_start
        ).scalar() or 0

        if event_count >= rule.threshold:
            severity = "HIGH" if event_count >= (rule.threshold * 2) else rule.severity
            desc = (
                f"High-frequency Event Flood detected from {event.source_ip}: "
                f"{event_count} events generated within {rule.window_minutes} minute(s)."
            )
            return self._create_or_deduplicate_alert(
                alert_type="EVENT_FLOOD",
                source_ip=event.source_ip,
                severity=severity,
                description=desc,
                rule=rule.code,
                details={
                    "event_count": event_count,
                    "threshold": rule.threshold,
                    "window_minutes": rule.window_minutes
                }
            )
        return None

    def _create_or_deduplicate_alert(
        self,
        alert_type: str,
        source_ip: str,
        severity: str,
        description: str,
        rule: str,
        details: dict
    ) -> Alert:
        # Check if an existing open alert for this IP and rule exists within last 2 minutes
        recent_window = datetime.utcnow() - timedelta(minutes=2)
        existing_alert = self.db.query(Alert).filter(
            Alert.source_ip == source_ip,
            Alert.alert_type == alert_type,
            Alert.status.in_(["Open", "Investigating"]),
            Alert.updated_at >= recent_window
        ).first()

        if existing_alert:
            existing_alert.description = description
            existing_alert.severity = severity
            existing_alert.details_json = json.dumps(details)
            existing_alert.updated_at = datetime.utcnow()
            self.db.commit()
            self.db.refresh(existing_alert)
            return existing_alert

        # Create new alert
        new_alert = Alert(
            timestamp=datetime.utcnow(),
            alert_type=alert_type,
            source_ip=source_ip,
            severity=severity,
            description=description,
            rule=rule,
            status="Open",
            details_json=json.dumps(details),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        self.db.add(new_alert)
        self.db.commit()
        self.db.refresh(new_alert)
        return new_alert
