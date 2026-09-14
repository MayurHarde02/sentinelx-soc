import json
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from app.models import SecurityEvent, Alert, DetectionRule
from app.anomaly_detector import anomaly_detector
from app.threat_intel import threat_intel_service
from app.websocket_manager import ws_manager

class DetectionEngine:
    """
    Advanced Threat Detection Engine for SentinelX SOC.
    Combines rule-based heuristics, dynamic custom rules, threat feed blocklists, and ML anomaly detection.
    """

    def __init__(self, db: Session):
        self.db = db

    def evaluate_event(self, event: SecurityEvent) -> List[Alert]:
        """
        Evaluate a single newly ingested event against all active heuristic rules,
        threat blocklists, custom rules, and machine learning anomaly detection.
        """
        rules = self.db.query(DetectionRule).filter(DetectionRule.is_enabled == True).all()
        rule_map = {r.code: r for r in rules}
        
        triggered_alerts = []

        # 0. Check Known Bad IP / Threat Feed Blocklist
        blocklist_item = threat_intel_service.check_threat_blocklist(self.db, event.source_ip)
        if blocklist_item:
            alert = self._check_known_malicious_ip(event, blocklist_item)
            if alert:
                triggered_alerts.append(alert)

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

        # 5. Evaluate Machine Learning Isolation Forest Anomaly Detector
        is_anomaly, decision_score, ml_details = anomaly_detector.evaluate_traffic_anomaly(self.db, event.source_ip)
        if is_anomaly:
            alert = self._check_ml_anomaly(event, decision_score, ml_details)
            if alert:
                triggered_alerts.append(alert)

        # 6. Evaluate Custom User-Defined Rules
        for r in rules:
            if r.is_custom:
                alert = self._check_custom_rule(event, r)
                if alert:
                    triggered_alerts.append(alert)

        return triggered_alerts

    def _check_known_malicious_ip(self, event: SecurityEvent, feed_item) -> Optional[Alert]:
        desc = (
            f"Traffic observed from Known Malicious Threat Feed IP {event.source_ip}. "
            f"Feed: '{feed_item.feed_name}' | Category: {feed_item.threat_category}. {feed_item.description or ''}"
        )
        return self._create_or_deduplicate_alert(
            alert_type="KNOWN_MALICIOUS_IP",
            source_ip=event.source_ip,
            severity=feed_item.severity or "CRITICAL",
            description=desc,
            rule="RULE_KNOWN_MALICIOUS_IP",
            mitre_tactic="Command and Control",
            mitre_technique_id="T1071",
            mitre_technique_name="Application Layer Protocol",
            details={
                "feed_name": feed_item.feed_name,
                "threat_category": feed_item.threat_category,
                "matched_ip": event.source_ip
            }
        )

    def _check_brute_force(self, event: SecurityEvent, rule: DetectionRule) -> Optional[Alert]:
        window_start = (event.timestamp or datetime.utcnow()) - timedelta(minutes=rule.window_minutes)
        
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
                mitre_tactic=rule.mitre_tactic or "Credential Access",
                mitre_technique_id=rule.mitre_technique_id or "T1110",
                mitre_technique_name=rule.mitre_technique_name or "Brute Force",
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
        
        distinct_ports = self.db.query(func.count(distinct(SecurityEvent.port))).filter(
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.port.isnot(None)
        ).scalar() or 0

        is_port_scan_event = (event.event_type == "PORT_SCAN")

        if distinct_ports >= rule.threshold or is_port_scan_event:
            desc = (
                f"Potential Port Scanning detected from {event.source_ip}: "
                f"Probed {distinct_ports} distinct ports within {rule.window_minutes} minute(s)."
            )
            return self._create_or_deduplicate_alert(
                alert_type="PORT_SCAN",
                source_ip=event.source_ip,
                severity=rule.severity,
                description=desc,
                rule=rule.code,
                mitre_tactic=rule.mitre_tactic or "Reconnaissance",
                mitre_technique_id=rule.mitre_technique_id or "T1046",
                mitre_technique_name=rule.mitre_technique_name or "Network Service Discovery",
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
                mitre_tactic=rule.mitre_tactic or "Initial Access",
                mitre_technique_id=rule.mitre_technique_id or "T1078",
                mitre_technique_name=rule.mitre_technique_name or "Valid Accounts",
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
                mitre_tactic=rule.mitre_tactic or "Impact",
                mitre_technique_id=rule.mitre_technique_id or "T1498",
                mitre_technique_name=rule.mitre_technique_name or "Network Denial of Service",
                details={
                    "event_count": event_count,
                    "threshold": rule.threshold,
                    "window_minutes": rule.window_minutes
                }
            )
        return None

    def _check_ml_anomaly(self, event: SecurityEvent, decision_score: float, ml_details: dict) -> Optional[Alert]:
        desc = (
            f"Machine Learning Anomaly Detected from {event.source_ip}: "
            f"Isolation Forest identified statistical velocity deviation (Confidence: {ml_details.get('anomaly_confidence_pct', 85)}%, "
            f"Score: {ml_details.get('ml_decision_score', 0)})."
        )
        return self._create_or_deduplicate_alert(
            alert_type="ANOMALY_DETECTION",
            source_ip=event.source_ip,
            severity="MEDIUM" if ml_details.get("anomaly_confidence_pct", 0) < 80 else "HIGH",
            description=desc,
            rule="RULE_ML_ANOMALY",
            mitre_tactic="Execution",
            mitre_technique_id="T1059",
            mitre_technique_name="Command and Scripting Interpreter",
            details=ml_details
        )

    def _check_custom_rule(self, event: SecurityEvent, rule: DetectionRule) -> Optional[Alert]:
        """Evaluates dynamic user-defined custom detection rules."""
        window_start = (event.timestamp or datetime.utcnow()) - timedelta(minutes=rule.window_minutes)
        query = self.db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.timestamp >= window_start
        )

        if rule.event_type_filter:
            query = query.filter(SecurityEvent.event_type == rule.event_type_filter.upper())
        if rule.status_filter:
            query = query.filter(SecurityEvent.status == rule.status_filter.upper())

        matched_count = query.scalar() or 0

        if matched_count >= rule.threshold:
            desc = f"Custom Rule '{rule.name}' triggered: {matched_count} matching events recorded for IP {event.source_ip}."
            return self._create_or_deduplicate_alert(
                alert_type="CUSTOM_DETECTION",
                source_ip=event.source_ip,
                severity=rule.severity,
                description=desc,
                rule=rule.code,
                mitre_tactic=rule.mitre_tactic or "Defense Evasion",
                mitre_technique_id=rule.mitre_technique_id or "T1078",
                mitre_technique_name=rule.mitre_technique_name or "Custom Heuristic",
                details={"matched_count": matched_count, "rule_name": rule.name}
            )
        return None

    def _create_or_deduplicate_alert(
        self,
        alert_type: str,
        source_ip: str,
        severity: str,
        description: str,
        rule: str,
        mitre_tactic: str,
        mitre_technique_id: str,
        mitre_technique_name: str,
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
            existing_alert.mitre_tactic = mitre_tactic
            existing_alert.mitre_technique_id = mitre_technique_id
            existing_alert.mitre_technique_name = mitre_technique_name
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
            mitre_tactic=mitre_tactic,
            mitre_technique_id=mitre_technique_id,
            mitre_technique_name=mitre_technique_name,
            details_json=json.dumps(details),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        self.db.add(new_alert)
        self.db.commit()
        self.db.refresh(new_alert)

        # Broadcast real-time alert event over WebSockets
        ws_manager.broadcast_sync("NEW_ALERT", {
            "id": new_alert.id,
            "alert_type": new_alert.alert_type,
            "source_ip": new_alert.source_ip,
            "severity": new_alert.severity,
            "description": new_alert.description,
            "mitre_technique_id": new_alert.mitre_technique_id,
            "timestamp": str(new_alert.timestamp)
        })

        # Autonomous SOAR Response Hook
        try:
            from app.playbooks import trigger_auto_containment_if_applicable
            trigger_auto_containment_if_applicable(self.db, new_alert)
        except Exception:
            pass

        return new_alert

