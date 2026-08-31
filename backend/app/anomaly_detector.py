import math
import numpy as np
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from app.models import SecurityEvent

class IsolationTreeNode:
    def __init__(self, left=None, right=None, split_feature: int = -1, split_value: float = 0.0, size: int = 0):
        self.left = left
        self.right = right
        self.split_feature = split_feature
        self.split_value = split_value
        self.size = size

class IsolationTree:
    """Single Isolation Tree for partitioning multi-dimensional event feature space."""

    def __init__(self, max_depth: int = 8):
        self.max_depth = max_depth
        self.root: Optional[IsolationTreeNode] = None

    def fit(self, X: np.ndarray, current_depth: int = 0) -> IsolationTreeNode:
        n_samples, n_features = X.shape
        if current_depth >= self.max_depth or n_samples <= 1:
            return IsolationTreeNode(size=n_samples)

        # Select random feature and split point
        feature_idx = np.random.randint(0, n_features)
        min_val = X[:, feature_idx].min()
        max_val = X[:, feature_idx].max()

        if min_val == max_val:
            return IsolationTreeNode(size=n_samples)

        split_val = np.random.uniform(min_val, max_val)
        left_mask = X[:, feature_idx] < split_val
        right_mask = ~left_mask

        left_node = self.fit(X[left_mask], current_depth + 1)
        right_node = self.fit(X[right_mask], current_depth + 1)

        return IsolationTreeNode(
            left=left_node,
            right=right_node,
            split_feature=feature_idx,
            split_value=split_val,
            size=n_samples
        )

    def path_length(self, x: np.ndarray, node: IsolationTreeNode, current_depth: int = 0) -> float:
        if node.left is None or node.right is None:
            # Average path length correction for leaf of size n
            if node.size <= 1:
                return current_depth
            return current_depth + 2.0 * (math.log(node.size - 1) + 0.5772156649) - (2.0 * (node.size - 1) / node.size)

        if x[node.split_feature] < node.split_value:
            return self.path_length(x, node.left, current_depth + 1)
        else:
            return self.path_length(x, node.right, current_depth + 1)

class AnomalyDetector:
    """
    Machine Learning Anomaly Detector for SentinelX SOC.
    Implements multi-dimensional Isolation Forest on event velocity & rate vectors.
    """

    def __init__(self, n_trees: int = 50, max_samples: int = 128):
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.trees: List[IsolationTree] = []
        self._initialize_baseline_model()

    def _initialize_baseline_model(self):
        """Train Isolation Forest baseline on normal operational SOC event distributions."""
        np.random.seed(42)
        # Normal baseline features: [event_count_per_min, unique_ports, failure_ratio, unique_users]
        normal_events = np.random.normal(loc=3.5, scale=1.8, size=(250, 1)).clip(1, 15)
        normal_ports = np.random.normal(loc=1.1, scale=0.3, size=(250, 1)).clip(1, 2)
        normal_fail_ratio = np.random.beta(a=0.5, b=6.0, size=(250, 1))
        normal_users = np.random.normal(loc=1.0, scale=0.2, size=(250, 1)).clip(1, 2)

        normal_data = np.hstack([normal_events, normal_ports, normal_fail_ratio, normal_users])

        # Mild outlier samples
        synthetic_anomalies = np.array([
            [85.0, 12.0, 0.9, 5.0],
            [120.0, 1.0, 0.05, 1.0],
            [15.0, 25.0, 0.8, 1.0],
            [40.0, 8.0, 0.95, 8.0],
            [60.0, 2.0, 0.7, 4.0]
        ])

        training_data = np.vstack([normal_data, synthetic_anomalies])
        self.trees = []

        for _ in range(self.n_trees):
            subsample_idx = np.random.choice(len(training_data), size=min(self.max_samples, len(training_data)), replace=False)
            subsample = training_data[subsample_idx]
            tree = IsolationTree(max_depth=int(np.ceil(np.log2(max(self.max_samples, 2)))) + 2)
            tree.root = tree.fit(subsample)
            self.trees.append(tree)

    def extract_features(self, db: Session, source_ip: str, window_minutes: int = 2) -> np.ndarray:
        """Extract multi-dimensional behavioral traffic vector for the given source IP."""
        window_start = datetime.utcnow() - timedelta(minutes=window_minutes)

        events_count = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= window_start
        ).scalar() or 0

        unique_ports = db.query(func.count(distinct(SecurityEvent.port))).filter(
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.port.isnot(None)
        ).scalar() or 1

        failed_count = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.status.in_(["FAILURE", "BLOCKED"])
        ).scalar() or 0

        unique_users = db.query(func.count(distinct(SecurityEvent.username))).filter(
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.username.isnot(None)
        ).scalar() or 1

        fail_ratio = (failed_count / events_count) if events_count > 0 else 0.0

        return np.array([float(events_count), float(unique_ports), float(fail_ratio), float(unique_users)])

    def _c(self, n: int) -> float:
        """Average path length of unsuccessful search in BST."""
        if n <= 1:
            return 1.0
        return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)

    def evaluate_traffic_anomaly(self, db: Session, source_ip: str) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Evaluates whether an IP's current behavioral vector is an anomalous outlier.
        Returns: (is_anomaly: bool, anomaly_score: float, details_dict: dict)
        """
        features = self.extract_features(db, source_ip)
        event_count = features[0]

        # Require a minimum statistical activity threshold
        if event_count < 6:
            return False, 0.0, {
                "events_rate": int(event_count),
                "unique_ports": int(features[1]),
                "failure_ratio": round(float(features[2]), 2),
                "unique_users": int(features[3]),
                "ml_decision_score": 0.0,
                "anomaly_confidence_pct": 0
            }

        # Calculate average tree path length E(h(x))
        path_lengths = [tree.path_length(features, tree.root) for tree in self.trees]
        avg_path_length = float(np.mean(path_lengths))
        c_n = self._c(self.max_samples)

        # Anomaly score s(x, n) = 2^(-E(h(x))/c(n))
        anomaly_score = math.pow(2.0, - (avg_path_length / c_n))

        # Confidence percentage (0 to 100)
        confidence = max(0, min(100, int((anomaly_score - 0.45) * 220)))

        is_anomaly = (anomaly_score >= 0.62) or (event_count >= 50 and features[2] > 0.4)

        details = {
            "events_rate": int(event_count),
            "unique_ports": int(features[1]),
            "failure_ratio": round(float(features[2]), 2),
            "unique_users": int(features[3]),
            "ml_decision_score": round(anomaly_score, 4),
            "anomaly_confidence_pct": confidence
        }

        return is_anomaly, anomaly_score, details

anomaly_detector = AnomalyDetector()
