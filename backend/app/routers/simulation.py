from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas import SimulationRequest, SimulationResponse
from app.simulator import AttackSimulator
import app.simulator as sim_module

router = APIRouter(prefix="/simulation", tags=["Attack Simulator"])

@router.post("/trigger", response_model=SimulationResponse)
def trigger_attack_scenario(payload: SimulationRequest, db: Session = Depends(get_db)):
    simulator = AttackSimulator(db)
    try:
        result = simulator.trigger_scenario(
            scenario=payload.scenario,
            target_ip=payload.target_ip,
            intensity=payload.intensity or 1
        )
        return SimulationResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/stream/toggle", response_model=Dict[str, Any])
def toggle_live_stream():
    sim_module.live_stream_active = not sim_module.live_stream_active
    state_str = "ACTIVE" if sim_module.live_stream_active else "PAUSED"
    return {
        "status": "success",
        "live_stream_active": sim_module.live_stream_active,
        "message": f"Background SOC telemetry simulation is now {state_str}."
    }

@router.get("/stream/status", response_model=Dict[str, Any])
def get_live_stream_status():
    return {
        "live_stream_active": sim_module.live_stream_active
    }

@router.post("/seed-demo", response_model=Dict[str, Any])
def seed_demo_data(db: Session = Depends(get_db)):
    """Seed comprehensive baseline telemetry with realistic attacks, ML anomalies, and normal traffic."""
    simulator = AttackSimulator(db)
    
    # 1. Normal traffic baseline
    simulator.trigger_scenario("benign", intensity=3)
    
    # 2. Brute force attack wave
    simulator.trigger_scenario("brute_force", target_ip="192.168.1.22", intensity=1)
    
    # 3. Port scan attack wave
    simulator.trigger_scenario("port_scan", target_ip="198.51.100.42", intensity=1)
    
    # 4. Suspicious login sequence
    simulator.trigger_scenario("suspicious_login", target_ip="185.220.101.5", intensity=1)
    
    # 5. ML Anomaly burst
    simulator.trigger_scenario("anomaly", target_ip="194.26.29.112", intensity=1)

    # 6. Additional benign traffic
    simulator.trigger_scenario("benign", intensity=2)

    return {
        "status": "success",
        "message": "Successfully seeded demo dataset with simulated attacks, ML anomalies, and baseline network traffic."
    }
