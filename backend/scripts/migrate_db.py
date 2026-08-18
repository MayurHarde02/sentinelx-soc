"""
SentinelX Database Migration & Sync Utility
Exports records from source database (e.g. SQLite) and loads them into a target database (e.g. PostgreSQL).
Usage:
    python scripts/migrate_db.py --source sqlite:///./sentinelx.db --target postgresql://user:pass@localhost:5432/sentinelx_db
"""

import argparse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base, User, DetectionRule, SecurityEvent, Alert, Incident, IncidentAlert, AnalystNote

def migrate(source_url: str, target_url: str):
    print(f"[*] Connecting to Source DB: {source_url}")
    source_engine = create_engine(source_url, connect_args={"check_same_thread": False} if "sqlite" in source_url else {})
    SourceSession = sessionmaker(bind=source_engine)
    src_db = SourceSession()

    print(f"[*] Connecting to Target DB: {target_url}")
    target_engine = create_engine(target_url, pool_pre_ping=True)
    TargetSession = sessionmaker(bind=target_engine)
    
    print("[*] Creating table schema in target database...")
    Base.metadata.create_all(bind=target_engine)
    tgt_db = TargetSession()

    models = [User, DetectionRule, SecurityEvent, Alert, Incident, IncidentAlert, AnalystNote]

    for model in models:
        table_name = model.__tablename__
        records = src_db.query(model).all()
        print(f"[*] Migrating {len(records)} records from table '{table_name}'...")
        
        for record in records:
            # Clone model attributes into target session
            attrs = {c.name: getattr(record, c.name) for c in record.__table__.columns}
            new_obj = model(**attrs)
            tgt_db.merge(new_obj)
        tgt_db.commit()

    src_db.close()
    tgt_db.close()
    print("[+] Migration completed successfully!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate SentinelX SQLite DB to PostgreSQL")
    parser.add_argument("--source", default="sqlite:///./sentinelx.db", help="Source database URL")
    parser.add_argument("--target", required=True, help="Target database URL (e.g. postgresql://...)")
    args = parser.parse_args()

    migrate(args.source, args.target)
