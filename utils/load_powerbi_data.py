"""
Power BI Data Loader Script
Load security events data from SQLite database into Power BI using Python.

Usage in Power BI:
1. Get Data -> Python script
2. Run this script or copy the code below
"""

import sqlite3
import pandas as pd
import os

# Get the absolute path to the database
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
db_path = os.path.join(project_root, 'output', 'security_events.db')

print(f"Connecting to database: {db_path}")

# Connect to SQLite database
conn = sqlite3.connect(db_path)

# Load the Power BI optimized view with all joins pre-computed
security_events = pd.read_sql_query("""
    SELECT
        event_id,
        timestamp,
        event_type,
        event_category,
        severity,
        severity_score,
        color_code,
        source_ip,
        username,
        secondary_user,
        command,
        threat_category,
        mitre_technique,
        event_count,
        window_start,
        window_end,
        country,
        city,
        latitude,
        longitude,
        date,
        hour,
        day_of_week,
        day_type,
        time_period
    FROM vw_security_dashboard
""", conn)

# Also load individual dimension tables 
dim_severity = pd.read_sql_query("SELECT * FROM dim_severity", conn)
dim_event_type = pd.read_sql_query("SELECT * FROM dim_event_type", conn)
dim_threat_category = pd.read_sql_query("SELECT * FROM dim_threat_category", conn)

# Load fact table
fact_security_events = pd.read_sql_query("SELECT * FROM fact_security_events", conn)

conn.close()

print(f"Loaded {len(security_events)} security events")
print(f"Date range: {security_events['date'].min()} to {security_events['date'].max()}")
print(f"\nDataFrames available for Power BI:")
print("  - security_events (recommended - pre-joined view)")
print("  - fact_security_events (raw fact table)")
print("  - dim_severity")
print("  - dim_event_type")
print("  - dim_threat_category")
