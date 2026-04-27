from flask import Blueprint
from auth import auth_bp
from routes_threats import threats_bp
from routes_sensors import sensors_bp
from routes_dashboard import active_networks_bp, dashboard_bp
from routes_incidents import incidents_bp


def register_blueprints(app):

    
    # 1. Core Authentication Routes
    app.register_blueprint(auth_bp)
    
    # 2. Threat Event Monitoring & Management
    app.register_blueprint(threats_bp)
    
    # 3. Sensor Infrastructure & Health
    app.register_blueprint(sensors_bp)
    
    # 4. Security Incidents & Logs
    app.register_blueprint(incidents_bp)
    
    # 5. Security Dashboard & Metrics
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(active_networks_bp)
    

    print("[API] All active blueprints registered successfully (Alerts & Settings removed)")