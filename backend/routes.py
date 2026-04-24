"""
API Blueprint Registration for ZeinaGuard Pro
Integrates all specialized route modules into the Flask app
"""

from flask import Blueprint
from auth import auth_bp
from routes_threats import threats_bp
from routes_sensors import sensors_bp
from routes_dashboard import active_networks_bp, dashboard_bp
from routes_alerts import alerts_bp
from routes_incidents import incidents_bp
from routes_topology import topology_bp
from notification_routes import notifications_bp

def register_blueprints(app):
    """
    Register all specialized blueprints with the Flask application
    Ensures that each module handles its own specific domain logic
    """
    
    # Core Authentication Routes
    app.register_blueprint(auth_bp)
    
    # Threat Event Monitoring & Management
    app.register_blueprint(threats_bp)
    
    # Sensor Infrastructure & Health
    app.register_blueprint(sensors_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(incidents_bp)
    
    # Security Dashboard & Metrics
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(active_networks_bp)
    
    # Network Topology Visualization
    app.register_blueprint(topology_bp)
    
    # Notification & Alert Configuration
    app.register_blueprint(notifications_bp)
    
    print("[API] All database-backed blueprints registered successfully")
