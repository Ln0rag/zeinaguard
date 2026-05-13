from flask import Blueprint
from routes_sensors import sensors_bp
from routes_dashboard import active_networks_bp, dashboard_bp


def register_blueprints(app):
    
    # 3. Sensor Infrastructure & Health
    app.register_blueprint(sensors_bp)
    
    # 5. Security Dashboard & Metrics
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(active_networks_bp)
    

    print("[API] All active blueprints registered successfully (Alerts & Settings removed)")