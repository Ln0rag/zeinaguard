"""
Network Topology Mock Data Generator for ZeinaGuard Pro
Generates realistic sensor, access point, and station data with shared visibility detection
"""

from typing import Dict, List, Tuple
from datetime import datetime
from random import randint, choice, uniform


class TopologyMockDataGenerator:
    """Generates mock network topology data with overlapping sensor coverage"""
    
    def __init__(self):
        self.sensors = []
        self.routers = []
        self.stations = []
        self.edges = []
        
    def generate_sensors(self, count: int = 2) -> List[Dict]:
        """Generate Raspberry Pi sensor nodes"""
        sensor_locations = [
            "Office - Floor 1",
            "Server Room - Floor 2",
            "Warehouse - Outdoor",
        ]
        
        self.sensors = []
        for i in range(min(count, len(sensor_locations))):
            sensor = {
                "id": f"sensor_{i+1}",
                "type": "sensor",
                "label": f"Raspberry Pi {i+1}",
                "location": sensor_locations[i],
                "mac_address": f"B8:27:EB:{randint(0,255):02X}:{randint(0,255):02X}:{randint(0,255):02X}",
                "ip_address": f"192.168.1.{100+i}",
                "status": "online",
                "signal_strength": randint(-40, -20),
                "uptime_percent": randint(95, 100),
                "last_heartbeat": datetime.utcnow().isoformat(),
            }
            self.sensors.append(sensor)
        return self.sensors
    
    def generate_routers(self, count: int = 3) -> List[Dict]:
        """Generate Access Point (Router) nodes"""
        router_templates = [
            {"ssid": "Corporate-WiFi", "security": "WPA2", "channel": 6},
            {"ssid": "Guest-Network", "security": "Open", "channel": 11},
            {"ssid": "Building-IoT", "security": "WPA3", "channel": 1},
            {"ssid": "VPN-Bridge", "security": "WPA2", "channel": 9},
            {"ssid": "Legacy-AP", "security": "WEP", "channel": 3},
        ]
        
        self.routers = []
        for i in range(min(count, len(router_templates))):
            template = router_templates[i]
            router = {
                "id": f"router_{i+1}",
                "type": "router",
                "label": template["ssid"],
                "ssid": template["ssid"],
                "mac_address": f"AA:BB:CC:{randint(0,255):02X}:{randint(0,255):02X}:{randint(0,255):02X}",
                "security": template["security"],
                "channel": template["channel"],
                "frequency": "2.4GHz" if template["channel"] in [1,6,11] else "5GHz",
                "signal_strength": randint(-50, -30),
                "client_count": randint(2, 8),
                "last_seen": datetime.utcnow().isoformat(),
                "is_suspicious": i == 4,  # Mark Legacy-AP as suspicious
            }
            self.routers.append(router)
        return self.routers
    
    def generate_stations(self, count: int = 7) -> List[Dict]:
        """Generate Station (Client Device) nodes"""
        device_names = [
            "iPhone-12", "MacBook-Air", "Samsung-Galaxy", 
            "HP-Laptop", "iPad-Pro", "Surface-Book",
            "Pixel-6", "ThinkPad-X1", "Dell-XPS"
        ]
        
        self.stations = []
        for i in range(min(count, len(device_names))):
            station = {
                "id": f"station_{i+1}",
                "type": "station",
                "label": device_names[i],
                "device_name": device_names[i],
                "mac_address": f"DD:EE:FF:{randint(0,255):02X}:{randint(0,255):02X}:{randint(0,255):02X}",
                "device_type": choice(["Phone", "Laptop", "Tablet", "IoT"]),
                "signal_strength": randint(-80, -40),
                "status": "connected" if randint(0, 10) > 2 else "idle",
                "ip_address": f"192.168.1.{150+i}",
                "last_activity": datetime.utcnow().isoformat(),
            }
            self.stations.append(station)
        return self.stations
    
    def generate_edges_with_shared_detection(self) -> Tuple[List[Dict], Dict]:
        """
        Generate edges and detect shared nodes (sensors seeing same routers/stations)
        Returns edges list and shared_nodes dict for visualization highlighting
        """
        self.edges = []
        shared_nodes = {}  # Track which nodes are seen by multiple sensors
        sensor_visibility = {}  # Map sensors to what they see
        
        # Build sensor visibility map
        for sensor in self.sensors:
            # Each sensor sees 2-3 routers (with overlap)
            visible_routers = self.routers[:2] + [choice(self.routers[2:])]
            sensor_visibility[sensor["id"]] = visible_routers
        
        # Detect shared routers (seen by multiple sensors)
        all_visible = [r["id"] for routers in sensor_visibility.values() for r in routers]
        for router_id in set(all_visible):
            if all_visible.count(router_id) > 1:
                shared_nodes[router_id] = "shared_router"
        
        # Create sensor -> router edges
        for sensor in self.sensors:
            for router in sensor_visibility[sensor["id"]]:
                self.edges.append({
                    "id": f"edge_{sensor['id']}_{router['id']}",
                    "source": sensor["id"],
                    "target": router["id"],
                    "type": "detection",
                    "signal_strength": randint(-80, -40),
                    "connection_type": "2.4GHz" if router.get("frequency") == "2.4GHz" else "5GHz",
                })
        
        # Create router -> station edges (devices connected to APs)
        # First router: 2-3 devices
        # Second router: 2-3 devices (with 1 shared)
        # Third router: 1-2 devices (with 1 possibly shared)
        station_assignments = [
            self.stations[0:2],  # Router 1 has stations 0-1
            self.stations[1:4],  # Router 2 has stations 1-3 (shares station 1)
            self.stations[3:5] + [self.stations[6]],  # Router 3 has 3,4,6 (shares 3)
        ]
        
        for router_idx, (router, assigned_stations) in enumerate(zip(self.routers, station_assignments)):
            for station in assigned_stations:
                edge_id = f"edge_{router['id']}_{station['id']}"
                self.edges.append({
                    "id": edge_id,
                    "source": router["id"],
                    "target": station["id"],
                    "type": "connection",
                    "signal_strength": station["signal_strength"],
                    "connection_status": station["status"],
                })
                
                # Detect shared stations (connected to multiple APs - indicator of roaming)
                if station["id"] not in shared_nodes:
                    shared_nodes[station["id"]] = "shared_station"
        
        return self.edges, shared_nodes
    
    def generate_topology_graph(self) -> Dict:
        """Generate complete topology graph with nodes and edges"""
        self.generate_sensors(2)
        self.generate_routers(3)
        self.generate_stations(7)
        edges, shared_nodes = self.generate_edges_with_shared_detection()
        
        # Combine all nodes
        all_nodes = self.sensors + self.routers + self.stations
        
        # Add shared node metadata
        for node in all_nodes:
            if node["id"] in shared_nodes:
                node["is_shared"] = True
                node["shared_type"] = shared_nodes[node["id"]]
                node["highlight"] = True
            else:
                node["is_shared"] = False
                node["highlight"] = False
        
        return {
            "nodes": all_nodes,
            "edges": edges,
            "metadata": {
                "total_sensors": len(self.sensors),
                "total_routers": len(self.routers),
                "total_stations": len(self.stations),
                "total_edges": len(edges),
                "shared_nodes_count": len(shared_nodes),
                "shared_nodes": shared_nodes,
                "generated_at": datetime.utcnow().isoformat(),
            }
        }


def get_mock_topology_data() -> Dict:
    """Main function to get mock topology data"""
    generator = TopologyMockDataGenerator()
    return generator.generate_topology_graph()
