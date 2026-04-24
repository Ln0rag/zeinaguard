"""
Network Topology API Routes for ZeinaGuard Pro
Provides graph-compatible JSON data for network visualization
"""

from flask import Blueprint, jsonify, request
from topology_mock_data import get_mock_topology_data

# Create blueprint
topology_bp = Blueprint('topology', __name__, url_prefix='/api/topology')


@topology_bp.route('', methods=['GET'])
def get_topology():
    """
    GET /api/topology
    Returns network topology graph with nodes and edges
    
    Response includes:
    - nodes: Array of topology nodes (sensors, routers, stations)
    - edges: Array of connections between nodes
    - metadata: Graph statistics and shared node information
    
    Returns gracefully with empty structure if no sensors are found.
    """
    try:
        topology_data = get_mock_topology_data()
        
        # Handle case where no sensors/nodes are available
        if not topology_data.get('nodes'):
            return jsonify({
                'success': True,
                'data': {
                    'nodes': [],
                    'edges': [],
                    'metadata': {
                        'total_nodes': 0,
                        'total_edges': 0,
                        'total_sensors': 0,
                        'total_routers': 0,
                        'total_stations': 0,
                        'shared_nodes_count': 0,
                        'shared_nodes': {},
                        'generated_at': None
                    }
                },
                'message': 'No active sensors detected. Please ensure your Raspberry Pi units are online.'
            }), 200
        
        return jsonify({
            'success': True,
            'data': topology_data,
            'message': 'Network topology data retrieved successfully'
        }), 200
        
    except Exception as e:
        # Return gracefully with empty structure on error (resilience)
        return jsonify({
            'success': True,
            'data': {
                'nodes': [],
                'edges': [],
                'metadata': {
                    'total_nodes': 0,
                    'total_edges': 0,
                    'total_sensors': 0,
                    'total_routers': 0,
                    'total_stations': 0,
                    'shared_nodes_count': 0,
                    'shared_nodes': {},
                    'generated_at': None
                }
            },
            'message': f'Error retrieving topology data. No active sensors detected. ({str(e)})'
        }), 200


@topology_bp.route('/sensors', methods=['GET'])
def get_topology_sensors():
    """
    GET /api/topology/sensors
    Returns only sensor nodes from the topology
    """
    try:
        topology_data = get_mock_topology_data()
        sensors = [node for node in topology_data['nodes'] if node['type'] == 'sensor']
        
        return jsonify({
            'success': True,
            'data': {
                'sensors': sensors,
                'count': len(sensors)
            },
            'message': 'Sensor nodes retrieved successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to retrieve sensor data'
        }), 500


@topology_bp.route('/routers', methods=['GET'])
def get_topology_routers():
    """
    GET /api/topology/routers
    Returns only access point/router nodes from the topology
    """
    try:
        topology_data = get_mock_topology_data()
        routers = [node for node in topology_data['nodes'] if node['type'] == 'router']
        
        return jsonify({
            'success': True,
            'data': {
                'routers': routers,
                'count': len(routers)
            },
            'message': 'Router nodes retrieved successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to retrieve router data'
        }), 500


@topology_bp.route('/stations', methods=['GET'])
def get_topology_stations():
    """
    GET /api/topology/stations
    Returns only station (client device) nodes from the topology
    """
    try:
        topology_data = get_mock_topology_data()
        stations = [node for node in topology_data['nodes'] if node['type'] == 'station']
        
        return jsonify({
            'success': True,
            'data': {
                'stations': stations,
                'count': len(stations)
            },
            'message': 'Station nodes retrieved successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to retrieve station data'
        }), 500


@topology_bp.route('/shared-nodes', methods=['GET'])
def get_shared_nodes():
    """
    GET /api/topology/shared-nodes
    Returns nodes that are visible/connected to multiple sensors (overlapping coverage)
    These nodes should be highlighted in the visualization
    """
    try:
        topology_data = get_mock_topology_data()
        shared = {
            'routers': [node for node in topology_data['nodes'] 
                       if node['type'] == 'router' and node.get('is_shared')],
            'stations': [node for node in topology_data['nodes'] 
                        if node['type'] == 'station' and node.get('is_shared')]
        }
        
        return jsonify({
            'success': True,
            'data': {
                'shared_nodes': shared,
                'total_shared': len(shared['routers']) + len(shared['stations']),
                'metadata': topology_data['metadata'].get('shared_nodes', {})
            },
            'message': 'Shared nodes retrieved successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to retrieve shared nodes data'
        }), 500


@topology_bp.route('/statistics', methods=['GET'])
def get_topology_statistics():
    """
    GET /api/topology/statistics
    Returns topology statistics and metadata
    """
    try:
        topology_data = get_mock_topology_data()
        metadata = topology_data['metadata']
        
        return jsonify({
            'success': True,
            'data': {
                'total_nodes': len(topology_data['nodes']),
                'total_edges': len(topology_data['edges']),
                'sensors': metadata['total_sensors'],
                'routers': metadata['total_routers'],
                'stations': metadata['total_stations'],
                'shared_nodes_count': metadata['shared_nodes_count'],
                'shared_nodes_detail': metadata['shared_nodes'],
                'generated_at': metadata['generated_at']
            },
            'message': 'Topology statistics retrieved successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to retrieve topology statistics'
        }), 500


@topology_bp.route('/node/<node_id>', methods=['GET'])
def get_node_details(node_id):
    """
    GET /api/topology/node/<node_id>
    Returns detailed information about a specific node
    Includes connected edges and related nodes
    """
    try:
        topology_data = get_mock_topology_data()
        
        # Find the node
        node = None
        for n in topology_data['nodes']:
            if n['id'] == node_id:
                node = n
                break
        
        if not node:
            return jsonify({
                'success': False,
                'error': f'Node {node_id} not found',
                'message': 'Node not found in topology'
            }), 404
        
        # Find connected edges
        connected_edges = [
            edge for edge in topology_data['edges']
            if edge['source'] == node_id or edge['target'] == node_id
        ]
        
        # Find related nodes
        related_node_ids = set()
        for edge in connected_edges:
            related_node_ids.add(edge['source'])
            related_node_ids.add(edge['target'])
        related_node_ids.discard(node_id)
        
        related_nodes = [
            n for n in topology_data['nodes']
            if n['id'] in related_node_ids
        ]
        
        return jsonify({
            'success': True,
            'data': {
                'node': node,
                'connected_edges': connected_edges,
                'related_nodes': related_nodes,
                'connection_count': len(connected_edges)
            },
            'message': f'Details for node {node_id} retrieved successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to retrieve node details'
        }), 500


def register_topology_blueprint(app):
    """Register the topology blueprint with the Flask app"""
    app.register_blueprint(topology_bp)
