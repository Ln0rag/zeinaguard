from queue import Queue

# Sniffer -> ThreatManager
event_queue = Queue()

# ThreatManager -> ResponseEngine
containment_queue = Queue()

# ThreatManager -> backend threat stream
dashboard_queue = Queue()

# ThreatManager -> backend/local scan storage
scan_queue = Queue()
