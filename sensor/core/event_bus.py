from queue import Queue

event_queue = Queue(maxsize=1000)
containment_queue = Queue(maxsize=500)
dashboard_queue = Queue(maxsize=2000)
scan_queue = Queue(maxsize=5000)