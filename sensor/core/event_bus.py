from queue import Queue

# تحديد حجم معقول للـ Queues لمنع استهلاك الميموري في حالات الضغط
event_queue = Queue(maxsize=1000)
containment_queue = Queue(maxsize=500)
dashboard_queue = Queue(maxsize=2000) # ده الأهم للوجات التيرمينال
scan_queue = Queue(maxsize=5000)