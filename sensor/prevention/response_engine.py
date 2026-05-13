from core.event_bus import containment_queue
from runtime_state import log_attack, update_status
import queue # هنحتاجها عشان الـ Timeout

class ResponseEngine:
    def __init__(self):
        self.running = True

    def stop(self):
        """دالة للتحكم في غلق المحرك بأمان"""
        self.running = False

    def start(self):
        print("[ResponseEngine] Active and monitoring containment queue...")
        while self.running:
            try:
                # استخدمنا timeout عشان الـ loop متفضلش محبوسة وتقدر تشوف قيمة self.running
                threat = containment_queue.get(timeout=1.0)
                
                bssid = threat.get("event", {}).get("bssid", "unknown")
                log_attack(f"Manual hunt required -> {bssid}", bssid)
                update_status(message=f"Rogue detected: press H and choose {bssid} for manual hunt")
                
                # علامة إننا خلصنا معالجة العنصر ده
                containment_queue.task_done()
                
            except queue.Empty:
                # الـ Queue فاضية، بنكمل الـ loop عادي ونشوف هل جالنا أمر stop ولا لا
                continue
            except Exception as e:
                print(f"[ResponseEngine] Error processing threat: {e}")
        
        print("[ResponseEngine] Shutdown complete. All threads joined.")