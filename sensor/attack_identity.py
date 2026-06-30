import hashlib
import hmac
import os

ATTACK_FRAME_SECRET: bytes = os.urandom(16)

def derive_attack_sc(bssid: str) -> int:
    """Return the 12-bit Sequence Number to embed in ZeinaGuard-generated deauth frames.

    Both ContainmentEngine (injection) and DeauthDetector (capture) call this
    function independently with the same BSSID to arrive at the same expected
    value without any inter-module state sharing.

    The Dot11 SC field is a 16-bit little-endian value where bits [15:4] are the
    Sequence Number and bits [3:0] are the Fragment Number.  Callers must apply
    ``(seq_num << 4) | 0`` before assigning to Scapy's SC field.

    Args:
        bssid: Target BSSID in any case or separator format.
               Normalised to uppercase colon-separated internally.

    Returns:
        Integer in [0, 4095] — the 12-bit Sequence Number component only.
    """
    normalised = bssid.upper().replace("-", ":").encode("ascii", errors="ignore")
    digest = hmac.new(ATTACK_FRAME_SECRET, normalised, hashlib.sha256).digest()
    return int.from_bytes(digest[:2], "big") & 0x0FFF
