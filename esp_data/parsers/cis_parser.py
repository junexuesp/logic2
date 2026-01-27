"""
CIS (Connected Isochronous Stream) link type parser for BLE packets.
"""

from constants import ISO_LLID_TYPE


def parse_s0_cis(byte_value):
    """
    Parse S0 byte for CIS link type.
    
    The S0 byte contains:
    - Link Layer ID (2 bits, bits 0-1)
    - Next Expected Sequence Number (1 bit, bit 2)
    - Sequence Number (1 bit, bit 3)
    - CIS Event (1 bit, bit 4)
    - Reserved for Future Use (1 bit, bit 5)
    - NSE Payload Indicator (1 bit, bit 6)
    - Reserved for Future Use (1 bit, bit 7)
    
    Args:
        byte_value: The S0 byte value
        
    Returns:
        dict: Parsed fields
    """
    return {
        'llid': ISO_LLID_TYPE[byte_value & 3],  # Bits 0-1: LLID
        'nesn': (byte_value >> 2) & 1,  # Bit 2: Next Expected Sequence Number
        'sn': (byte_value >> 3) & 1,  # Bit 3: Sequence Number
        'cie': (byte_value >> 4) & 1,  # Bit 4: CIS Event
        'rfu': (byte_value >> 5) & 1,  # Bit 5: Reserved for Future Use
        'npi': (byte_value >> 6) & 1,  # Bit 6: NSE Payload Indicator
        'rfu': (byte_value >> 7) & 1,  # Bit 7: Reserved for Future Use
    }
