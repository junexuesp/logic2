"""
BIS (Broadcast Isochronous Stream) link type parser for BLE packets.
"""

from constants import ISO_LLID_TYPE


def parse_s0_bis(byte_value):
    """
    Parse S0 byte for BIS link type.
    
    The S0 byte contains:
    - Link Layer ID (2 bits, bits 0-1)
    - CIS Subevent Sequence Number (3 bits, bits 2-4)
    - CIS Subevent Time Flag (1 bit, bit 5)
    - Reserved for Future Use (2 bits, bits 6-7)
    
    Args:
        byte_value: The S0 byte value
        
    Returns:
        dict: Parsed fields
    """
    return {
        'llid': ISO_LLID_TYPE[byte_value & 3],  # Bits 0-1: LLID
        'cssn': (byte_value >> 2) & 7,  # Bits 2-4: CIS Subevent Sequence Number
        'cstf': (byte_value >> 5) & 1,  # Bit 5: CIS Subevent Time Flag
        'rfu': (byte_value >> 6) & 3,  # Bits 6-7: Reserved for Future Use
    }
