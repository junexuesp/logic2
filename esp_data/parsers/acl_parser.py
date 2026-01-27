"""
ACL (Asynchronous Connection-Less) link type parser for BLE packets.
"""

from constants import ACL_LLID_TYPE


def parse_s0_acl(byte_value):
    """
    Parse S0 byte for ACL link type.
    
    The S0 byte contains:
    - Link Layer ID (2 bits, bits 0-1)
    - Next Expected Sequence Number (1 bit, bit 2)
    - Sequence Number (1 bit, bit 3)
    - More Data (1 bit, bit 4)
    - Control PDU (1 bit, bit 5)
    - Reserved for Future Use (1 bit, bit 6)
    
    Args:
        byte_value: The S0 byte value
        
    Returns:
        dict: Parsed fields
    """
    return {
        'llid': ACL_LLID_TYPE[byte_value & 3],  # Bits 0-1: LLID
        'nesn': (byte_value >> 2) & 1,  # Bit 2: Next Expected Sequence Number
        'sn': (byte_value >> 3) & 1,  # Bit 3: Sequence Number
        'md': (byte_value >> 4) & 1,  # Bit 4: More Data
        'cp': (byte_value >> 5) & 1,  # Bit 5: Control PDU
        'rfu': (byte_value >> 6) & 1,  # Bit 6: Reserved for Future Use
    }
