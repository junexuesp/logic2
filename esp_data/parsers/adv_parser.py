"""
ADV (Advertising) link type parser for BLE packets.
Handles both legacy and extended advertising packets.
"""

from saleae.analyzers import AnalyzerFrame
from constants import PDU_TYPE, EXT_ADV_MODE


def parse_s0_adv(byte_value):
    """
    Parse S0 byte for ADV link type.
    
    Args:
        byte_value: The S0 byte value
        
    Returns:
        dict: Parsed fields and PDU type
    """
    pdu_type_idx = byte_value & 0x7  # Bits 0-2: PDU Type
    pdu_type = PDU_TYPE[pdu_type_idx]
    
    return {
        'pdu_type': pdu_type,
        'rfu': (byte_value >> 4) & 1,  # Bit 4: Reserved for Future Use
        'chsel': (byte_value >> 5) & 1,  # Bit 5: Channel Selection
        'TxAdd': (byte_value >> 6) & 1,  # Bit 6: Transmit Address
        'RxAdd': (byte_value >> 7) & 1,  # Bit 7: Receive Address
    }


def parse_ceap_fields(byte_value, frame_len_remain):
    """
    Parse and set Common Extended Advertising Payload (CEAP) header fields.
    
    The CEAP header (1 byte) contains:
    - Extended Header Length (6 bits, bits 0-5): Length of extended header (0-63 bytes)
    - AdvMode (2 bits, bits 6-7): Advertising mode
    
    Args:
        byte_value: The CEAP header byte
        frame_len_remain: Remaining frame length
        
    Returns:
        dict: Parsed CEAP fields and extended header length
    """
    ext_hdr_len = byte_value & 0x3F  # Bits 0-5: Extended Header Length (0-63 bytes)
    adv_mode_idx = (byte_value >> 6) & 0x3  # Bits 6-7: Advertising Mode
    
    result = {
        'ext_hdr_len': ext_hdr_len,
        'adv_mode': EXT_ADV_MODE[adv_mode_idx],
    }
    
    # Adjust remaining payload length (CEAP header is part of payload)
    new_frame_len_remain = frame_len_remain - 1 if frame_len_remain > 0 else 0
    
    return result, ext_hdr_len, new_frame_len_remain


def parse_extended_header(ext_hdr_bytes):
    """
    Parse Extended Header fields based on flags (BLE 6.0 specification).
    
    Extended Header structure (BLE 6.0):
    - Flags (1 byte): Indicates which fields are present
      - Bit 0: AdvA present
      - Bit 1: TargetA present
      - Bit 2: CTEInfo present
      - Bit 3: ADI (Advertising Data Indication) present
      - Bit 4: AuxPtr present
      - Bit 5: SyncInfo present
      - Bit 6: TxPower present
      - Bit 7: RFU
    - AdvA (6 bytes): Advertiser's address (if Flags bit 0 set)
    - TargetA (6 bytes): Target address (if Flags bit 1 set)
    - CTEInfo (1 byte): Constant Tone Extension Info (if Flags bit 2 set)
    - ADI (2 bytes, LE): DID 12 bits (bits 0-11), SID 4 bits (bits 12-15)
    - AuxPtr (3 bytes, LE): Ch.Index 6b, CA 1b, aux_offset_unit 1b, Aux Offset 13b, Aux PHY 3b;
      outputs aux_offset_unit (0|1), aux_off (µs) = raw_13b × (30 if unit==0 else 300)
    - SyncInfo (18 bytes): Synchronization Info (if Flags bit 5 set)
    - TxPower (1 byte): Transmit Power (if Flags bit 6 set)
    
    Args:
        ext_hdr_bytes: List of bytes in the extended header
        
    Returns:
        dict: Parsed extended header fields
    """
    if len(ext_hdr_bytes) == 0:
        return {}
    
    parsed = {}
    idx = 0
    
    # Parse Flags (first byte)
    if idx < len(ext_hdr_bytes):
        flags = ext_hdr_bytes[idx]
        parsed['flags'] = flags
        parsed['AdvA'] = (flags & 0x01) != 0  # Bit 0
        parsed['TgtA'] = (flags & 0x02) != 0  # Bit 1
        parsed['CTE'] = (flags & 0x04) != 0  # Bit 2
        parsed['ADI'] = (flags & 0x08) != 0  # Bit 3
        parsed['AuxPtr'] = (flags & 0x10) != 0  # Bit 4
        parsed['SyncInfo'] = (flags & 0x20) != 0  # Bit 5
        parsed['TxPwr'] = (flags & 0x40) != 0  # Bit 6
        parsed['rfu'] = (flags >> 7) & 0x1  # Bit 7
        idx += 1
        
        # Parse AdvA (6 bytes) if present
        if parsed['AdvA'] and idx + 6 <= len(ext_hdr_bytes):
            adv_a_bytes = ext_hdr_bytes[idx:idx+6]
            # Convert to little-endian MAC address format
            adv_a_str = ':'.join(f'{b:02X}' for b in reversed(adv_a_bytes))
            parsed['adv_a'] = adv_a_str
            idx += 6
        
        # Parse TargetA (6 bytes) if present
        if parsed['TgtA'] and idx + 6 <= len(ext_hdr_bytes):
            target_a_bytes = ext_hdr_bytes[idx:idx+6]
            target_a_str = ':'.join(f'{b:02X}' for b in reversed(target_a_bytes))
            parsed['target_a'] = target_a_str
            idx += 6
        
        # Parse CTEInfo (1 byte) if present
        if parsed['CTE'] and idx < len(ext_hdr_bytes):
            cte_info_byte = ext_hdr_bytes[idx]
            # CTEInfo: Bits 0-4 = CTE Length, Bit 5 = RFU, Bits 6-7 = CTE Type
            cte_length = cte_info_byte & 0x1F  # Bits 0-4
            cte_rfu = (cte_info_byte >> 5) & 0x1  # Bit 5
            cte_type = (cte_info_byte >> 6) & 0x3  # Bits 6-7
            parsed['cte_length'] = cte_length
            parsed['cte_rfu'] = cte_rfu
            parsed['cte_type'] = cte_type
            idx += 1
        
        # Parse ADI (2 bytes) if present — Core Spec Vol 6 Part B (Advertising Data Info)
        if parsed['ADI'] and idx + 2 <= len(ext_hdr_bytes):
            adi_bytes = ext_hdr_bytes[idx:idx+2]
            adi = adi_bytes[0] | (adi_bytes[1] << 8)  # little-endian
            parsed['did'] = adi & 0x0FFF  # 12 bits: Advertising Data ID
            parsed['sid'] = (adi >> 12) & 0x0F  # 4 bits: Advertising Set ID
            idx += 2
        
        # Parse AuxPtr (3 bytes) if present — Core Spec Vol 6 Part B
        if parsed['AuxPtr'] and idx + 3 <= len(ext_hdr_bytes):
            b0, b1, b2 = (
                ext_hdr_bytes[idx],
                ext_hdr_bytes[idx + 1],
                ext_hdr_bytes[idx + 2],
            )
            v = b0 | (b1 << 8) | (b2 << 16)
            aux_ch = v & 0x3F  # bits 0-5: channel index
            ca = (v >> 6) & 0x1  # bit 6: clock accuracy (0=51–500ppm, 1=0–50ppm)
            offset_unit = (v >> 7) & 0x1  # bit 7: 0 → 30µs, 1 → 300µs per offset step
            aux_off_raw = (v >> 8) & 0x1FFF  # bits 8-20: auxiliary offset
            aux_phy = (v >> 21) & 0x07  # bits 21-23: PHY for aux packet
            unit_us = 300 if offset_unit else 30
            aux_off_us = aux_off_raw * unit_us
            parsed['aux_ch'] = aux_ch
            parsed['aux_ca'] = ca
            # Protocol bit: 0 → 30µs per Aux Offset step, 1 → 300µs per step
            parsed['aux_offset_unit'] = offset_unit
            parsed['aux_phy'] = aux_phy
            parsed['aux_off'] = aux_off_us  # µs (= raw 13b × 30 or ×300 per aux_offset_unit)
            idx += 3
        
        # Parse SyncInfo (18 bytes) if present
        if parsed['SyncInfo'] and idx + 18 <= len(ext_hdr_bytes):
            sync_info = ext_hdr_bytes[idx:idx+18]
            # SyncInfo: Access Address (4 bytes) + CRCInit (3 bytes) + 
            #          WinOffset (2 bytes) + WinSize (1 byte) + Interval (2 bytes) +
            #          Channel Map (5 bytes) + Hop/SCA/RFU (1 byte)
            access_addr = sync_info[0:4]
            crc_init = sync_info[4:7]
            win_offset = sync_info[7] | (sync_info[8] << 8)
            win_size = sync_info[9]
            interval = sync_info[10] | (sync_info[11] << 8)
            channel_map = sync_info[12:17]
            hop_byte = sync_info[17]
            # Hop byte: Bits 0-2 = Hop, Bits 3-5 = SCA, Bits 6-7 = RFU
            hop = hop_byte & 0x7
            sca = (hop_byte >> 3) & 0x7
            rfu = (hop_byte >> 6) & 0x3
            
            parsed['sync_aa'] = ':'.join(f'{b:02X}' for b in reversed(access_addr))
            parsed['sync_crc'] = ':'.join(f'{b:02X}' for b in reversed(crc_init))
            parsed['sync_win_off'] = win_offset
            parsed['sync_win_sz'] = win_size
            parsed['sync_iv'] = interval
            parsed['sync_chm'] = ':'.join(f'{b:02X}' for b in channel_map)
            parsed['sync_hop'] = hop
            parsed['sync_sca'] = sca
            parsed['sync_rfu'] = rfu
            idx += 18
        
        # Parse TxPower (1 byte) if present
        if parsed['TxPwr'] and idx < len(ext_hdr_bytes):
            tx_power = ext_hdr_bytes[idx]
            # TxPower is signed 8-bit value
            if tx_power > 127:
                tx_power = tx_power - 256
            parsed['tx_power'] = tx_power
            idx += 1

    # Strip display-only noise (flags byte + substantive fields are enough for the Logic bubble)
    for _k in (
        'AdvA', 'TgtA', 'CTE', 'ADI', 'AuxPtr', 'SyncInfo', 'TxPwr', 'rfu',
        'cte_rfu',
    ):
        parsed.pop(_k, None)

    return parsed


def parse_adv_payload(pdu_type, payload_bytes):
    """
    Parse BLE 4.2 advertising packet payload according to PDU type.
    
    BLE 4.2 Advertising Channel PDU Payload Formats:
    - ADV_IND: AdvA (6 bytes) + AdvData (0-31 bytes)
    - ADV_DIR_IND: AdvA (6 bytes) + TargetA (6 bytes)
    - ADV_NONCONN_IND: AdvA (6 bytes) + AdvData (0-31 bytes)
    - ADV_SCAN_IND: AdvA (6 bytes) + AdvData (0-31 bytes)
    - SCAN_REQ: ScanA (6 bytes) + AdvA (6 bytes)
    - SCAN_RSP: AdvA (6 bytes) + AdvData (0-31 bytes)
    - CONN_IND: InitA (6 bytes) + AdvA (6 bytes) + LLData (22 bytes)
    
    Args:
        pdu_type: PDU type string (e.g., 'ADV_IND', 'SCAN_REQ')
        payload_bytes: List of payload bytes
        
    Returns:
        dict: Parsed payload fields
    """
    parsed = {}
    
    if not payload_bytes:
        return parsed
    
    # Helper function to format MAC address (little-endian)
    def format_mac_addr(bytes_list):
        if len(bytes_list) >= 6:
            return ':'.join(f'{b:02X}' for b in reversed(bytes_list[:6]))
        return None
    
    if pdu_type == 'ADV_IND':
        # ADV_IND: AdvA (6 bytes) + AdvData (0-31 bytes)
        if len(payload_bytes) >= 6:
            adv_a_bytes = payload_bytes[0:6]
            parsed['adv_a'] = format_mac_addr(adv_a_bytes)
            if len(payload_bytes) > 6:
                adv_data_bytes = payload_bytes[6:]
                parsed['adv_data'] = str(list(map(hex, adv_data_bytes)))
    
    elif pdu_type == 'ADV_DIR_IND' or pdu_type == 'ADV_DIR':
        # ADV_DIR_IND: AdvA (6 bytes) + TargetA (6 bytes)
        if len(payload_bytes) >= 6:
            adv_a_bytes = payload_bytes[0:6]
            parsed['adv_a'] = format_mac_addr(adv_a_bytes)
        if len(payload_bytes) >= 12:
            target_a_bytes = payload_bytes[6:12]
            parsed['target_a'] = format_mac_addr(target_a_bytes)
    
    elif pdu_type == 'ADV_NONCONN_IND' or pdu_type == 'NON_CONN':
        # ADV_NONCONN_IND: AdvA (6 bytes) + AdvData (0-31 bytes)
        if len(payload_bytes) >= 6:
            adv_a_bytes = payload_bytes[0:6]
            parsed['adv_a'] = format_mac_addr(adv_a_bytes)
            if len(payload_bytes) > 6:
                adv_data_bytes = payload_bytes[6:]
                parsed['adv_data'] = str(list(map(hex, adv_data_bytes)))
    
    elif pdu_type == 'ADV_SCAN_IND' or pdu_type == 'SCAN_IND':
        # ADV_SCAN_IND/SCAN_IND: AdvA (6 bytes) + AdvData (0-31 bytes)
        if len(payload_bytes) >= 6:
            adv_a_bytes = payload_bytes[0:6]
            parsed['adv_a'] = format_mac_addr(adv_a_bytes)
            if len(payload_bytes) > 6:
                adv_data_bytes = payload_bytes[6:]
                parsed['adv_data'] = str(list(map(hex, adv_data_bytes)))
    
    elif pdu_type == 'SCAN_REQ':
        # SCAN_REQ: ScanA (6 bytes) + AdvA (6 bytes)
        if len(payload_bytes) >= 6:
            scan_a_bytes = payload_bytes[0:6]
            parsed['scan_a'] = format_mac_addr(scan_a_bytes)
        if len(payload_bytes) >= 12:
            adv_a_bytes = payload_bytes[6:12]
            parsed['adv_a'] = format_mac_addr(adv_a_bytes)
    
    elif pdu_type == 'SCAN_RSP':
        # SCAN_RSP: AdvA (6 bytes) + AdvData (0-31 bytes)
        if len(payload_bytes) >= 6:
            adv_a_bytes = payload_bytes[0:6]
            parsed['adv_a'] = format_mac_addr(adv_a_bytes)
            if len(payload_bytes) > 6:
                adv_data_bytes = payload_bytes[6:]
                parsed['adv_data'] = str(list(map(hex, adv_data_bytes)))
    
    elif pdu_type == 'CONN_IND':
        # CONN_IND (connection request): InitA (6) + AdvA (6) + LLData (22); full parse below
        if len(payload_bytes) >= 6:
            init_a_bytes = payload_bytes[0:6]
            parsed['init_a'] = format_mac_addr(init_a_bytes)
        if len(payload_bytes) >= 12:
            adv_a_bytes = payload_bytes[6:12]
            parsed['adv_a'] = format_mac_addr(adv_a_bytes)
        if len(payload_bytes) >= 34:
            ll_data_bytes = payload_bytes[12:34]
            parsed['ll_data'] = str(list(map(hex, ll_data_bytes)))
            # Parse LLData fields (BLE 4.2 spec)
            # LLData: AA (4) + CRCInit (3) + WinSize (1) + WinOffset (2) + 
            #         Interval (2) + Latency (2) + Timeout (2) + ChM (5) + Hop (1)
            if len(ll_data_bytes) >= 22:
                parsed['ll_aa'] = ':'.join(f'{b:02X}' for b in reversed(ll_data_bytes[0:4]))
                parsed['ll_crc'] = ':'.join(f'{b:02X}' for b in reversed(ll_data_bytes[4:7]))
                parsed['ll_win_sz'] = ll_data_bytes[7]
                parsed['ll_win_off'] = ll_data_bytes[8] | (ll_data_bytes[9] << 8)
                parsed['ll_iv'] = ll_data_bytes[10] | (ll_data_bytes[11] << 8)
                parsed['ll_lat'] = ll_data_bytes[12] | (ll_data_bytes[13] << 8)
                parsed['ll_tmo'] = ll_data_bytes[14] | (ll_data_bytes[15] << 8)
                parsed['ll_chm'] = ':'.join(f'{b:02X}' for b in ll_data_bytes[16:21])
                parsed['ll_hop'] = ll_data_bytes[21] & 0x1F
                parsed['ll_sca'] = (ll_data_bytes[21] >> 5) & 0x7
    
    return parsed
