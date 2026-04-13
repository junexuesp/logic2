# BLE constants and type definitions (abbreviated for Logic 2 display)

# Advertising PDU Type = low nibble of first header octet (Vol 6 Part B Table 2.3, Core 5.4+ /6.x).
# Wireshark packet-btle.c: 0x8 = AUX_CONNECT_RSP (0b1000),0x9 = ADV_DECISION_IND.
PDU_TYPE = [
    'ADV_IND',            # 0x0
    'ADV_DIR',            # 0x1 ADV_DIRECT_IND
    'NON_CONN',           # 0x2 ADV_NONCONN_IND
    'SCAN_REQ',           # 0x3
    'SCAN_RSP',           # 0x4
    'CONN_IND',           # 0x5 (secondary: AUX_CONNECT_REQ)
    'SCAN_IND',           # 0x6 ADV_SCAN_IND
    'EXT_ADV',            # 0x7 ADV_EXT_IND / AUX common extended on secondary
    'AUX_CONN_RSP',       # 0x8 AUX_CONNECT_RSP
    'ADV_DECISION_IND',   # 0x9
    'RSVD_0xA',
    'RSVD_0xB',
    'RSVD_0xC',
    'RSVD_0xD',
    'RSVD_0xE',
    'RSVD_0xF',
]

# Payload begins with Common Extended Advertising Payload (ExtHdrLen + AdvMode + …)
ADV_PDU_USES_CEAP = frozenset({
    'EXT_ADV',
    'AUX_CONN_RSP',
    'ADV_DECISION_IND',
})

# ACL Link Layer ID: RFU, Empty/Continue, Start, Control
ACL_LLID_TYPE = ['RFU', 'CONT', 'START', 'CTRL']

# ISO Link Layer ID: Unframed End, Unframed Start, Framed PDU, Control PDU
ISO_LLID_TYPE = ['UNF_END', 'UNF_START', 'FRM_PDU', 'CTRL_PDU']

# Bit rate timing in microseconds: [1Mbps, 2Mbps, 125Kbps, 500Kbps]
BIT_RATE_TIME = [1, 0.5, 8, 2]

# Gap timeout: evaluated when next bit arrives (gap = current_bit.start - last_bit.end).
# WAIT_CRC: use smaller threshold so gap after payload (e.g. 40µs before next packet) triggers; PLD→CRC (~8µs) does not.
GAP_TIMEOUT_CRC_BYTE_MULTIPLIER = 3

# Extended Adv Mode (CEAP): 0b00 NC+NS, 0b01 C+NS, 0b10 NC+S, 0b11 RFU
EXT_ADV_MODE = ['NC_NS', 'C_NS', 'NC_S', 'RFU']
