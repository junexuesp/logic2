# BLE constants and type definitions (abbreviated for Logic 2 display)

# BLE PDU types for advertising channels
PDU_TYPE = ['ADV_IND', 'ADV_DIR', 'NON_CONN', 'SCAN_REQ', 'SCAN_RSP', 'CONN_IND', 'SCAN_IND', 'EXT_ADV', 'AUX_CONN_RSP']

# ACL Link Layer ID: RFU, Empty/Continue, Start, Control
ACL_LLID_TYPE = ['RFU', 'CONT', 'START', 'CTRL']

# ISO Link Layer ID: Unframed End, Unframed Start, Framed PDU, Control PDU
ISO_LLID_TYPE = ['UNF_END', 'UNF_START', 'FRM_PDU', 'CTRL_PDU']

# Bit rate timing in microseconds: [1Mbps, 2Mbps, 500Kbps, 125Kbps]
BIT_RATE_TIME = [1, 0.5, 8, 2]

# Extended Adv Mode (CEAP): 0b00 NC+NS, 0b01 C+NS, 0b10 NC+S, 0b11 RFU
EXT_ADV_MODE = ['NC_NS', 'C_NS', 'NC_S', 'RFU']
