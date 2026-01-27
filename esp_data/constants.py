# BLE constants and type definitions

# BLE PDU types for advertising channels
PDU_TYPE = ['ADV_IND', 'ADV_DIR', 'NON_CONN', 'SCAN_REQ', 'SCAN_RSP', 'CONN_IND', 'SCAN_IND', 'EXT_ADV', 'AUX_CONN_RSP']

# ACL (Asynchronous Connection-Less) Link Layer ID types
ACL_LLID_TYPE = ['RFU', 'EMP_CONTINUE', 'START_COM', 'CONTROL']

# ISO (Isochronous) Link Layer ID types
ISO_LLID_TYPE = ['UNF_COM_END', 'UNF_START_CON', 'FRAMED_PDU', 'CTRL_PDU']

# Bit rate timing in microseconds: [1Mbps, 2Mbps, 500Kbps, 125Kbps]
BIT_RATE_TIME = [1, 0.5, 8, 2]

# Extended Advertising Mode types
EXT_ADV_MODE = ['LEGACY', 'NON_CONNECTABLE', 'SCANNABLE', 'CONNECTABLE']
