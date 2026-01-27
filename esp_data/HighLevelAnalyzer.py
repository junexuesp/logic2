# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# Import SaleaeTimeDelta for time calculations
from saleae.data import SaleaeTimeDelta

# BLE PDU types for advertising channels
pdutype = ['ADV_IND', 'ADV_DIR', 'NON_CONN', 'SCAN_REQ', 'SCAN_RSP', 'CONN_IND', 'SCAN_IND', 'EXT_ADV', 'AUX_CONN_RSP']

# ACL (Asynchronous Connection-Less) Link Layer ID types
acl_llid_type = ['RFU', 'EMP_CONTINUE', 'START_COM', 'CONTROL']

# ISO (Isochronous) Link Layer ID types
iso_llid_type = ['UNF_COM_END', 'UNF_START_CON', 'FRAMED_PDU', 'CTRL_PDU']

# Bit rate timing in microseconds: [1Mbps, 2Mbps, 500Kbps, 125Kbps]
bit_rate_time = [1, 0.5, 8, 2]

# Extended Advertising Mode types
ext_adv_mode = ['LEGACY', 'NON_CONNECTABLE', 'SCANNABLE', 'CONNECTABLE']
# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_string_setting = StringSetting()
    my_number_setting = NumberSetting(min_value=0, max_value=255)
    my_choices_setting = ChoicesSetting(choices=("ACL", "CIS", "BIS", "ADV"))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
        }
    }

    def __init__(self):
        """
        Initialize the High Level Analyzer.
        
        Initializes all state variables for BLE frame parsing:
        - State machine starts in WAIT_S0 (waiting for frame header)
        - Bit assembly variables (byte, count) start at 0
        - Frame timing and payload buffers are initialized
        
        Settings can be accessed using the same name used above.
        """
        self.bit_time_error = 0  # 0=no error, 1=too long, 2=too short
        self.byte = 0  # Accumulated byte value (8 bits)
        self.count = 0  # Number of bits accumulated in current byte
        self.frame_start_time = 0  # Start time of current frame
        self.pld_frame_start_time = 0  # Start time of payload section
        self.analyze_st = "WAIT_S0"  # Current state machine state
        self.rate = 0  # Detected bit rate index (0=1Mbps, 1=2Mbps, 2=500Kbps, 3=125Kbps)
        self.frame_len = 0  # Total length of payload
        self.frame_len_remain = 0  # Remaining bytes to receive
        self.pld = []  # Payload data buffer
        self.pdu_type = None  # Current PDU type (for EXT_ADV detection)
        self.ext_hdr_len = 0  # Extended header length for EXT_ADV
        self.ext_hdr_remain = 0  # Remaining extended header bytes
        self.ext_hdr_data = []  # Extended header data buffer
        self.ext_hdr_flags = 0  # Extended header flags
        self.ext_hdr_parsed = False  # Whether extended header has been parsed

        print("Settings:", self.my_string_setting,
              self.my_number_setting, self.my_choices_setting, self.frame_start_time)
    def delta_to_ns(self, t_end, t_start):
        """
        Convert frame delta time to nanoseconds.
        
        Args:
            t_end: End time of the frame
            t_start: Start time of the frame
            
        Returns:
            int: Duration in nanoseconds
        """
        duration_delta = t_end - t_start
        duration_delta_ns = float(duration_delta * 1000000000)
        return int(duration_delta_ns)
    def analyze_state_change(self):
        """
        Update the state machine to the next state after processing a byte.
        
        State transitions:
        - WAIT_S0 -> WAIT_LEN: After receiving frame header (S0)
        - WAIT_LEN -> WAIT_CEAP or WAIT_PLD or WAIT_CRC: After receiving length byte
          - If EXT_ADV: go to WAIT_CEAP to parse Common Extended Advertising Payload
          - If length is 0, skip payload and go to WAIT_CRC
          - Otherwise: go to WAIT_PLD
        - WAIT_CEAP -> WAIT_EXT_HDR or WAIT_PLD: After parsing CEAP header
          - If Extended Header Length > 0: go to WAIT_EXT_HDR
          - Otherwise: go to WAIT_PLD
        - WAIT_EXT_HDR -> WAIT_PLD: After receiving all extended header bytes
        - WAIT_PLD -> WAIT_CRC: After receiving all payload bytes
        - WAIT_CRC -> WAIT_S0: After receiving CRC, ready for next frame
        """
        if self.analyze_st == "WAIT_S0":
            self.analyze_st = "WAIT_LEN"
        elif self.analyze_st == "WAIT_LEN":
            self.frame_len = self.byte
            self.frame_len_remain = self.byte
            if self.frame_len == 0:
                # Empty payload, skip directly to CRC
                self.frame_len = 3
                self.frame_len_remain = 3
                self.analyze_st = "WAIT_CRC"
            elif self.pdu_type == "EXT_ADV":
                # EXT_ADV requires parsing Common Extended Advertising Payload first
                self.analyze_st = "WAIT_CEAP"
            else:
                self.analyze_st = "WAIT_PLD"
        elif self.analyze_st == "WAIT_CEAP":
            # CEAP header parsed, check if extended header exists
            if self.ext_hdr_len > 0:
                self.ext_hdr_remain = self.ext_hdr_len
                self.analyze_st = "WAIT_EXT_HDR"
            else:
                # No extended header, go directly to payload
                self.analyze_st = "WAIT_PLD"
        elif self.analyze_st == "WAIT_EXT_HDR":
            # Extended header complete, now parse payload
            self.analyze_st = "WAIT_PLD"
        elif self.analyze_st == "WAIT_PLD":
            # Payload complete, now expect 3 bytes of CRC
            self.frame_len = 3
            self.frame_len_remain = 3
            self.analyze_st = "WAIT_CRC"
        else:
            # WAIT_CRC complete, reset to wait for next frame
            self.analyze_st = "WAIT_S0"
            self.pdu_type = None  # Reset PDU type
            self.ext_hdr_len = 0
            self.ext_hdr_remain = 0
            self.ext_hdr_data = []
            self.ext_hdr_flags = 0
            self.ext_hdr_parsed = False
    def process_state(self, frame: AnalyzerFrame):
        """
        Process frame state and detect bit rate and timing errors.
        
        Detects the bit rate based on bit duration:
        - < 500ns: 2Mbps (rate=1)
        - < 1000ns: 1Mbps (rate=0)
        - < 2000ns: 125Kbps (rate=3)
        - >= 2000ns: 500Kbps (rate=2)
        
        Also detects bit timing errors:
        - Error type 1: Bit duration > 8000ns (too long)
        - Error type 2: Bit duration < 200ns and not the last bit (too short)
        
        Args:
            frame: Input analyzer frame containing bit data
        """
        delta_st = self.delta_to_ns(frame.end_time, frame.start_time)
        # Initialize the frame start time and detect bit rate on first bit
        if self.frame_start_time == 0:
            self.frame_start_time = frame.start_time
            # Detect bit rate based on bit duration (in nanoseconds)
            if delta_st < 500:
                self.rate = 1  # 2Mbps
            elif delta_st < 1000:
                self.rate = 0  # 1Mbps
            elif delta_st < 2000:
                self.rate = 3  # 125Kbps
            else:
                self.rate = 2  # 500Kbps
        
        # Detect bit duration errors
        if delta_st > 8000:
            # Error type 1: Bit duration too long (possible frame gap or error)
            self.bit_time_error = 1
        elif delta_st < 200 and self.count != 7:
            # Error type 2: Bit duration too short (except for the last bit)
            self.bit_time_error = 2
        else:
            self.bit_time_error = 0
    def get_frame_type(self):
        """
        Get the frame type string based on current state.
        
        Returns:
            str: Frame type ('s0', 'len', 'ceap', 'ext_hdr', 'pld', or 'crc')
        """
        if self.analyze_st == "WAIT_S0":
            frame_type = 's0'
        elif self.analyze_st == "WAIT_LEN":
            frame_type = 'len'
        elif self.analyze_st == "WAIT_CEAP":
            frame_type = 'ceap'
        elif self.analyze_st == "WAIT_EXT_HDR":
            frame_type = 'ext_hdr'
        elif self.analyze_st == "WAIT_PLD":
            frame_type = 'pld'
        else:
            frame_type = 'crc'
        return frame_type
    def set_s0_fields(self, new_frame: AnalyzerFrame):
        """
        Parse and set S0 (first byte) fields based on link type.
        
        The S0 byte contains different fields depending on the link type:
        - ACL: Link Layer ID, NESN, SN, MD, CP, RFU
        - CIS: Link Layer ID, NESN, SN, CIE, RFU, NPI
        - ADV: PDU Type, RFU, ChSel, TxAdd, RxAdd
        - BIS: Link Layer ID, CSSN, CSTF, RFU
        
        Args:
            new_frame: AnalyzerFrame to populate with parsed fields
        """
        if self.my_choices_setting == "ACL":
            # ACL (Asynchronous Connection-Less) link type
            new_frame.data['llid'] = acl_llid_type[self.byte & 3]  # Bits 0-1: LLID
            new_frame.data['nesn'] = (self.byte >> 2) & 1  # Bit 2: Next Expected Sequence Number
            new_frame.data['sn'] = (self.byte >> 3) & 1  # Bit 3: Sequence Number
            new_frame.data['md'] = (self.byte >> 4) & 1  # Bit 4: More Data
            new_frame.data['cp'] = (self.byte >> 5) & 1  # Bit 5: Control PDU
            new_frame.data['rfu'] = (self.byte >> 6) & 1  # Bit 6: Reserved for Future Use
        elif self.my_choices_setting == "CIS":
            # CIS (Connected Isochronous Stream) link type
            new_frame.data['llid'] = iso_llid_type[self.byte & 3]  # Bits 0-1: LLID
            new_frame.data['nesn'] = (self.byte >> 2) & 1  # Bit 2: Next Expected Sequence Number
            new_frame.data['sn'] = (self.byte >> 3) & 1  # Bit 3: Sequence Number
            new_frame.data['cie'] = (self.byte >> 4) & 1  # Bit 4: CIS Event
            new_frame.data['rfu'] = (self.byte >> 5) & 1  # Bit 5: Reserved for Future Use
            new_frame.data['npi'] = (self.byte >> 6) & 1  # Bit 6: NSE Payload Indicator
            new_frame.data['rfu'] = (self.byte >> 7) & 1  # Bit 7: Reserved for Future Use
        elif self.my_choices_setting == "ADV":
            # ADV (Advertising) link type
            pdu_type_idx = self.byte & 0x7  # Bits 0-2: PDU Type
            new_frame.data['pdu_type'] = pdutype[pdu_type_idx]
            # Save PDU type for EXT_ADV special handling
            self.pdu_type = pdutype[pdu_type_idx]
            new_frame.data['rfu'] = (self.byte >> 4) & 1  # Bit 4: Reserved for Future Use
            new_frame.data['chsel'] = (self.byte >> 5) & 1  # Bit 5: Channel Selection
            new_frame.data['TxAdd'] = (self.byte >> 6) & 1  # Bit 6: Transmit Address
            new_frame.data['RxAdd'] = (self.byte >> 7) & 1  # Bit 7: Receive Address
        else:
            # BIS (Broadcast Isochronous Stream) link type
            new_frame.data['llid'] = iso_llid_type[self.byte & 3]  # Bits 0-1: LLID
            new_frame.data['cssn'] = (self.byte >> 2) & 7  # Bits 2-4: CIS Subevent Sequence Number
            new_frame.data['cstf'] = (self.byte >> 5) & 1  # Bit 5: CIS Subevent Time Flag
            new_frame.data['rfu'] = (self.byte >> 6) & 3  # Bits 6-7: Reserved for Future Use

    def set_ceap_fields(self, new_frame: AnalyzerFrame):
        """
        Parse and set Common Extended Advertising Payload (CEAP) header fields.
        
        The CEAP header (1 byte) contains:
        - Extended Header Length (6 bits, bits 0-5): Length of extended header (0-63 bytes)
        - AdvMode (2 bits, bits 6-7): Advertising mode
        
        Args:
            new_frame: AnalyzerFrame to populate with parsed fields
        """
        self.ext_hdr_len = self.byte & 0x3F  # Bits 0-5: Extended Header Length (0-63 bytes)
        adv_mode_idx = (self.byte >> 6) & 0x3  # Bits 6-7: Advertising Mode
        new_frame.data['ext_hdr_len'] = self.ext_hdr_len
        new_frame.data['adv_mode'] = ext_adv_mode[adv_mode_idx]
        # Adjust remaining payload length (CEAP header is part of payload)
        if self.frame_len_remain > 0:
            self.frame_len_remain -= 1

    def parse_extended_header(self, ext_hdr_bytes):
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
        - ADI (2 bytes): Advertising Data Indication (if Flags bit 3 set)
        - AuxPtr (3 bytes): Auxiliary Pointer (if Flags bit 4 set)
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
            parsed['adv_a_present'] = (flags & 0x01) != 0  # Bit 0
            parsed['target_a_present'] = (flags & 0x02) != 0  # Bit 1
            parsed['cte_info_present'] = (flags & 0x04) != 0  # Bit 2
            parsed['adi_present'] = (flags & 0x08) != 0  # Bit 3
            parsed['aux_ptr_present'] = (flags & 0x10) != 0  # Bit 4
            parsed['sync_info_present'] = (flags & 0x20) != 0  # Bit 5
            parsed['tx_power_present'] = (flags & 0x40) != 0  # Bit 6
            parsed['rfu'] = (flags >> 7) & 0x1  # Bit 7
            idx += 1
            
            # Parse AdvA (6 bytes) if present
            if parsed['adv_a_present'] and idx + 6 <= len(ext_hdr_bytes):
                adv_a_bytes = ext_hdr_bytes[idx:idx+6]
                # Convert to little-endian MAC address format
                adv_a_str = ':'.join(f'{b:02X}' for b in reversed(adv_a_bytes))
                parsed['adv_a'] = adv_a_str
                idx += 6
            
            # Parse TargetA (6 bytes) if present
            if parsed['target_a_present'] and idx + 6 <= len(ext_hdr_bytes):
                target_a_bytes = ext_hdr_bytes[idx:idx+6]
                target_a_str = ':'.join(f'{b:02X}' for b in reversed(target_a_bytes))
                parsed['target_a'] = target_a_str
                idx += 6
            
            # Parse CTEInfo (1 byte) if present
            if parsed['cte_info_present'] and idx < len(ext_hdr_bytes):
                cte_info_byte = ext_hdr_bytes[idx]
                # CTEInfo: Bits 0-4 = CTE Length, Bit 5 = RFU, Bits 6-7 = CTE Type
                cte_length = cte_info_byte & 0x1F  # Bits 0-4
                cte_rfu = (cte_info_byte >> 5) & 0x1  # Bit 5
                cte_type = (cte_info_byte >> 6) & 0x3  # Bits 6-7
                parsed['cte_info'] = {
                    'cte_length': cte_length,
                    'cte_rfu': cte_rfu,
                    'cte_type': cte_type
                }
                idx += 1
            
            # Parse ADI (2 bytes) if present
            if parsed['adi_present'] and idx + 2 <= len(ext_hdr_bytes):
                adi_bytes = ext_hdr_bytes[idx:idx+2]
                # ADI: Advertising Data Indication (2 bytes)
                adi = adi_bytes[0] | (adi_bytes[1] << 8)
                parsed['adi'] = adi
                idx += 2
            
            # Parse AuxPtr (3 bytes) if present
            if parsed['aux_ptr_present'] and idx + 3 <= len(ext_hdr_bytes):
                aux_ptr = ext_hdr_bytes[idx:idx+3]
                # AuxPtr: Channel Index (1 byte) + CA (1 byte) + Offset (1 byte)
                channel_idx = aux_ptr[0]
                ca = aux_ptr[1]
                offset = aux_ptr[2]
                parsed['aux_ptr'] = {
                    'channel_idx': channel_idx,
                    'ca': ca,
                    'offset': offset
                }
                idx += 3
            
            # Parse SyncInfo (18 bytes) if present
            if parsed['sync_info_present'] and idx + 18 <= len(ext_hdr_bytes):
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
                
                parsed['sync_info'] = {
                    'access_addr': ':'.join(f'{b:02X}' for b in reversed(access_addr)),
                    'crc_init': ':'.join(f'{b:02X}' for b in reversed(crc_init)),
                    'win_offset': win_offset,
                    'win_size': win_size,
                    'interval': interval,
                    'channel_map': ':'.join(f'{b:02X}' for b in channel_map),
                    'hop': hop,
                    'sca': sca,
                    'rfu': rfu
                }
                idx += 18
            
            # Parse TxPower (1 byte) if present
            if parsed['tx_power_present'] and idx < len(ext_hdr_bytes):
                tx_power = ext_hdr_bytes[idx]
                # TxPower is signed 8-bit value
                if tx_power > 127:
                    tx_power = tx_power - 256
                parsed['tx_power'] = tx_power
                idx += 1
        
        return parsed

    def show_byte(self, frame: AnalyzerFrame, tmo):
        """
        Create and return an output frame for the current byte.
        
        Handles different frame types:
        - S0/LEN: Single byte frames with parsed fields
        - PLD/CRC: Multi-byte frames containing payload or CRC data
        
        Args:
            frame: Input analyzer frame
            tmo: Timeout flag (1 if timeout occurred, 0 otherwise)
            
        Returns:
            AnalyzerFrame or None: Output frame if ready, None if waiting for more bytes
        """
        # Convert the byte to a bytes object
        byte_data = bytes([self.byte])
        show_frame = 0
        new_frame = None
        
        if self.analyze_st == "WAIT_PLD" or self.analyze_st == "WAIT_CRC":
            # Collect payload or CRC bytes
            self.pld.append(self.byte)
            if self.frame_len != 0:
                # Track payload frame start time (first byte of actual payload data)
                # For EXT_ADV, this is after CEAP and extended header
                if self.frame_len_remain == self.frame_len:
                    self.pld_frame_start_time = self.frame_start_time
                self.frame_len_remain -= 1
                # Show frame when all bytes received or on timeout
                if self.frame_len_remain == 0 or tmo == 1:
                    show_frame = 1
                else:
                    # Reset and wait for more bytes
                    self.byte = 0
                    self.count = 0
                    self.frame_start_time = 0
                    return None
            else:
                show_frame = 1
                self.pld_frame_start_time = self.frame_start_time
        elif self.analyze_st == "WAIT_EXT_HDR":
            # Collect extended header bytes
            if self.ext_hdr_remain == self.ext_hdr_len:
                # First byte of extended header, track start time
                self.pld_frame_start_time = self.frame_start_time
                self.ext_hdr_data = []  # Initialize extended header buffer
            self.ext_hdr_data.append(self.byte)
            self.pld.append(self.byte)  # Also keep in pld for display
            self.ext_hdr_remain -= 1
            self.frame_len_remain -= 1
            # Show frame when all extended header bytes received or on timeout
            if self.ext_hdr_remain == 0 or tmo == 1:
                show_frame = 1
            else:
                # Reset and wait for more bytes
                self.byte = 0
                self.count = 0
                self.frame_start_time = 0
                return None
        else:
            # S0, LEN, or CEAP: show immediately
            show_frame = 1
        
        # Calculate end time (adjust for timeout if needed)
        end_time_f = frame.end_time
        if tmo == 1:
            # Use expected bit duration for timeout cases
            delta_time = SaleaeTimeDelta(microsecond=bit_rate_time[self.rate])
            end_time_f = frame.start_time + delta_time
        
        if show_frame == 1:
            frame_type = self.get_frame_type()
            if self.analyze_st == "WAIT_PLD" or self.analyze_st == "WAIT_CRC":
                # Create frame for payload or CRC data
                pld_hex = list(map(hex, self.pld))
                new_frame = AnalyzerFrame(frame_type, self.pld_frame_start_time, end_time_f, {
                    'data': str(pld_hex)
                })
                # Clear payload buffer and reset frame length
                self.pld.clear()
                self.frame_len = 0
                self.frame_len_remain = 0
            elif self.analyze_st == "WAIT_EXT_HDR":
                # Parse extended header fields
                ext_hdr_parsed = self.parse_extended_header(self.ext_hdr_data)
                # Create frame for extended header data with parsed fields
                ext_hdr_hex = list(map(hex, self.ext_hdr_data))
                frame_data = {
                    'data': str(ext_hdr_hex),
                    'ext_hdr': True
                }
                # Add parsed fields to frame data
                frame_data.update(ext_hdr_parsed)
                new_frame = AnalyzerFrame(frame_type, self.pld_frame_start_time, end_time_f, frame_data)
                # Clear extended header from payload buffer
                self.pld.clear()
                self.ext_hdr_data = []
                self.ext_hdr_parsed = True
            else:
                # Create frame for S0, LEN, or CEAP byte
                new_frame = AnalyzerFrame(frame_type, self.frame_start_time, end_time_f, {
                    'data': "byte"
                })
                if self.analyze_st == "WAIT_S0":
                    # Parse S0 fields based on link type
                    self.set_s0_fields(new_frame)
                elif self.analyze_st == "WAIT_CEAP":
                    # Parse CEAP header fields for EXT_ADV
                    self.set_ceap_fields(new_frame)
                new_frame.data['data'] = byte_data
            
            # Update state machine to next state
            self.analyze_state_change()
        
        # Reset byte assembly state
        self.byte = 0
        self.count = 0
        self.frame_start_time = 0
        
        # Reset to initial state on timeout
        if tmo == 1:
            self.analyze_st = "WAIT_S0"
            self.pdu_type = None
            self.ext_hdr_len = 0
            self.ext_hdr_remain = 0
            self.ext_hdr_data = []
            self.ext_hdr_flags = 0
            self.ext_hdr_parsed = False
        
        return new_frame

    def decode(self, frame: AnalyzerFrame):
        """
        Process a frame from the input analyzer and decode BLE data.
        
        This is the main entry point called by Logic 2 for each input frame.
        It assembles bits into bytes (8 bits per byte) and processes complete bytes
        according to the BLE frame structure.
        
        Args:
            frame: Input analyzer frame containing bit data
            
        Returns:
            AnalyzerFrame or None: Output frame when a complete byte is processed,
                                  None when waiting for more bits
        """
        # Process frame state (detect bit rate, timing errors)
        self.process_state(frame)

        # Get the bit data from the input frame
        data = frame.data['data']
        
        # Handle bit timing errors
        if self.bit_time_error == 1:
            # Error type 1: Bit duration too long - force complete current byte
            # Shift bit into position and OR with accumulated byte
            data = data << self.count
            self.byte = self.byte | data
            self.count = self.count + 1
            # Force output with timeout flag
            return self.show_byte(frame, 1)
        elif self.bit_time_error == 2:
            # Error type 2: Bit duration too short - discard this bit
            return None
        
        # Normal processing: accumulate bits into byte
        # Shift bit into position based on current bit count
        data = data << self.count
        # OR the bit into the accumulated byte
        self.byte = self.byte | data
        # Increment bit counter
        self.count = self.count + 1
        
        # Check if we have received 8 bits (complete byte)
        if self.count == 8:
            new_frame = self.show_byte(frame, 0)
            # Return the output frame to Logic 2 software
            return new_frame
        
        # Not enough bits yet, return None to wait for more
        return None

