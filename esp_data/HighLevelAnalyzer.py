# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# Import SaleaeTimeDelta for time calculations
from saleae.data import SaleaeTimeDelta

# Import constants and parsers
from constants import PDU_TYPE, BIT_RATE_TIME
from parsers import adv_parser, acl_parser, cis_parser, bis_parser
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
        self.last_bit_end_time = 0  # End time of previous bit (for gap-based timeout, e.g. CRC after PLD stop)

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
        
        Also detects bit timing errors and gap timeout:
        - Error type 1: Bit duration or gap > one byte time at current bit rate (timeout)
        - Error type 2: Bit duration < 200ns and not the last bit (too short)
        
        Args:
            frame: Input analyzer frame containing bit data
        """
        delta_st = self.delta_to_ns(frame.end_time, frame.start_time)
        # Initialize the frame start time and detect bit rate on first bit (needed for byte_time_ns)
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
        # One byte time at current bit rate (ns): 8 bits * BIT_RATE_TIME[rate] µs/bit
        byte_time_ns = int(8 * BIT_RATE_TIME[self.rate] * 1000)
        # Gap-based timeout: after PLD we enter WAIT_CRC; if no data for > one byte time, reset to WAIT_S0.
        # When the next bit arrives, gap from last bit (e.g. last PLD bit) > byte_time_ns → timeout.
        if self.last_bit_end_time != 0:
            gap_ns = self.delta_to_ns(frame.start_time, self.last_bit_end_time)
            if gap_ns > byte_time_ns:
                self.bit_time_error = 1  # Will call show_byte(1) and reset to WAIT_S0
        self.last_bit_end_time = frame.end_time
        # Detect bit duration errors (only if gap didn't already set timeout)
        if self.bit_time_error != 1 and delta_st > byte_time_ns:
            # Error type 1: Current bit duration > one byte time (gap or error)
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
            parsed = acl_parser.parse_s0_acl(self.byte)
            new_frame.data.update(parsed)
        elif self.my_choices_setting == "CIS":
            parsed = cis_parser.parse_s0_cis(self.byte)
            new_frame.data.update(parsed)
        elif self.my_choices_setting == "ADV":
            parsed = adv_parser.parse_s0_adv(self.byte)
            new_frame.data.update(parsed)
            # Save PDU type for EXT_ADV special handling
            self.pdu_type = parsed['pdu_type']
        else:  # BIS
            parsed = bis_parser.parse_s0_bis(self.byte)
            new_frame.data.update(parsed)

    def set_ceap_fields(self, new_frame: AnalyzerFrame):
        """
        Parse and set Common Extended Advertising Payload (CEAP) header fields.
        
        The CEAP header (1 byte) contains:
        - Extended Header Length (6 bits, bits 0-5): Length of extended header (0-63 bytes)
        - AdvMode (2 bits, bits 6-7): Advertising mode
        
        Args:
            new_frame: AnalyzerFrame to populate with parsed fields
        """
        parsed, ext_hdr_len, new_frame_len_remain = adv_parser.parse_ceap_fields(
            self.byte, self.frame_len_remain
        )
        new_frame.data.update(parsed)
        self.ext_hdr_len = ext_hdr_len
        self.frame_len_remain = new_frame_len_remain

    def parse_extended_header(self, ext_hdr_bytes):
        """
        Parse Extended Header fields based on flags (BLE 6.0 specification).
        
        Delegates to adv_parser module.
        
        Args:
            ext_hdr_bytes: List of bytes in the extended header
            
        Returns:
            dict: Parsed extended header fields
        """
        return adv_parser.parse_extended_header(ext_hdr_bytes)

    def parse_adv_payload(self, pdu_type, payload_bytes):
        """
        Parse BLE 4.2 advertising packet payload according to PDU type.
        
        Delegates to adv_parser module.
        
        Args:
            pdu_type: PDU type string (e.g., 'ADV_IND', 'SCAN_REQ')
            payload_bytes: List of payload bytes
            
        Returns:
            dict: Parsed payload fields
        """
        return adv_parser.parse_adv_payload(pdu_type, payload_bytes)

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
        
        # WAIT_CRC timeout: after PLD, if no data for > one byte time → reset to WAIT_S0 (gap > byte_time_ns in decode sets tmo=1)
        if self.analyze_st == "WAIT_CRC" and len(self.pld) == 0:
            if tmo == 1:
                # Timeout: current bit belongs to next packet. Output incomplete CRC (0 bytes), reset to WAIT_S0, keep byte/count so next packet's first byte aligns.
                end_time_f = frame.start_time + SaleaeTimeDelta(microsecond=BIT_RATE_TIME[self.rate])
                frame_data = {'data': '[]', 'incomplete': True, 'expected_bytes': 3, 'received_bytes': 0}
                new_frame = AnalyzerFrame('crc', self.pld_frame_start_time, end_time_f, frame_data)
                self.pld.clear()
                self.frame_len = 0
                self.frame_len_remain = 0
                self.analyze_st = "WAIT_S0"
                self.pdu_type = None
                self.ext_hdr_len = 0
                self.ext_hdr_remain = 0
                self.ext_hdr_data = []
                self.ext_hdr_flags = 0
                self.ext_hdr_parsed = False
                self.last_bit_end_time = 0
                # Do NOT reset self.byte, self.count - next bits complete the first byte of next packet
                return new_frame
            else:
                # Full byte received - this is S0 of next packet (no CRC was sent). Output S0 frame.
                end_time_f = frame.end_time
                new_frame = AnalyzerFrame('s0', self.frame_start_time, end_time_f, {'data': "byte"})
                self.set_s0_fields(new_frame)
                new_frame.data['data'] = byte_data
                self.pld.clear()
                self.frame_len = 0
                self.frame_len_remain = 0
                self.analyze_st = "WAIT_S0"
                self.analyze_state_change()  # WAIT_S0 -> WAIT_LEN
                self.byte = 0
                self.count = 0
                self.frame_start_time = 0
                return new_frame
        
        if self.analyze_st == "WAIT_PLD" or self.analyze_st == "WAIT_CRC":
            # Collect payload or CRC bytes (CRC: 3 bytes; timeout if gap > one byte time at current bit rate)
            # Track payload frame start time (first byte of actual payload data).
            # For EXT_ADV we come from WAIT_EXT_HDR so frame_len_remain != frame_len;
            # use "first byte in pld for this section" (len(pld)==0) so pld begin time
            # is after the previous ext_hdr frame and Logic 2 validation passes.
            if len(self.pld) == 0:
                self.pld_frame_start_time = self.frame_start_time
            self.pld.append(self.byte)
            if self.frame_len != 0:
                self.frame_len_remain -= 1
                # Show frame when all bytes received or on timeout
                # On timeout, always show what we have collected so far
                if self.frame_len_remain == 0 or tmo == 1:
                    show_frame = 1
                else:
                    # Reset and wait for more bytes
                    self.byte = 0
                    self.count = 0
                    self.frame_start_time = 0
                    return None
            else:
                # frame_len == 0 case (shouldn't happen normally, but handle it)
                show_frame = 1
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
            # On timeout, always show what we have collected so far
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
            # These are single-byte fields, so they're always complete when we reach here
            show_frame = 1
            # If timeout occurred, mark as potentially incomplete (though for single bytes this is rare)
            if tmo == 1:
                # For single-byte fields, timeout usually means the byte was forced to complete
                # but we can still mark it if needed
                pass
        
        # Calculate end time (adjust for timeout if needed)
        end_time_f = frame.end_time
        if tmo == 1:
            # Use expected bit duration for timeout cases
            delta_time = SaleaeTimeDelta(microsecond=BIT_RATE_TIME[self.rate])
            end_time_f = frame.start_time + delta_time
        
        if show_frame == 1:
            frame_type = self.get_frame_type()
            if self.analyze_st == "WAIT_PLD" or self.analyze_st == "WAIT_CRC":
                # Create frame for payload or CRC data
                pld_hex = list(map(hex, self.pld))
                frame_data = {
                    'data': str(pld_hex)
                }
                
                # Mark as incomplete if timeout occurred and data is not complete
                if tmo == 1 and self.frame_len_remain > 0:
                    frame_data['incomplete'] = True
                    frame_data['expected_bytes'] = self.frame_len
                    frame_data['received_bytes'] = len(self.pld)
                
                # Parse payload according to BLE 4.2 spec if PDU type is known and we're in ADV mode
                # Only parse when payload is complete (frame_type is 'pld' and all payload bytes received)
                if (self.my_choices_setting == "ADV" and self.pdu_type and 
                    frame_type == 'pld' and len(self.pld) > 0):
                    # frame_len_remain == 0 means all payload bytes have been received
                    # (it was decremented after adding the last byte to self.pld)
                    # Only parse if payload is complete (not timed out or all bytes received)
                    if self.frame_len_remain == 0:
                        payload_parsed = self.parse_adv_payload(self.pdu_type, self.pld)
                        frame_data.update(payload_parsed)
                
                new_frame = AnalyzerFrame(frame_type, self.pld_frame_start_time, end_time_f, frame_data)
                # Clear payload buffer and reset frame length
                self.pld.clear()
                self.frame_len = 0
                self.frame_len_remain = 0
            elif self.analyze_st == "WAIT_EXT_HDR":
                # Parse extended header fields (even if incomplete due to timeout)
                ext_hdr_parsed = self.parse_extended_header(self.ext_hdr_data)
                # Create frame for extended header data with parsed fields
                ext_hdr_hex = list(map(hex, self.ext_hdr_data))
                frame_data = {
                    'data': str(ext_hdr_hex),
                    'ext_hdr': True
                }
                # Mark as incomplete if timeout occurred and extended header is not complete
                if tmo == 1 and self.ext_hdr_remain > 0:
                    frame_data['incomplete'] = True
                    frame_data['expected_bytes'] = self.ext_hdr_len
                    frame_data['received_bytes'] = len(self.ext_hdr_data)
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
        
        # Reset to WAIT_S0 on timeout: after PLD→WAIT_CRC, no data for > one byte time → state machine reset to WAIT_S0
        if tmo == 1:
            self.analyze_st = "WAIT_S0"
            self.pdu_type = None
            self.ext_hdr_len = 0
            self.ext_hdr_remain = 0
            self.ext_hdr_data = []
            self.ext_hdr_flags = 0
            self.ext_hdr_parsed = False
            self.last_bit_end_time = 0  # So next packet doesn't falsely trigger gap timeout
        
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

