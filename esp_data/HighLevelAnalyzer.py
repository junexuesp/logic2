# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# 从saleae.data模块中导入SaleaeTimeDelta类
from saleae.data import SaleaeTime, SaleaeTimeDelta

from saleae.data import GraphTime

# Import the binascii module
import binascii

# Import the time module
import time

pdutype = ['ADV_IND', 'ADV_DIR', 'NON_CONN', 'SCAN_REQ', 'SCAN_RSP', 'CONN_IND', 'SCAN_IND', 'EXT_ADV', 'AUX_CONN_RSP']
acl_llid_type = ['RFU', 'EMP_CONTINUE', 'START_COM', 'CONTROL']
iso_llid_type = ['UNF_COM_END', 'UNF_START_CON', 'FRAMED_PDU', 'CTRL_PDU']
bit_rate_time = [1, 0.5, 8, 2]
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
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.bit_time_error = 0
        self.byte = 0
        self.count = 0
        self.frame_start_time = 0
        self.pld_frame_start_time = 0
        self.analyze_st = "WAIT_S0"
        self.rate = 0
        self.frame_len = 0
        self.frame_len_remain = 0
        self.pld = []

        print("Settings:", self.my_string_setting,
              self.my_number_setting, self.my_choices_setting, self.frame_start_time)
    # API to convert frame delta time to nano seconds
    def delat_to_ns(self, t_end, t_start):
        duration_delta = t_end - t_start
        duration_delta_ns = float(duration_delta*1000000000)
        return int(duration_delta_ns)
    # API to set state
    def analyze_state_change(self):
        if self.analyze_st == "WAIT_S0":
            self.analyze_st = "WAIT_LEN"
        elif self.analyze_st == "WAIT_LEN":
            self.frame_len = self.byte
            self.frame_len_remain  = self.byte
            if self.frame_len == 0:
                self.frame_len = 3
                self.frame_len_remain  = 3
                self.analyze_st = "WAIT_CRC"
            else:
                self.analyze_st = "WAIT_PLD"
        elif self.analyze_st == "WAIT_PLD":
            self.frame_len = 3
            self.frame_len_remain  = 3
            self.analyze_st = "WAIT_CRC"
        else:
            self.analyze_st = "WAIT_S0"
    # API to process timeout frames
    def process_state(self, frame: AnalyzerFrame):
        delta_st = self.delat_to_ns(frame.end_time, frame.start_time)
        #init the frame start time
        if self.frame_start_time == 0:
            self.frame_start_time = frame.start_time
            # self.frame_start_time = frame.start_time
            if delta_st < 500:
                self.rate = 1
            elif delta_st <1000:
                self.rate = 0
            elif delta_st < 2000:
                self.rate = 3
            else:
                self.rate = 2
        #means bit duration error
        if delta_st > 8000:
            self.bit_time_error = 1
        elif delta_st < 200 and self.count != 7:
            self.bit_time_error = 2
        else:
            self.bit_time_error = 0
    # API to return frame type info
    def get_frame_type(self):
        if self.analyze_st == "WAIT_S0":
            frame_type = 's0'
        elif self.analyze_st == "WAIT_LEN":
            frame_type = 'len'
        elif self.analyze_st == "WAIT_PLD":
            frame_type = 'pld'
        else:
            frame_type = 'crc'
        return frame_type
    # API to set s0 fields
    def set_s0_fields(self, new_frame: AnalyzerFrame):
        if self.my_choices_setting == "ACL":
            new_frame.data['llid'] = acl_llid_type[self.byte&3]
            new_frame.data['nesn'] = (self.byte>>2)&1
            new_frame.data['sn'] = (self.byte>>3)&1
            new_frame.data['md'] = (self.byte>>4)&1
            new_frame.data['cp'] = (self.byte>>5)&1
            new_frame.data['rfu'] = (self.byte>>6)&1
        elif self.my_choices_setting == "CIS":
            new_frame.data['llid'] = iso_llid_type[self.byte&3]
            new_frame.data['nesn'] = (self.byte>>2)&1
            new_frame.data['sn'] = (self.byte>>3)&1
            new_frame.data['cie'] = (self.byte>>4)&1
            new_frame.data['rfu'] = (self.byte>>5)&1
            new_frame.data['npi'] = (self.byte>>6)&1
            new_frame.data['rfu'] = (self.byte>>7)&1
        elif self.my_choices_setting == "ADV":
            new_frame.data['pdu_type'] = pdutype[self.byte&0x7]
            new_frame.data['rfu'] = (self.byte>>4)&1
            new_frame.data['chsel'] = (self.byte>>5)&1
            new_frame.data['TxAdd'] = (self.byte>>6)&1
            new_frame.data['RxAdd'] = (self.byte>>7)&1
        else:
            new_frame.data['llid'] = iso_llid_type[self.byte&3]
            new_frame.data['cssn'] = (self.byte>>2)&7
            new_frame.data['cstf'] = (self.byte>>5)&1
            new_frame.data['rfu'] = (self.byte>>6)&3

    # show byte frame
    def show_byte(self, frame: AnalyzerFrame, tmo):
        # Convert the self.byte variable to a byte object
        byte_data = bytes([self.byte])
        show_frame = 0
        new_frame = 0
        if self.analyze_st == "WAIT_PLD" or self.analyze_st == "WAIT_CRC":
            self.pld.append(self.byte)
            # print("***:",self.pld)
            if self.frame_len != 0:
                if self.frame_len_remain == self.frame_len:
                    self.pld_frame_start_time = self.frame_start_time
                self.frame_len_remain -= 1
                if self.frame_len_remain == 0 or tmo == 1:
                    show_frame = 1
                else:
                    self.byte = 0
                    self.count = 0
                    self.frame_start_time = 0
                    return
            else:
                show_frame = 1
                self.pld_frame_start_time = self.frame_start_time
        else:
            show_frame = 1
        end_time_f = frame.end_time
        if tmo == 1:
            deltass = SaleaeTimeDelta(microsecond=bit_rate_time[self.rate])
            end_time_f = frame.start_time + deltass
        if show_frame == 1:
            frame_type = self.get_frame_type()
            if self.analyze_st == "WAIT_PLD" or self.analyze_st == "WAIT_CRC":
                pld_hex = list(map(hex, self.pld))
                # Create a new output frame with the same start and end time as the last input frame
                new_frame = AnalyzerFrame(frame_type, self.pld_frame_start_time, end_time_f, {
                    'data': str(pld_hex)
                })
                
                # Add the self.byte variable as the data field of the output frame
                # new_frame.data['data'] = str(pld_hex)
                # print("hex:",str(pld_hex))
                self.pld.clear()
                self.frame_len = 0
                self.frame_len_remain = 0
            else:
                # Create a new output frame with the same start and end time as the last input frame
                # print("start: , end: ,", self.frame_start_time, end_time_f, self.count)
                new_frame = AnalyzerFrame(frame_type, self.frame_start_time, end_time_f, {
                    'data': "byte"
                })
                if self.analyze_st == "WAIT_S0":
                    self.set_s0_fields(new_frame)
                # Add the self.byte variable as the data field of the output frame
                new_frame.data['data'] = byte_data
            #update state machine
            self.analyze_state_change()
        # Reset the self.byte and self.count variables to 0
        self.byte = 0
        self.count = 0
        self.frame_start_time = 0
        if tmo == 1:
            self.analyze_st = "WAIT_S0"
        return new_frame

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        self.process_state(frame)

        # Get the data from the input frame
        data = frame.data['data']
        # if bit time duration error
        if self.bit_time_error == 1:
            # Shift the self.byte variable to the left by one bit
            data = data << self.count
            # Or the self.byte variable with the data
            self.byte = self.byte | data
            # Increment the self.count variable by one
            self.count = self.count + 1
            return self.show_byte(frame, 1)
        elif self.bit_time_error == 2:
            return
        # Shift the self.byte variable to the left by one bit
        data = data << self.count
        # Or the self.byte variable with the data
        self.byte = self.byte | data
        # Increment the self.count variable by one
        self.count = self.count + 1
        # Check if we have received 8 input frames
        if self.count == 8:
            new_frame = self.show_byte(frame, 0)
            # Return the output frame to Logic 2 software
            return new_frame
