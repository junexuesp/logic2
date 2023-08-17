# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# 从saleae.data模块中导入SaleaeTimeDelta类
from saleae.data import SaleaeTimeDelta

from saleae.data import GraphTime

# Import the binascii module
import binascii

# Import the time module
import time

pdutype = ['ADV_IND', 'ADV_DIR', 'NON_CONN', 'SCAN_REQ', 'CONN_IND', 'SCAN_IND', 'EXT_ADV', 'AUX_CONN_RSP']
acl_llid_type = ['RFU', 'EMP_CONTINUE', 'START_COM', 'CONTROL']
iso_llid_type = ['UNF_COM_END', 'UNF_START_CON', 'FRAMED_PDU', 'CTRL_PDU']
byte_rate_time = [8, 4, 64, 16]
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
        self.analyze_st = "WAIT_S0"
        self.rate = 0
        self.frame_len = 0

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
            self.analyze_st = "WAIT_PLD"
    # API to process timeout frames
    def process_state(self, frame: AnalyzerFrame):
        delta_st = self.delat_to_ns(frame.end_time, frame.start_time)
        #means bit duration error
        if delta_st > 8000:
            self.bit_time_error = 1
        elif delta_st < 400 and self.count != 7:
            self.bit_time_error = 2
        else:
            self.bit_time_error = 0
            if self.count == 0:
                self.frame_start_time = frame.start_time
                if delta_st < 4000:
                    self.rate = 1
                elif delta_st <8000:
                    self.rate = 0
                elif delta_st < 16000:
                    self.rate = 3
                else:
                    self.rate = 2
    # API to return frame type info
    def get_frame_type(self):
        if self.analyze_st == "WAIT_S0":
            frame_type = 's0'
        elif self.analyze_st == "WAIT_LEN":
            frame_type = 'len'
        else:
            frame_type = 'pld'
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
    # API to display timeout byte             
    def show_byte_tmo(self, frame: AnalyzerFrame):
        frame_type = self.get_frame_type()
        deltass = SaleaeTimeDelta(microsecond=byte_rate_time[self.rate])
        end_time_f = self.frame_start_time + deltass
        # Create a new output frame with the same start and end time as the last input frame
        new_frame = AnalyzerFrame(frame_type, self.frame_start_time, end_time_f, {
            'data': "byte"
        })

        if self.analyze_st == "WAIT_S0":
            self.set_s0_fields(new_frame)
        # Convert the self.byte variable to a byte object
        byte_data = bytes([self.byte])
        # Add the self.byte variable as the data field of the output frame
        new_frame.data['data'] = byte_data
        # Reset the self.byte and self.count variables to 0
        self.byte = 0
        self.count = 0
        # Means a new frame
        self.analyze_st = "WAIT_S0"
        return new_frame

    # show byte frame
    def show_byte(self, frame: AnalyzerFrame):
        frame_type = self.get_frame_type()
        # Create a new output frame with the same start and end time as the last input frame
        new_frame = AnalyzerFrame(frame_type, self.frame_start_time, frame.end_time, {
            'data': "byte"
        })

        if self.analyze_st == "WAIT_S0":
            self.set_s0_fields(new_frame)
        # Convert the self.byte variable to a byte object
        byte_data = bytes([self.byte])
        # Add the self.byte variable as the data field of the output frame
        new_frame.data['data'] = byte_data
        #update state machine
        self.analyze_state_change()
        # Reset the self.byte and self.count variables to 0
        self.byte = 0
        self.count = 0
        return new_frame

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        self.process_state(frame)

        # Get the data from the input frame
        data = frame.data['data']
        byte_timeout = 0
        # if bit time duration error
        if self.bit_time_error == 1:
            return self.show_byte_tmo(frame)
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
            new_frame = self.show_byte(frame)
            # Return the output frame to Logic 2 software
            return new_frame
