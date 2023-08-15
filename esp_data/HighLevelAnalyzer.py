# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
# Import the SaleaeTime type
from saleae.data.timing import SaleaeTime

# 从saleae.data模块中导入SaleaeTimeDelta类
from saleae.data import SaleaeTimeDelta

# Import the binascii module
import binascii

# Import the time module
import time

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_string_setting = StringSetting()
    my_number_setting = NumberSetting(min_value=0, max_value=255)
    my_choices_setting = ChoicesSetting(choices=('A', 'B'))

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
        self.end_time = 0
        self.byte_start_time_ns = 0
        self.analyze_st = 1
        self.byte_period_ns = 0
        self.sn = 0
        self.nesn = 0
        self.llid = 0
        self.md_cie = 0
        self.cp_rfu = 0
        self.rfu_npi = 0


        print("Settings:", self.my_string_setting,
              self.my_number_setting, self.my_choices_setting)
    def delat_to_ns(self, t_end, t_start):
        duration_delta = t_end - t_start
        duration_delta_ns = float(duration_delta*1000000000)
        return int(duration_delta_ns)

    def process_state(self, frame: AnalyzerFrame):
        delta_st = self.delat_to_ns(frame.end_time, frame.start_time)
        #means bit duration error
        if delta_st > 8000:
            self.bit_time_error = 1
        elif delta_st < 400:
            self.bit_time_error = 2
        else:
            self.bit_time_error = 0
            if self.count == 0:
                self.frame_start_time = frame.start_time
                self.byte_period_ns = delta_st*8
                
    def show_byte_tmo(self, frame: AnalyzerFrame):
        self.end_time = frame.end_time
        if self.analyze_st == 1:
            frame_type = 's0:'
            self.analyze_st = 2
        elif self.analyze_st == 2:
            self.analyze_st = 3
            frame_type = 'len:'
        else:
            frame_type = 'pld:'
        
        end_time_f = self.frame_start_time + SaleaeTimeDelta(second = 0, millisecond=0.01)
        # Create a new output frame with the same start and end time as the last input frame
        new_frame = AnalyzerFrame(frame_type, self.frame_start_time, end_time_f, {
            'data': "byte"
        })

        if self.analyze_st == 2:
            new_frame.data['llid'] = self.llid
            new_frame.data['nesn'] = self.nesn
            new_frame.data['sn'] = self.sn
            new_frame.data['md_cie'] = self.md_cie
            new_frame.data['cp_rfu'] = self.cp_rfu
            new_frame.data['npi_rfu'] = self.rfu_npi
        # Convert the self.byte variable to a byte object
        byte_data = bytes([self.byte])
        # Add the self.byte variable as the data field of the output frame
        new_frame.data['data'] = byte_data
        # Reset the self.byte and self.count variables to 0
        self.byte = 0
        self.count = 0
        self.byte_start_time_ns = 0
        # Means a new frame
        self.analyze_st = 1
        # self.byte_period_ns = 0
        return new_frame

    def show_byte(self, frame: AnalyzerFrame):
        self.end_time = frame.end_time
        if self.analyze_st == 1:
            frame_type = 's0:'
            self.analyze_st = 2
        elif self.analyze_st == 2:
            self.analyze_st = 3
            frame_type = 'len:'
        else:
            frame_type = 'pld:'
        # Create a new output frame with the same start and end time as the last input frame
        new_frame = AnalyzerFrame(frame_type, self.frame_start_time, frame.end_time, {
            'data': "byte"
        })

        if self.analyze_st == 2:
            new_frame.data['llid'] = self.llid
            new_frame.data['nesn'] = self.nesn
            new_frame.data['sn'] = self.sn
            new_frame.data['md_cie'] = self.md_cie
            new_frame.data['cp_rfu'] = self.cp_rfu
            new_frame.data['npi_rfu'] = self.rfu_npi
        # Convert the self.byte variable to a byte object
        byte_data = bytes([self.byte])
        # Add the self.byte variable as the data field of the output frame
        new_frame.data['data'] = byte_data
        # Reset the self.byte and self.count variables to 0
        self.byte = 0
        self.count = 0
        self.byte_start_time_ns = 0
        # self.byte_period_ns = 0
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

        if self.analyze_st == 1 and self.count == 2:
            self.llid = self.byte
        elif self.analyze_st == 1 and self.count == 3:
            self.nesn = frame.data['data']
        elif self.analyze_st == 1 and self.count == 4:
            self.sn = frame.data['data']
        elif self.analyze_st == 1 and self.count == 5:
            self.md_cie = frame.data['data']
        elif self.analyze_st == 1 and self.count == 6:
            self.cp_rfu = frame.data['data']  
        elif self.analyze_st == 1 and self.count == 7:
            self.rfu_npi = frame.data['data']  

        # if byte_timeout == 1:
            # return new_frame
        # Check if we have received 8 input frames
        if self.count == 8:
            new_frame = self.show_byte(frame)
            # Return the output frame to Logic 2 software
            return new_frame
