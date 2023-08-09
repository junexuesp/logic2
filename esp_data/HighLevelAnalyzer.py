# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
# Import the SaleaeTime type
from saleae.data.timing import SaleaeTime

# Import the binascii module
import binascii

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
        self.byte = 0
        self.count = 0
        self.start_time = 0
        self.end_time = 0
        self.analyze_st = 0
        self.byte_period = 0
        self.sn = 0
        self.nesn = 0
        self.llid = 0
        self.md_cie = 0
        self.cp_rfu = 0
        self.rfu_npi = 0


        print("Settings:", self.my_string_setting,
              self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        if self.count == 0:
            self.start_time = frame.start_time
        
       
        if self.byte_period == 0:
            # Means a new frame
            self.analyze_st = 1
        else:
             # Determine whether its a new frame
            delta_st = frame.start_time - self.end_time
            if delta_st > self.byte_period:
            # Means a new frame
                self.analyze_st = 1

        # Get the data from the input frame
        data = frame.data['data']

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


        # Check if we have received 8 input frames
        if self.count == 8:
            self.end_time = frame.end_time
            if self.analyze_st == 1:
                frame_type = 's0:'
                self.byte_period = self.end_time - self.start_time
                self.analyze_st = 2
            elif self.analyze_st == 2:
                self.analyze_st = 3
                frame_type = 'len:'
            else:
                frame_type = 'pld:'
            
            end_time_f = self.end_time
            
            if self.end_time - self.start_time > self.byte_period + self.byte_period:
                end_time_f = self.start_time + self.byte_period
                # Means a new frame
                self.analyze_st = 1
            # Create a new output frame with the same start and end time as the last input frame
            
            new_frame = AnalyzerFrame(frame_type, self.start_time, end_time_f, {
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
            # Return the output frame to Logic 2 software
            return new_frame
