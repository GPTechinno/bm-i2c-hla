# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from distutils import core
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting
from time import gmtime, strftime

apw_types = {
    # 2: "something", # no payload
    # 3: "something", # no payload
    # 4: "something", # no payload
    # 6: "get_something", # read payload n bytes
    131: "set_voltage", # read payload 2 bytes with Voltage value
    # 134: "set_something", # write payload 1+n bytes, read payload[1] should be == 0x01
}

pic_types = {
    2: "write_app", # write payload 16 bytes with chunck of app
    6: "jump_app",
    7: "init",
    9: "erase_app",
    16: "set_something_3", # write payload 3 bytes with only first byte significant value, other 0x00
    21: "power_switch", # write payload 1 byte
    22: "heart_beat", # read payload 2 bytes
    23: "get_fw_version", # read payload 1 bytes with PIC FW Version
    40: "get_something_9", # read payload 9 bytes with 1 byte (not significant ?) then 4 u16 values
    41: "get_voltage", # read payload 5 bytes with Voltage value
    43: "get_something_5", # read payload 5 bytes with 1 byte (not significant ?) then 3 u16 values (no checksum ?)
    49: "set_something_1", # write payload 1 byte with some value
}

def get_type(dev: str, code: int) -> str:
    """Get the type by code."""
    try:
        if dev == "APW":
            return apw_types[code]
        elif dev == "dsPIC":
            return pic_types[code]
        else:
            return "unknown"
    except KeyError:
        return "unknown"

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    """Bitmain I2C High Level Analyzer."""

    bm_device = ChoicesSetting(['APW', 'dsPIC'], label='Device')

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'write_app': {
            'format': 'Write App checksum={{data.checksum}}'
        },
        'jump_app': {
            'format': 'Jump App checksum={{data.checksum}}'
        },
        'init': {
            'format': 'Init checksum={{data.checksum}}'
        },
        'erase_app': {
            'format': 'Erase App checksum={{data.checksum}}'
        },
        'set_something_3': {
            'format': 'Set Something3 val={{data.payload}} checksum={{data.checksum}}'
        },
        'set_something_3_resp': {
            'format': 'Set Something3 checksum={{data.checksum}}'
        },
        'power_switch': {
            'format': 'Power Switch {{data.payload}} checksum={{data.checksum}}'
        },
        'power_switch_resp': {
            'format': 'Power Switch checksum={{data.checksum}}'
        },
        'heart_beat': {
            'format': 'HeartBeat checksum={{data.checksum}}'
        },
        'get_fw_version': {
            'format': 'Get FW Version checksum={{data.checksum}}'
        },
        'get_fw_version_resp': {
            'format': 'Get FW Version version={{data.payload}} checksum={{data.checksum}}'
        },
        'get_something_9': {
            'format': 'Get Something9 checksum={{data.checksum}}'
        },
        'get_something_9_resp': {
            'format': 'Get Something9 val={{data.payload}} checksum={{data.checksum}}'
        },
        'get_voltage': {
            'format': 'Get Voltage checksum={{data.checksum}}'
        },
        'get_voltage_resp': {
            'format': 'Get Voltage voltage={{data.payload}} checksum={{data.checksum}}'
        },
        'get_something_5': {
            'format': 'Get Something5 checksum={{data.checksum}}'
        },
        'get_something_5_resp': {
            'format': 'Get Something5 val={{data.payload}} checksum?={{data.checksum}}'
        },
        'set_something_1': {
            'format': 'Set Something1 val={{data.payload}} checksum={{data.checksum}}'
        },
        'set_something_1_resp': {
            'format': 'Set Something1 checksum={{data.checksum}}'
        },
        'set_voltage': {
            'format': 'Set Voltage voltage={{data.payload}} checksum={{data.checksum}}'
        },
        'unknown': {
            'format': 'Code: {{data.code}} checksum={{data.checksum}}'
        }
    }

    def __init__(self):
        # current byte position
        self._byte_pos: int = 0
        self._start_of_transaction = None
        self._start_of_frame = self._start_of_transaction
        self._end_of_frame = None
        self._read: bool = False
        self._last_read: bool = True
        self._for_us: bool = False
        self._preamble_offset: int = 0
        # current frame length
        self._frame_len: int = 99
        # current frame type
        self._code: int = 99
        self._type: str = ""
        # current frame payload
        self._payload = bytearray(b'')
        # current frame checksum
        self._checksum_read: int = 0
        self._checksum_calc: int = 0

    def decode(self, frame: AnalyzerFrame):
        if 'error' in frame.data:
            print("BM I2C: ", frame.data['error'])
            return
        if frame.type == 'start':
            self._start_of_transaction = frame.start_time
            if self._byte_pos == 0:
                self._start_of_frame = frame.start_time
        elif frame.type == 'address':
            expected_addr = 0x10 if self.bm_device == "APW" else 0x20 if self.bm_device == "dsPIC" else 0xFF
            if frame.data['address'][0] == expected_addr:
                self._for_us = True
            else:
                self._for_us = False
                # print(f"not for us : i2c@0x{frame.data['address'][0]:02X}")
                return
            self._read = frame.data['read']
            if self._read and self.bm_device == "dsPIC": # APW response include preamble
                self._preamble_offset = 0
            else:
                self._preamble_offset = 2
        elif frame.type == 'data':
            if not self._for_us:
                return
            raw = frame.data['data'][0]
            # check preamble if any
            if self._byte_pos == 0:
                if self._preamble_offset == 2:
                    if raw != 0x55:
                        print(f"BM I2C: malformed command, preamble[0]=0x{raw:02X}, expected 0x55")
                    return
            elif self._byte_pos == 1:
                if self._preamble_offset == 2:
                    if raw != 0xAA:
                        print(f"BM I2C: malformed command, preamble[1]=0x{raw:02X}, expected 0xAA")
                    return
            # accumulate bytes in checksum
            if self._byte_pos >= 0 + self._preamble_offset and self._byte_pos < self._frame_len - 2 + self._preamble_offset:
                self._checksum_calc += raw
            # parse data
            if self._byte_pos == 0 + self._preamble_offset:
                self._frame_len = raw
            elif self._byte_pos == 1 + self._preamble_offset:
                if raw == 1:
                    # short frame
                    self._code = self._frame_len
                    self._frame_len = 2
                else:
                    self._code = raw
                self._type = get_type(self.bm_device ,self._code)
            elif self._byte_pos == self._frame_len - 2 + self._preamble_offset:
                if self.bm_device == "APW" and self._read: # APW response checksum is LE
                    self._checksum_read = raw
                else:
                    self._checksum_read = raw << 8
            elif self._byte_pos == self._frame_len - 1 + self._preamble_offset:
                if self.bm_device == "APW" and self._read: # APW response checksum is LE
                    self._checksum_read += raw << 8
                else:
                    self._checksum_read += raw
            elif self._byte_pos >= 2 + self._preamble_offset:
                self._payload.append(raw)
        elif frame.type == 'stop':
            if not self._for_us:
                return
            self._end_of_frame = frame.end_time
            self._last_read = self._read
            if self._byte_pos == self._frame_len - 1 + self._preamble_offset:
                # last byte of frame
                analyzer_frame_type = self._type
                if self._read and (self._type == "set_something_3" or self._type == "power_switch" or self._type == "get_voltage" or self._type == "get_something_9" or self._type == "get_fw_version" or self._type == "get_something_5" or self._type == "set_something_1"):
                    analyzer_frame_type += "_resp"
                start_of_frame = self._start_of_frame
                end_of_frame = self._end_of_frame
                read = self._last_read
                frame_len = self._frame_len
                code = self._code
                payload = ''.join(format(x, '02x') for x in self._payload) if len(self._payload) > 0 else "None"
                if self._read and self._type == "get_fw_version":
                    payload = f"{self._payload[0]}"
                elif not self._read and self._type == "power_switch":
                    if self._payload[0] == 0:
                        payload = "OFF"
                    else:
                        payload = "ON"
                elif self._read and self._type == "get_voltage":
                    volt = ((self._payload[1] * 256) + self._payload[2]) * 3.3 * 0.000244140625 * 7.599999904632568
                    payload = f"{volt:10.3f}V"
                elif self._type == "set_voltage":
                    volt = ((self._payload[0] * 256) + self._payload[1]) * 3.3 * 0.000244140625 * 7.599999904632568 # not sure yet
                    payload = f"{volt:10.3f}V"
                checksum = "None" if self._checksum_read == 0 else "OK" if self._checksum_read == self._checksum_calc else "KO"
                # init vars
                self._byte_pos = 0
                self._frame_len = 99
                self._payload = bytearray(b'')
                self._checksum_read = 0
                self._checksum_calc = 0
                self._start_of_frame = self._start_of_transaction
                # Return the data frame itself
                return AnalyzerFrame(analyzer_frame_type, start_of_frame, end_of_frame, {
                    'direction': "response" if read else "request",
                    'len': f"{frame_len}",
                    'code': f"{code}",
                    'payload': payload,
                    'checksum': checksum
                })
            else:
                self._byte_pos += 1
