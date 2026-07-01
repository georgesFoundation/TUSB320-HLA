from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, NumberSetting


TUSB320_DEFAULT_ADDRESS = 0x61

REGISTERS = {
    0x00: "DeviceId0",
    0x01: "DeviceId1",
    0x02: "DeviceId2",
    0x03: "DeviceId3",
    0x04: "DeviceId4",
    0x05: "DeviceId5",
    0x06: "DeviceId6",
    0x07: "DeviceId7",
    0x08: "CurrentModeDetectAdvertise",
    0x09: "StateDirInterruptStatus",
    0x0A: "DebounceModeSelectReset",
}

EXPECTED_CHIP_ID = [0x30, 0x32, 0x33, 0x42, 0x53, 0x55, 0x54, 0x00]

ACCESSORY_CONNECTED = {
    0b000: "None",
    0b001: "AudioAccessory",
    0b010: "DebugAccessory",
    0b011: "AccessoryReserved3",
    0b100: "AccessoryReserved4",
    0b101: "AccessoryReserved5",
    0b110: "AccessoryReserved6",
    0b111: "AccessoryReserved7",
}

CURRENT_MODE = {
    0b00: "DefaultUsbCurrent",
    0b01: "MediumCurrent",
    0b10: "HighCurrent",
    0b11: "CurrentReserved",
}

CURRENT_ADVERTISE = {
    0b00: "DefaultUsbCurrent",
    0b01: "MediumCurrent",
    0b10: "HighCurrent",
    0b11: "AdvertiseReserved",
}

MODE_SELECT = {
    0b00: "Port",
    0b01: "UFP",
    0b10: "DFP",
    0b11: "DRP",
}

ATTACHED_STATE = {
    0b00: "NotAttached",
    0b01: "AttachedSrc",
    0b10: "AttachedSnk",
    0b11: "AttachedAccessory",
}

DRP_DUTY_CYCLE = {
    0b00: "Default",
    0b01: "DutyCycle1",
    0b10: "DutyCycle2",
    0b11: "DutyCycle3",
}

DEBOUNCE = {
    0b00: "Default",
    0b01: "Debounce1",
    0b10: "Debounce2",
    0b11: "Debounce3",
}


def reg_name(register):
    return REGISTERS.get(register, "Reg0x%02X" % register)


def bit_value(value, bit_num):
    return bool(value & (1 << bit_num))


def field(value, hi, lo):
    mask = (1 << (hi - lo + 1)) - 1
    return (value >> lo) & mask


def bytes_hex(data):
    return " ".join("0x%02X" % byte for byte in data)


def on_off(value):
    return "1" if value else "0"


def ascii_byte(value):
    if 0x20 <= value <= 0x7E:
        return "'%s'" % chr(value)
    if value == 0:
        return "NUL"
    return "."


def decode_current_mode_detect_advertise(value):
    accessory = field(value, 3, 1)
    current_detect = field(value, 5, 4)
    current_advertise = field(value, 7, 6)
    return (
        "0x%02X active_cable=%s accessory=%s current_detect=%s current_advertise=%s"
        % (
            value,
            on_off(bit_value(value, 0)),
            ACCESSORY_CONNECTED[accessory],
            CURRENT_MODE[current_detect],
            CURRENT_ADVERTISE[current_advertise],
        )
    )


def decode_state_dir_interrupt_status(value):
    drp_duty = field(value, 2, 1)
    attached = field(value, 7, 6)
    return (
        "0x%02X drp_duty=%s interrupt=%s cable_dir=%s attached=%s"
        % (
            value,
            DRP_DUTY_CYCLE[drp_duty],
            on_off(bit_value(value, 4)),
            "CC2" if bit_value(value, 5) else "CC1",
            ATTACHED_STATE[attached],
        )
    )


def decode_debounce_mode_select_reset(value):
    mode = field(value, 5, 4)
    debounce = field(value, 7, 6)
    return (
        "0x%02X soft_reset=%s mode_select=%s debounce=%s"
        % (
            value,
            on_off(bit_value(value, 3)),
            MODE_SELECT[mode],
            DEBOUNCE[debounce],
        )
    )


def format_value(register, value):
    if 0x00 <= register <= 0x07:
        expected = EXPECTED_CHIP_ID[register]
        suffix = " expected" if value == expected else " expected 0x%02X" % expected
        return "0x%02X %s%s" % (value, ascii_byte(value), suffix)
    if register == 0x08:
        return decode_current_mode_detect_advertise(value)
    if register == 0x09:
        return decode_state_dir_interrupt_status(value)
    if register == 0x0A:
        return decode_debounce_mode_select_reset(value)
    return "0x%02X" % value


class TUSB320Analyzer(HighLevelAnalyzer):
    i2c_address = NumberSetting(min_value=0, max_value=0x7F)

    result_types = {
        "read": {"format": "{{data.summary}}"},
        "write": {"format": "{{data.summary}}"},
        "select": {"format": "{{data.summary}}"},
        "error": {"format": "{{data.summary}}"},
    }

    def __init__(self):
        self._address = int(self.i2c_address)
        if self._address == 0:
            self._address = TUSB320_DEFAULT_ADDRESS
        self._reset_transaction()

    def _reset_transaction(self):
        self._transaction_start = None
        self._segments = []
        self._current_segment = None

    def decode(self, frame):
        if frame.type == "start":
            if self._transaction_start is None:
                self._transaction_start = frame.start_time
            return None

        if frame.type == "address":
            if self._transaction_start is None:
                self._transaction_start = frame.start_time

            address = self._value_byte(frame.data.get("address"))
            read = bool(frame.data.get("read", False))
            self._current_segment = {"address": address, "read": read, "data": []}
            self._segments.append(self._current_segment)
            return None

        if frame.type == "data":
            if self._current_segment is not None:
                self._current_segment["data"].append(self._value_byte(frame.data.get("data")))
            return None

        if frame.type == "stop":
            result = self._decode_transaction(frame.end_time)
            self._reset_transaction()
            return result

        return None

    def _value_byte(self, value):
        if isinstance(value, (bytes, bytearray, list, tuple)):
            return int(value[0])
        return int(value)

    def _decode_transaction(self, end_time):
        segments = [segment for segment in self._segments if segment["address"] == self._address]
        if not segments:
            return None

        start_time = self._transaction_start
        if start_time is None:
            start_time = end_time

        if len(segments) == 1:
            return self._decode_single_segment(segments[0], start_time, end_time)

        if len(segments) == 2 and not segments[0]["read"] and segments[1]["read"]:
            return self._decode_write_read(segments[0], segments[1], start_time, end_time)

        summary = "TUSB320 unsupported transaction: " + self._segments_summary(segments)
        return AnalyzerFrame("error", start_time, end_time, {"summary": summary})

    def _decode_single_segment(self, segment, start_time, end_time):
        data = segment["data"]
        if segment["read"]:
            summary = "TUSB320 read without register pointer: %s" % bytes_hex(data)
            return AnalyzerFrame("error", start_time, end_time, {"summary": summary})

        if len(data) == 1:
            summary = "TUSB320 select %s (0x%02X)" % (reg_name(data[0]), data[0])
            return AnalyzerFrame("select", start_time, end_time, {"summary": summary})

        register = data[0]
        payload = data[1:]

        if len(payload) == 1:
            value = payload[0]
            summary = "TUSB320 write %s (0x%02X) = %s" % (
                reg_name(register),
                register,
                format_value(register, value),
            )
            return AnalyzerFrame("write", start_time, end_time, {"summary": summary})

        summary = "TUSB320 write %s (0x%02X) = %s" % (reg_name(register), register, bytes_hex(payload))
        return AnalyzerFrame("write", start_time, end_time, {"summary": summary})

    def _decode_write_read(self, write_segment, read_segment, start_time, end_time):
        pointer = write_segment["data"]
        data = read_segment["data"]

        if len(pointer) != 1:
            summary = "TUSB320 read with unexpected pointer bytes: %s -> %s" % (
                bytes_hex(pointer),
                bytes_hex(data),
            )
            return AnalyzerFrame("error", start_time, end_time, {"summary": summary})

        register = pointer[0]
        if len(data) == 1:
            value = data[0]
            summary = "TUSB320 read %s (0x%02X) = %s" % (
                reg_name(register),
                register,
                format_value(register, value),
            )
            return AnalyzerFrame("read", start_time, end_time, {"summary": summary})

        if 0x00 <= register <= 0x07 and len(data) == 8:
            expected = data == EXPECTED_CHIP_ID
            text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in data)
            summary = "TUSB320 read chip id = %s \"%s\" %s" % (
                bytes_hex(data),
                text,
                "OK" if expected else "unexpected",
            )
            return AnalyzerFrame("read", start_time, end_time, {"summary": summary})

        summary = "TUSB320 read %s (0x%02X) = %s" % (reg_name(register), register, bytes_hex(data))
        return AnalyzerFrame("read", start_time, end_time, {"summary": summary})

    def _segments_summary(self, segments):
        parts = []
        for segment in segments:
            direction = "R" if segment["read"] else "W"
            parts.append("%s %s" % (direction, bytes_hex(segment["data"])))
        return "; ".join(parts)
