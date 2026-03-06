# ICSForge BACnet/IP payload builder
# Real BVLC + NPDU + APDU framing per ASHRAE 135-2020
# UDP port 47808 (0xBAC0)
import random
import struct

from .common import marker_bytes


# ── BVLC (BACnet Virtual Link Control) ───────────────────────────────
# Type 0x81 = BACnet/IP (Annex J)
BVLC_TYPE = 0x81

# BVLC Functions (Annex J.2)
BVLC_ORIGINAL_UNICAST = 0x0A
BVLC_ORIGINAL_BROADCAST = 0x0B
BVLC_FORWARDED_NPDU = 0x04
BVLC_REGISTER_FD = 0x05  # Register Foreign Device
BVLC_DISTRIBUTE_BROADCAST = 0x09

# ── NPDU (Network Protocol Data Unit) ────────────────────────────────
# Version always 0x01 (ASHRAE 135-2020 §6.2.1)
NPDU_VERSION = 0x01

# NPDU Control flags (§6.2.2)
NPDU_CTRL_NO_APDU = 0x00       # Message contains APDU, no network-layer message
NPDU_CTRL_EXPECTING_REPLY = 0x04
NPDU_CTRL_PRIORITY_NORMAL = 0x00
NPDU_CTRL_PRIORITY_URGENT = 0x01
NPDU_CTRL_PRIORITY_CRITICAL = 0x02
NPDU_CTRL_PRIORITY_LIFE_SAFETY = 0x03

# NPDU Network-layer message types (§6.2.4) — when bit5 of control is set
NPDU_MSG_WHO_IS_ROUTER = 0x00
NPDU_MSG_I_AM_ROUTER = 0x01
NPDU_MSG_REJECT_ROUTER = 0x03

# ── APDU types (§20.1.2) ─────────────────────────────────────────────
APDU_CONFIRMED_REQ = 0x00      # BACnet-Confirmed-Request-PDU
APDU_UNCONFIRMED_REQ = 0x10    # BACnet-Unconfirmed-Request-PDU
APDU_SIMPLE_ACK = 0x20
APDU_COMPLEX_ACK = 0x30
APDU_ERROR = 0x50

# ── Confirmed Service Choices (§21) ──────────────────────────────────
SVC_READ_PROPERTY = 12
SVC_READ_PROPERTY_MULTIPLE = 14
SVC_WRITE_PROPERTY = 15
SVC_WRITE_PROPERTY_MULTIPLE = 16
SVC_SUBSCRIBE_COV = 5
SVC_SUBSCRIBE_COV_PROPERTY = 28
SVC_ATOMIC_READ_FILE = 6
SVC_ATOMIC_WRITE_FILE = 7
SVC_REINITIALIZE_DEVICE = 20
SVC_DEVICE_COMMUNICATION_CONTROL = 17
SVC_CONFIRMED_PRIVATE_TRANSFER = 18
SVC_CREATE_OBJECT = 10
SVC_DELETE_OBJECT = 11
SVC_ADD_LIST_ELEMENT = 8
SVC_REMOVE_LIST_ELEMENT = 9

# ── Unconfirmed Service Choices (§22) ─────────────────────────────────
SVC_I_AM = 0
SVC_I_HAVE = 1
SVC_WHO_IS = 8
SVC_WHO_HAS = 7
SVC_UNCONFIRMED_PRIVATE_TRANSFER = 4
SVC_TIME_SYNCHRONIZATION = 6
SVC_UTC_TIME_SYNCHRONIZATION = 9

# ── Object Types (§23.2) ─────────────────────────────────────────────
OBJ_ANALOG_INPUT = 0
OBJ_ANALOG_OUTPUT = 1
OBJ_ANALOG_VALUE = 2
OBJ_BINARY_INPUT = 3
OBJ_BINARY_OUTPUT = 4
OBJ_BINARY_VALUE = 5
OBJ_DEVICE = 8
OBJ_FILE = 10
OBJ_SCHEDULE = 17
OBJ_NOTIFICATION_CLASS = 15
OBJ_PROGRAM = 16

# ── Property Identifiers (§23.3, commonly used) ──────────────────────
PROP_PRESENT_VALUE = 85
PROP_OBJECT_NAME = 77
PROP_DESCRIPTION = 28
PROP_DEVICE_TYPE = 31
PROP_FIRMWARE_REVISION = 44
PROP_MODEL_NAME = 70
PROP_VENDOR_NAME = 121
PROP_VENDOR_ID = 120
PROP_PROTOCOL_VERSION = 98
PROP_OBJECT_LIST = 76
PROP_SYSTEM_STATUS = 112
PROP_MAX_APDU_LENGTH = 62
PROP_SEGMENTATION_SUPPORTED = 107
PROP_APDU_TIMEOUT = 11


# ── Encoding helpers ──────────────────────────────────────────────────

def _bvlc_header(function: int, npdu_len: int) -> bytes:
    """BVLC header: Type(1) + Function(1) + Length(2). Length includes header."""
    total = 4 + npdu_len
    return struct.pack(">BBH", BVLC_TYPE, function, total)


def _npdu(control: int = NPDU_CTRL_EXPECTING_REPLY) -> bytes:
    """Minimal NPDU: Version(1) + Control(1). No DNET/SNET for local segment."""
    return struct.pack("BB", NPDU_VERSION, control)


def _context_tag(tag_number: int, value: bytes) -> bytes:
    """BACnet context-tagged value (§20.2.1.3.2)."""
    length = len(value)
    if length <= 4:
        return bytes([(tag_number << 4) | 0x08 | length]) + value
    else:
        return bytes([(tag_number << 4) | 0x0D, length]) + value


def _opening_tag(tag_number: int) -> bytes:
    return bytes([(tag_number << 4) | 0x0E])


def _closing_tag(tag_number: int) -> bytes:
    return bytes([(tag_number << 4) | 0x0F])


def _object_identifier(obj_type: int, instance: int) -> bytes:
    """Encode BACnet Object Identifier (4 bytes): type(10 bits) + instance(22 bits)."""
    val = ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)
    return struct.pack(">I", val)


def _unsigned(value: int) -> bytes:
    """Encode unsigned integer in minimum bytes."""
    if value < 0x100:
        return struct.pack("B", value)
    elif value < 0x10000:
        return struct.pack(">H", value)
    else:
        return struct.pack(">I", value)


# ── Payload builder ───────────────────────────────────────────────────

def build_payload(marker: str, style: str = "who_is", **kwargs) -> bytes:
    """
    Build BACnet/IP frame (BVLC + NPDU + APDU).

    Styles:
      who_is               Unconfirmed Who-Is broadcast — T0840 Network Connection Enumeration
      i_am                 Unconfirmed I-Am (fake device announcement) — T0849 Masquerading
      read_property        Confirmed ReadProperty — T0801 Monitor Process State / T0882
      read_property_multi  Confirmed ReadPropertyMultiple — T0802 Automated Collection
      write_property       Confirmed WriteProperty — T0855 Unauthorized Command / T0831
      write_property_multi Confirmed WritePropertyMultiple — T0836 Modify Parameter
      subscribe_cov        Confirmed SubscribeCOV — T0802 Automated Collection
      reinitialize_device  Confirmed ReinitializeDevice — T0816 Device Restart
      device_comm_control  Confirmed DeviceCommunicationControl — T0813/T0826 DoS
      read_file            Confirmed AtomicReadFile — T0882 Theft of Operational Info
      write_file           Confirmed AtomicWriteFile — T0843 Program Download
      private_transfer     Confirmed PrivateTransfer — T0869 Standard App Layer Protocol
      who_has              Unconfirmed Who-Has — T0861 Point & Tag Identification
      time_sync            Unconfirmed TimeSynchronization — T0849 Spoof Reporting
      create_object        Confirmed CreateObject — T0889 Modify Program
      delete_object        Confirmed DeleteObject — T0809 Data Destruction
    """
    rnd = random.Random(kwargs.get("seed"))
    mb = marker_bytes(marker)
    invoke_id = rnd.randint(0, 255)
    device_instance = int(kwargs.get("device_instance", rnd.randint(1, 4194303)))

    if style == "who_is":
        # Unconfirmed Who-Is broadcast (§16.10)
        # Optional range: low-limit(context 0) + high-limit(context 1)
        low = int(kwargs.get("low_limit", 0))
        high = int(kwargs.get("high_limit", 4194303))
        apdu = bytes([APDU_UNCONFIRMED_REQ, SVC_WHO_IS])
        apdu += _context_tag(0, _unsigned(low))
        apdu += _context_tag(1, _unsigned(high))
        npdu = _npdu(NPDU_CTRL_NO_APDU)
        bvlc_fn = BVLC_ORIGINAL_BROADCAST

    elif style == "i_am":
        # Unconfirmed I-Am (§16.3) — fake device announcement
        obj_id = _object_identifier(OBJ_DEVICE, device_instance)
        apdu = bytes([APDU_UNCONFIRMED_REQ, SVC_I_AM])
        apdu += _context_tag(0, obj_id)                              # iAmDeviceIdentifier
        apdu += _context_tag(1, _unsigned(1476))                     # maxAPDULengthAccepted
        apdu += _context_tag(2, bytes([0x03]))                       # segmentationSupported: no
        apdu += _context_tag(3, _unsigned(rnd.randint(0, 1000)))     # vendorID
        npdu = _npdu(NPDU_CTRL_NO_APDU)
        bvlc_fn = BVLC_ORIGINAL_BROADCAST

    elif style == "read_property":
        # Confirmed ReadProperty (§15.5)
        obj_type = int(kwargs.get("object_type", OBJ_ANALOG_INPUT))
        obj_inst = int(kwargs.get("object_instance", rnd.randint(0, 100)))
        prop_id = int(kwargs.get("property_id", PROP_PRESENT_VALUE))
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_READ_PROPERTY])
        apdu += _context_tag(0, _object_identifier(obj_type, obj_inst))
        apdu += _context_tag(1, _unsigned(prop_id))
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "read_property_multi":
        # Confirmed ReadPropertyMultiple (§15.7) — bulk read
        obj_type = int(kwargs.get("object_type", OBJ_DEVICE))
        obj_inst = int(kwargs.get("object_instance", device_instance))
        props = [PROP_OBJECT_NAME, PROP_VENDOR_NAME, PROP_MODEL_NAME,
                 PROP_FIRMWARE_REVISION, PROP_SYSTEM_STATUS]
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_READ_PROPERTY_MULTIPLE])
        # ListOfReadAccessSpecification
        apdu += _context_tag(0, _object_identifier(obj_type, obj_inst))
        apdu += _opening_tag(1)  # listOfPropertyReferences
        for pid in props:
            apdu += _context_tag(0, _unsigned(pid))
        apdu += _closing_tag(1)
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "write_property":
        # Confirmed WriteProperty (§15.9)
        obj_type = int(kwargs.get("object_type", OBJ_ANALOG_OUTPUT))
        obj_inst = int(kwargs.get("object_instance", rnd.randint(0, 50)))
        prop_id = int(kwargs.get("property_id", PROP_PRESENT_VALUE))
        value = kwargs.get("value", rnd.uniform(0.0, 100.0))
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_WRITE_PROPERTY])
        apdu += _context_tag(0, _object_identifier(obj_type, obj_inst))
        apdu += _context_tag(1, _unsigned(prop_id))
        # propertyValue (context 3): Application-tagged REAL
        apdu += _opening_tag(3)
        apdu += bytes([0x44]) + struct.pack(">f", float(value))  # Application tag 4 (REAL), 4 bytes
        apdu += _closing_tag(3)
        # priority (context 4): optional, 1-16
        priority = int(kwargs.get("priority", rnd.randint(1, 16)))
        apdu += _context_tag(4, _unsigned(priority))
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "write_property_multi":
        # Confirmed WritePropertyMultiple (§15.11) — bulk parameter change
        obj_type = int(kwargs.get("object_type", OBJ_ANALOG_OUTPUT))
        obj_inst = int(kwargs.get("object_instance", rnd.randint(0, 20)))
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_WRITE_PROPERTY_MULTIPLE])
        apdu += _context_tag(0, _object_identifier(obj_type, obj_inst))
        apdu += _opening_tag(1)  # listOfWriteAccessSpecification
        # Write PRESENT_VALUE
        apdu += _context_tag(0, _unsigned(PROP_PRESENT_VALUE))
        apdu += _opening_tag(2)
        apdu += bytes([0x44]) + struct.pack(">f", rnd.uniform(0, 100))
        apdu += _closing_tag(2)
        apdu += _closing_tag(1)
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "subscribe_cov":
        # Confirmed SubscribeCOV (§13.1)
        obj_type = int(kwargs.get("object_type", OBJ_ANALOG_INPUT))
        obj_inst = int(kwargs.get("object_instance", rnd.randint(0, 100)))
        subscriber_process_id = rnd.randint(1, 255)
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_SUBSCRIBE_COV])
        apdu += _context_tag(0, _unsigned(subscriber_process_id))
        apdu += _context_tag(1, _object_identifier(obj_type, obj_inst))
        apdu += _context_tag(2, bytes([0x01]))  # issueConfirmedNotifications: TRUE
        apdu += _context_tag(3, _unsigned(300))  # lifetime: 300 seconds
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "reinitialize_device":
        # Confirmed ReinitializeDevice (§15.4)
        # reinitializedStateOfDevice: 0=coldstart, 1=warmstart
        state = int(kwargs.get("state", 0))
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_REINITIALIZE_DEVICE])
        apdu += _context_tag(0, _unsigned(state))
        # Optional password (context 1)
        password = kwargs.get("password", "")
        if password:
            apdu += _context_tag(1, password.encode("utf-8")[:20])
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "device_comm_control":
        # Confirmed DeviceCommunicationControl (§16.1)
        # enableDisable: 0=enable, 1=disable, 2=disable-initiation
        enable_disable = int(kwargs.get("enable_disable", 1))  # default: disable
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_DEVICE_COMMUNICATION_CONTROL])
        # timeDuration (context 0): optional, minutes
        apdu += _context_tag(0, _unsigned(int(kwargs.get("duration", 0xFFFF))))
        apdu += _context_tag(1, _unsigned(enable_disable))
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "read_file":
        # Confirmed AtomicReadFile (§14.1)
        file_inst = int(kwargs.get("file_instance", rnd.randint(0, 10)))
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_ATOMIC_READ_FILE])
        apdu += _context_tag(0, _object_identifier(OBJ_FILE, file_inst))
        # streamAccess (context 0): fileStartPosition + requestedOctetCount
        apdu += _opening_tag(0)
        apdu += _context_tag(0, struct.pack(">i", 0))          # fileStartPosition
        apdu += _context_tag(1, _unsigned(1024))                # requestedOctetCount
        apdu += _closing_tag(0)
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "write_file":
        # Confirmed AtomicWriteFile (§14.2)
        file_inst = int(kwargs.get("file_instance", rnd.randint(0, 10)))
        data = kwargs.get("data", bytes([rnd.randint(0x20, 0x7E) for _ in range(64)]))
        if isinstance(data, str):
            data = data.encode("utf-8")
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_ATOMIC_WRITE_FILE])
        apdu += _context_tag(0, _object_identifier(OBJ_FILE, file_inst))
        # streamAccess (context 0)
        apdu += _opening_tag(0)
        apdu += _context_tag(0, struct.pack(">i", 0))  # fileStartPosition
        apdu += _context_tag(1, data[:240])             # fileData
        apdu += _closing_tag(0)
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "private_transfer":
        # Confirmed PrivateTransfer (§22.3)
        vendor_id = int(kwargs.get("vendor_id", rnd.randint(0, 1000)))
        service_number = int(kwargs.get("service_number", rnd.randint(0, 255)))
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_CONFIRMED_PRIVATE_TRANSFER])
        apdu += _context_tag(0, _unsigned(vendor_id))
        apdu += _context_tag(1, _unsigned(service_number))
        # Optional serviceParameters (context 2)
        apdu += _opening_tag(2)
        apdu += bytes([rnd.randint(0, 255) for _ in range(16)])
        apdu += _closing_tag(2)
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "who_has":
        # Unconfirmed Who-Has (§16.8)
        obj_name = kwargs.get("object_name", "HVAC-AHU-01")
        apdu = bytes([APDU_UNCONFIRMED_REQ, SVC_WHO_HAS])
        # objectName (context 3): character string
        name_bytes = obj_name.encode("utf-8")
        apdu += _context_tag(3, bytes([0x00]) + name_bytes)  # encoding=0 (UTF-8)
        npdu = _npdu(NPDU_CTRL_NO_APDU)
        bvlc_fn = BVLC_ORIGINAL_BROADCAST

    elif style == "time_sync":
        # Unconfirmed TimeSynchronization (§16.7)
        import time as _time
        now = _time.gmtime()
        apdu = bytes([APDU_UNCONFIRMED_REQ, SVC_TIME_SYNCHRONIZATION])
        # BACnet Date: year-1900(1), month(1), day(1), dow(1)
        apdu += bytes([0xA4])  # Application tag 10 (Date), 4 bytes
        apdu += bytes([now.tm_year - 1900, now.tm_mon, now.tm_mday, now.tm_wday])
        # BACnet Time: hour(1), minute(1), second(1), hundredths(1)
        apdu += bytes([0xB4])  # Application tag 11 (Time), 4 bytes
        apdu += bytes([now.tm_hour, now.tm_min, now.tm_sec, 0])
        npdu = _npdu(NPDU_CTRL_NO_APDU)
        bvlc_fn = BVLC_ORIGINAL_BROADCAST

    elif style == "create_object":
        # Confirmed CreateObject (§15.1)
        obj_type = int(kwargs.get("object_type", OBJ_PROGRAM))
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_CREATE_OBJECT])
        # objectSpecifier (context 0) — objectType
        apdu += _opening_tag(0)
        apdu += _context_tag(0, _unsigned(obj_type))
        apdu += _closing_tag(0)
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    elif style == "delete_object":
        # Confirmed DeleteObject (§15.2)
        obj_type = int(kwargs.get("object_type", OBJ_SCHEDULE))
        obj_inst = int(kwargs.get("object_instance", rnd.randint(0, 50)))
        apdu = bytes([APDU_CONFIRMED_REQ, 0x05, invoke_id, SVC_DELETE_OBJECT])
        apdu += _context_tag(0, _object_identifier(obj_type, obj_inst))
        npdu = _npdu(NPDU_CTRL_EXPECTING_REPLY)
        bvlc_fn = BVLC_ORIGINAL_UNICAST

    else:
        # Fallback: Who-Is broadcast
        apdu = bytes([APDU_UNCONFIRMED_REQ, SVC_WHO_IS])
        npdu = _npdu(NPDU_CTRL_NO_APDU)
        bvlc_fn = BVLC_ORIGINAL_BROADCAST

    body = npdu + apdu + mb
    return _bvlc_header(bvlc_fn, len(body)) + body
