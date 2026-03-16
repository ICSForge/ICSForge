# ICSForge MQTT 3.1.1 payload builder
# Real packet framing per OASIS MQTT v3.1.1 Standard (29 October 2014)
# TCP port 1883 (unencrypted), 8883 (TLS — not emulated here)
#
# MQTT is the dominant IIoT messaging protocol, used in:
#   - Building automation (BACnet→MQTT bridges, Niagara Framework)
#   - IIoT sensor telemetry (OPC UA Pub/Sub over MQTT)
#   - SCADA cloud gateways (Ignition, Inductive Automation)
#   - Smart grid AMI and DER aggregation

import random
import struct

from .common import marker_bytes

# ── Packet types (§2.1.2) ───────────────────────────────────────────
CONNECT     = 1
CONNACK     = 2
PUBLISH     = 3
PUBACK      = 4
SUBSCRIBE   = 8
SUBACK      = 9
UNSUBSCRIBE = 10
UNSUBACK    = 11
PINGREQ     = 12
PINGRESP    = 13
DISCONNECT  = 14

QOS_0 = 0
QOS_1 = 1
QOS_2 = 2

# ── ICS-relevant MQTT topics ────────────────────────────────────────
ACTUATOR_TOPICS = [
    "factory/plc01/register/write",
    "building/hvac/ahu03/setpoint",
    "power/substation/breaker/cmd",
    "water/pump/station02/speed",
    "process/reactor/valve/position",
    "oilgas/wellhead/choke/set",
]

SENSOR_TOPICS = [
    "factory/plc01/register/read",
    "building/hvac/ahu03/temperature",
    "power/substation/meter/reading",
    "water/tank/level/sensor01",
    "process/reactor/pressure",
    "oilgas/pipeline/flow/meter",
]

ALARM_TOPICS = [
    "factory/safety/sis/trip",
    "building/fire/zone02/alarm",
    "power/protection/relay/status",
    "water/overflow/alarm",
    "process/safety/shutdown",
]

CONFIG_TOPICS = [
    "factory/plc01/config/upload",
    "building/bms/schedule/override",
    "power/rtu/config/change",
    "water/scada/tuning/pid",
]

COMMAND_TOPICS = [
    "factory/plc01/command/execute",
    "building/bms/override/all",
    "power/substation/trip/manual",
    "water/pump/emergency/stop",
]


# ── Encoding helpers (§1.5, §2.2.3) ─────────────────────────────────

def _remaining_length(length: int) -> bytes:
    """Variable-length encoding per §2.2.3."""
    out = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        out.append(byte)
        if length == 0:
            break
    return bytes(out)


def _utf8(s: str) -> bytes:
    """MQTT UTF-8 string: 2-byte length + UTF-8 bytes (§1.5.3)."""
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def _packet(pkt_type: int, flags: int, body: bytes) -> bytes:
    """Fixed header byte + remaining length + body."""
    hdr = bytes([((pkt_type & 0x0F) << 4) | (flags & 0x0F)])
    return hdr + _remaining_length(len(body)) + body


def _pkt_id(rnd: random.Random) -> bytes:
    return struct.pack(">H", rnd.randint(1, 65535))


# ── Individual packet builders ──────────────────────────────────────

def _connect(client_id: str, username: str = "", password: str = "",
             keep_alive: int = 60, clean: bool = True,
             will_topic: str = "", will_msg: bytes = b"",
             will_qos: int = 0, will_retain: bool = False) -> bytes:
    """CONNECT (§3.1)."""
    var = _utf8("MQTT") + bytes([0x04])  # protocol name + level 3.1.1
    flags = 0x02 if clean else 0x00
    if will_topic:
        flags |= 0x04
        flags |= (will_qos & 0x03) << 3
        if will_retain:
            flags |= 0x20
    if password:
        flags |= 0x40
    if username:
        flags |= 0x80
    var += bytes([flags]) + struct.pack(">H", keep_alive)
    payload = _utf8(client_id)
    if will_topic:
        payload += _utf8(will_topic)
        payload += struct.pack(">H", len(will_msg)) + will_msg
    if username:
        payload += _utf8(username)
    if password:
        payload += _utf8(password)
    return _packet(CONNECT, 0x00, var + payload)


def _publish(topic: str, payload: bytes, qos: int = 0,
             retain: bool = False, rnd: random.Random = None) -> bytes:
    """PUBLISH (§3.3)."""
    flags = (qos & 0x03) << 1
    if retain:
        flags |= 0x01
    var = _utf8(topic)
    if qos > 0:
        rnd = rnd or random.Random()
        var += _pkt_id(rnd)
    return _packet(PUBLISH, flags, var + payload)


def _subscribe(topics: list, qos: int = 0, rnd: random.Random = None) -> bytes:
    """SUBSCRIBE (§3.8). Reserved flags = 0x02."""
    rnd = rnd or random.Random()
    body = _pkt_id(rnd)
    for t in topics:
        body += _utf8(t) + bytes([qos & 0x03])
    return _packet(SUBSCRIBE, 0x02, body)


def _unsubscribe(topics: list, rnd: random.Random = None) -> bytes:
    """UNSUBSCRIBE (§3.10). Reserved flags = 0x02."""
    rnd = rnd or random.Random()
    body = _pkt_id(rnd)
    for t in topics:
        body += _utf8(t)
    return _packet(UNSUBSCRIBE, 0x02, body)


def _pingreq() -> bytes:
    return _packet(PINGREQ, 0x00, b"")


def _disconnect() -> bytes:
    return _packet(DISCONNECT, 0x00, b"")


# ── Main entry: build_payload ────────────────────────────────────────

def build_payload(marker: str, style: str = "auto", seed: int = None, **kwargs) -> bytes:
    """Build an MQTT 3.1.1 payload for ICS security testing.

    Returns a complete MQTT packet with the ICSForge marker appended
    after framing so the receiver can correlate it.
    """
    rnd = random.Random(seed) if seed is not None else random.Random()
    mb = marker_bytes(marker)

    client_ids = [
        "icsforge-plc01", "scada-hmi-03", "mes-gateway", "bms-ctrl",
        "rtu-site42", "historian-01", "iot-sensor", "edge-node-07",
    ]
    cid = rnd.choice(client_ids) + f"-{rnd.randint(100, 999)}"

    # ── CONNECT variants ────────────────────────────────────────────
    if style in ("auto", "connect"):
        return _connect(cid, keep_alive=rnd.randint(30, 120)) + mb

    if style == "connect_creds":
        users = ["admin", "operator", "engineer", "scada", "root", "mqtt"]
        pwds = ["admin", "password", "1234", "scada", "", "operator123"]
        return _connect(cid, username=rnd.choice(users),
                        password=rnd.choice(pwds), keep_alive=30) + mb

    if style == "connect_anonymous":
        return _connect(cid, username="", password="", clean=True) + mb

    if style == "will_message":
        topic = rnd.choice(ALARM_TOPICS)
        will = b'{"status":"offline","unexpected":true}'
        return _connect(cid, will_topic=topic, will_msg=will,
                        will_qos=QOS_1, will_retain=True,
                        keep_alive=rnd.randint(15, 45)) + mb

    # ── PUBLISH variants ────────────────────────────────────────────
    if style == "publish_command":
        topic = rnd.choice(ACTUATOR_TOPICS)
        cmds = [
            b'{"cmd":"write","register":40001,"value":1}',
            b'{"cmd":"start","speed":1750}',
            b'{"cmd":"open","position":100}',
            b'{"cmd":"override","mode":"manual"}',
        ]
        return _publish(topic, rnd.choice(cmds) + b" " + mb, qos=QOS_1, rnd=rnd)

    if style == "publish_setpoint":
        topic = rnd.choice(ACTUATOR_TOPICS)
        sps = [
            b'{"setpoint":999.9,"unit":"degC"}',
            b'{"setpoint":0.0,"unit":"bar"}',
            b'{"speed_rpm":9999}',
            b'{"level_target":0,"override":true}',
        ]
        return _publish(topic, rnd.choice(sps) + b" " + mb,
                        qos=QOS_1, retain=True, rnd=rnd)

    if style == "publish_telemetry":
        topic = rnd.choice(SENSOR_TOPICS)
        vals = [
            b'{"temperature":72.5,"unit":"F","ts":1710000000}',
            b'{"pressure":14.7,"unit":"psi","quality":"good"}',
            b'{"flow":125.3,"unit":"gpm"}',
            b'{"level":85.2,"unit":"percent"}',
        ]
        return _publish(topic, rnd.choice(vals) + b" " + mb, qos=QOS_0, rnd=rnd)

    if style == "publish_firmware":
        topic = rnd.choice(CONFIG_TOPICS).replace("config", "firmware")
        fw_hdr = struct.pack(">4sHH", b"FWUP", 2, 0)
        padding = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(64, 256)))
        return _publish(topic, fw_hdr + padding + mb, qos=QOS_2, rnd=rnd)

    if style == "publish_dos":
        blob = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(2048, 4096)))
        return _publish("factory/broadcast/all", blob + mb, qos=QOS_0, rnd=rnd)

    if style == "publish_alarm":
        topic = rnd.choice(ALARM_TOPICS)
        msgs = [
            b'{"alarm":"clear","ack":true}',
            b'{"trip":false,"bypass":true}',
            b'{"suppress":true,"duration":3600}',
        ]
        return _publish(topic, rnd.choice(msgs) + b" " + mb, qos=QOS_1, rnd=rnd)

    if style == "publish_config":
        topic = rnd.choice(CONFIG_TOPICS)
        cfgs = [
            b'{"pid":{"kp":0,"ki":0,"kd":0}}',
            b'{"polling_interval_ms":60000}',
            b'{"alarm_threshold":99999}',
            b'{"reporting_enabled":false}',
        ]
        return _publish(topic, rnd.choice(cfgs) + b" " + mb,
                        qos=QOS_1, retain=True, rnd=rnd)

    # ── SUBSCRIBE variants ──────────────────────────────────────────
    if style == "subscribe_telemetry":
        topics = rnd.sample(SENSOR_TOPICS, min(3, len(SENSOR_TOPICS)))
        return _subscribe(topics, qos=QOS_1, rnd=rnd) + mb

    if style == "subscribe_commands":
        topics = rnd.sample(COMMAND_TOPICS, min(2, len(COMMAND_TOPICS)))
        return _subscribe(topics, qos=QOS_1, rnd=rnd) + mb

    if style == "subscribe_all":
        return _subscribe(["#"], qos=QOS_0, rnd=rnd) + mb

    # ── Other ───────────────────────────────────────────────────────
    if style == "unsubscribe":
        topics = rnd.sample(SENSOR_TOPICS, 2)
        return _unsubscribe(topics, rnd=rnd) + mb

    if style == "pingreq":
        return _pingreq() + mb

    if style == "disconnect":
        return _disconnect() + mb

    # Fallback
    return _connect(cid, keep_alive=60) + mb


STYLES = [
    "connect", "connect_creds", "connect_anonymous", "will_message",
    "publish_command", "publish_setpoint", "publish_telemetry",
    "publish_firmware", "publish_dos", "publish_alarm", "publish_config",
    "subscribe_telemetry", "subscribe_commands", "subscribe_all",
    "unsubscribe", "pingreq", "disconnect",
]
