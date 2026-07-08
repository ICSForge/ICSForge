"""
Tests for v0.62.2 protocol-correctness fixes.

These fixes came out of the comprehensive style-level scenario audit
(scripts/audit_resumable.py) that runs every distinct (proto, style)
combination through tshark. Locks the post-fix state in place.

Run audit fresh: scripts/audit_resumable.py [PROTO]
Output: /tmp/audit_checkpoint.json
"""
import os
import shutil
import struct
import subprocess

import pytest

from icsforge.protocols import bacnet, opcua, s7comm
from icsforge.scenarios.engine import run_scenario

# ── BACnet (v0.62.2) ─────────────────────────────────────────────────────

class TestBacnetMarkerSuppression:
    """BACnet markers must be omitted; they break BVLC length envelope."""

    def test_who_is_no_marker(self):
        pkt = bacnet.build_payload(b"M", style="who_is")
        assert b"ICSFORGE:" not in pkt

    def test_write_property_no_marker(self):
        pkt = bacnet.build_payload(b"M", style="write_property")
        assert b"ICSFORGE:" not in pkt

    def test_subscribe_cov_no_marker(self):
        pkt = bacnet.build_payload(b"M", style="subscribe_cov")
        assert b"ICSFORGE:" not in pkt


class TestBacnetIamApplicationTags:
    """BACnet I-Am parameters must use application-class tags per §16.3.

    Bug: v0.62.0 used context tags 0..3, which Wireshark flagged as
    'Wrong length indicated. Expected 1 or 2, got 4'.
    """

    def test_i_am_uses_app_tag_for_object_identifier(self):
        pkt = bacnet.build_payload(b"M", style="i_am")
        # Find the APDU. After BVLC(4) + NPDU(2) is the APDU.
        # APDU header: type(1) + service(1) = 2 bytes (Unconfirmed-REQ + I-Am)
        # First parameter starts at offset 6+2=8 in the BACnet payload.
        # First byte of first parameter must have application class
        # (top nibble bit 3 = 0) and tag number 12 (BACnetObjectIdentifier).
        # Tag byte = (12 << 4) | 0x05 = 0xC5 (long-form length) for 4-byte value
        # OR (12 << 4) | 4 = 0xC4 (short-form length=4)
        # 0xC4 = 1100 0100: tag=12, app class (bit 3=0), len=4 ✓
        first_param_byte = pkt[8]
        assert first_param_byte == 0xC4, (
            f"I-Am first parameter must be application-tag 12 (0xC4), got "
            f"0x{first_param_byte:02X}. v0.62.0 had this as 0x0E (context-tag 0)."
        )


class TestBacnetSubscribeCovBoolean:
    """SubscribeCOV's issueConfirmedNotifications must be context-Boolean
    encoded as 1-byte payload (not value-in-tag-nibble form)."""

    def test_subscribe_cov_boolean_format(self):
        pkt = bacnet.build_payload(b"M", style="subscribe_cov")
        # Look for context-2 boolean encoded as `0x29 0x01` (TRUE) or `0x29 0x00`
        # That's: tag=2 (context, len=1) + payload byte
        assert b"\x29\x01" in pkt or b"\x29\x00" in pkt


# ── S7comm (v0.62.2) ─────────────────────────────────────────────────────

class TestS7commPiServiceLayout:
    """PI-Service (FC 0x28) must have 7 unknown bytes + 2-byte block_len
    + name_len + name. v0.62.0 had wrong byte count."""

    def test_cpu_start_warm_pi_service_format(self):
        pkt = s7comm.build_payload(b"M", style="cpu_start_warm")
        # Find FC 0x28 in the payload (after TPKT + COTP + S7 hdr)
        # S7 header is 10 bytes for Job; FC starts at byte 0 of param block
        # TPKT(4) + COTP(3) + S7_hdr(10) = 17, then FC=0x28 should be at offset 17
        assert pkt[17] == 0x28
        # Bytes 18-24 = 7 unknown bytes ending with 0xFD
        assert pkt[24] == 0xFD, (
            f"PI-Service: 7th unknown byte (offset 24) should be 0xFD, "
            f"got 0x{pkt[24]:02X}"
        )
        # Bytes 25-26 = block length (BE)
        block_len = (pkt[25] << 8) | pkt[26]
        assert block_len == 0, f"empty param block expected, got len={block_len}"
        # Byte 27 = name length, bytes 28+ = ASCII name
        name_len = pkt[27]
        name = pkt[28:28 + name_len]
        assert name == b"P_PROGRAM"


class TestS7commRequestDownloadLayout:
    """Request Download (FC 0x1A) parameter must be:
    FC + status + errcode(2) + unknown(4) + length(1) + filename(7) + dest_fs(1).
    v0.62.0 was missing the errcode field."""

    def test_download_req_filename_format(self):
        pkt = s7comm.build_payload(b"M", style="download_req")
        # Offset: TPKT(4) + COTP(3) + S7_hdr(10) = 17
        assert pkt[17] == 0x1A  # FC = Request Download
        # FC(1) + status(1) + errcode(2) + unknown(4) = 8 bytes header before length
        # length-of-part-2 at offset 17+8=25
        assert pkt[25] == 8, f"length-of-part-2 should be 8, got {pkt[25]}"
        # Filename starts at offset 26
        assert pkt[26:26 + 7] == b"_000001"  # _ + block_type=0 (OB) + 5 digits

    def test_upload_req_uses_same_layout(self):
        pkt = s7comm.build_payload(b"M", style="upload_req")
        assert pkt[17] == 0x1D  # FC = Request Upload
        assert pkt[25] == 8


class TestS7commCotpCr:
    """COTP CR length field must equal bytes-after-length-field (= 17 for our CR)."""

    def test_native_cotp_length(self):
        pkt = s7comm.build_payload(b"M", style="native_cotp")
        # TPKT(4) + COTP-length-byte
        # COTP CR starts at offset 4 with length byte
        assert pkt[4] == 0x11, (
            f"COTP CR length must be 0x11 (17 bytes follow), got 0x{pkt[4]:02X}. "
            f"v0.62.0 had 0x0B which doesn't match the actual content length."
        )
        assert pkt[5] == 0xE0, "byte after length must be CR PDU code (0xE0)"


class TestS7commSzlCleanSubfunction:
    """szl_clear must use Read SZL subfunction (0x01), not the broken 0x03."""

    def test_szl_clear_subfunction(self):
        pkt = s7comm.build_payload(b"M", style="szl_clear")
        # USERDATA layout: TPKT(4) + COTP(3) + S7_hdr(12 for userdata) = 19
        # Then param2: head(3) + type_func(1) + subfunc(1) + ...
        # Subfunc is at offset 19+4 = 23
        assert pkt[23] == 0x01, (
            f"szl_clear must use subfunction 0x01 (Read SZL), got 0x{pkt[23]:02X}"
        )


# ── OPC UA (v0.62.2) ─────────────────────────────────────────────────────

class TestOpcuaOpnLayout:
    """OPN messages must follow Part 6 §7.1.2 layout:
    MessageHeader → SecureChannelId → AsymmetricAlgorithmSecurityHeader →
    SequenceHeader → OpenSecureChannelRequest.

    Per spec, opening a NEW channel uses SecureChannelId = 0 (the server
    assigns the id in its response) — not 0xFFFFFFFF — and the asym header
    carries a real securityPolicyUri String (here the '#None' policy), with
    null senderCertificate and receiverCertificateThumbprint ByteStrings.
    OPN carries an OpenSecureChannelRequest (service 446), not CreateSession."""

    _POLICY_NONE = b"http://opcfoundation.org/UA/SecurityPolicy#None"

    def test_relay_session_opn_layout(self):
        pkt = opcua.build_payload(b"M", style="relay_session")
        # MessageHeader: "OPN" + chunk 'F' + 4-byte size = 8 bytes
        assert pkt[:3] == b"OPN"
        assert pkt[3] == ord("F")
        # SecureChannelId at offset 8 (4 bytes) = 0 for a new channel
        sc_id = struct.unpack("<I", pkt[8:12])[0]
        assert sc_id == 0, f"new channel id should be 0, got {sc_id:#x}"
        # AsymmetricAlgorithmSecurityHeader: securityPolicyUri String at offset 12
        uri_len = struct.unpack("<I", pkt[12:16])[0]
        assert uri_len == len(self._POLICY_NONE), f"policy uri len {uri_len}"
        assert pkt[16:16 + uri_len] == self._POLICY_NONE
        # senderCertificate + receiverCertificateThumbprint = null ByteStrings
        off = 16 + uri_len
        assert pkt[off:off + 8] == b"\xFF" * 8, "null cert + null thumbprint expected"

    def test_native_raw_opn_layout(self):
        pkt = opcua.build_payload(b"M", style="native_raw")
        assert pkt[:3] == b"OPN"
        sc_id = struct.unpack("<I", pkt[8:12])[0]
        assert sc_id == 0


# ── Cross-protocol audit invariant ────────────────────────────────────────

@pytest.mark.slow
@pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not available")
@pytest.mark.timeout(45)
class TestStyleAuditInvariant:
    """Lock the v0.62.2 audit-derived cleanliness in place.

    Each fixed style is regenerated and run through tshark. If a
    regression introduces malformations, this test catches it.
    """

    @pytest.mark.parametrize("proto,style", [
        ("bacnet", "i_am"),
        ("bacnet", "subscribe_cov"),
        ("bacnet", "private_transfer"),
        ("s7comm", "cpu_start_warm"),
        ("s7comm", "cpu_start_cold"),
        ("s7comm", "program_mode"),
        ("s7comm", "download_req"),
        ("s7comm", "download_block"),
        ("s7comm", "download_end"),
        ("s7comm", "upload_req"),
        ("s7comm", "upload_block"),
        ("s7comm", "upload_end"),
        ("s7comm", "modify_ob1"),
        ("s7comm", "modified_ob1_dl"),
        ("s7comm", "download_sdb0"),
        ("s7comm", "native_cotp"),
        ("s7comm", "szl_clear"),
        ("opcua", "relay_session"),
        ("opcua", "native_raw"),
    ])
    def test_style_dissects_cleanly(self, proto, style, tmp_path):
        # Find a scenario using this (proto, style)
        import yaml
        with open("icsforge/scenarios/scenarios.yml") as f:
            scenarios = yaml.safe_load(f)["scenarios"]
        rep = None
        for name, body in scenarios.items():
            for step in body.get("steps", []):
                if step.get("proto") == proto and step.get("style") == style:
                    rep = name
                    break
            if rep:
                break
        if not rep:
            pytest.skip(f"no scenario uses ({proto}, {style})")

        outdir = str(tmp_path)
        run_scenario(
            scenario_path="icsforge/scenarios/scenarios.yml",
            name=rep,
            outdir=outdir,
            dst_ip="192.0.2.10",
            src_ip="192.0.2.11",
            skip_intervals=True,
        )
        # Find pcap
        pcap = None
        for root, _, files in os.walk(outdir):
            for f in files:
                if f.endswith(".pcap"):
                    pcap = os.path.join(root, f)
                    break
            if pcap:
                break
        assert pcap, f"no pcap generated for {rep}"

        # Run tshark, count malformed packets
        r = subprocess.run(
            ["tshark", "-r", pcap, "-Y",
             "_ws.malformed || _ws.expert.severity==error",
             "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True, timeout=20,
        )
        err_count = sum(1 for line in r.stdout.splitlines() if line.strip().isdigit())
        assert err_count == 0, (
            f"{proto}/{style} produced {err_count} dissector errors in {rep}; "
            f"this is a regression from v0.62.2 audit baseline."
        )
