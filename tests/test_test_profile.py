"""Tests for the Test Profile feature (Firewall/ACL ⟷ NSM).

A test profile encodes operator intent and sets safe defaults — it never
fabricates device responses (the receiver is a safe sinkhole). Firewall/ACL is
unidirectional (arrival = a rule allowed it). NSM defaults the handshake on
(stream sensors engage) and pairs witnessed traffic with the expected technique.
"""
import json
import tempfile

from icsforge.reports.network_validation import build_network_validation_report
from icsforge.scenarios.engine import profile_defaults


class TestProfileDefaults:
    def test_firewall_is_stateless(self):
        assert profile_defaults("firewall") == {"stateful": False}

    def test_nsm_defaults_stateful(self):
        assert profile_defaults("nsm") == {"stateful": True}

    def test_unknown_falls_back_to_firewall(self):
        assert profile_defaults("") == {"stateful": False}
        assert profile_defaults("bogus") == {"stateful": False}


class TestReceiverEnrichment:
    def test_expectation_carries_profile_and_alert(self):
        from icsforge.receiver import receiver as R
        R.register_expectation(
            "run__proftest", scenario="T0855__unauth_command__modbus",
            technique="T0855", protos=["modbus"],
            test_profile="nsm", expected_alert="Modbus write to PLC",
        )
        exp = R._match_expectation("modbus")
        enr = R._expectation_enrichment(exp)
        assert enr["test_profile"] == "nsm"
        assert enr["expected_technique"] == "T0855"
        assert enr["expected_alert"] == "Modbus write to PLC"
        R.clear_expectation("run__proftest")


class TestProfileAwareReport:
    def _report(self, profile, alerts=None):
        td = tempfile.mkdtemp()
        ev = f"{td}/ev.jsonl"
        rc = f"{td}/rc.jsonl"
        with open(ev, "w") as f:
            f.write(json.dumps({"run_id": "r1", "mitre.ics.technique": "T0855"}) + "\n")
        with open(rc, "w") as f:
            f.write(json.dumps({
                "run_id": "r1", "technique": "T0855", "test_profile": profile,
                "expected_alert": "T0855",
            }) + "\n")
        al = None
        if alerts is not None:
            al = f"{td}/al.jsonl"
            with open(al, "w") as f:
                for t in alerts:
                    f.write(json.dumps({"run_id": "r1", "mitre.ics.technique": t}) + "\n")
        return build_network_validation_report(ev, rc, alerts_jsonl=al)

    def test_firewall_frames_as_boundary_traversal(self):
        rep = self._report("firewall")
        run = rep["runs"][0]
        assert run["test_profile"] == "firewall"
        assert "TRAVERSED" in run["interpretation"]

    def test_nsm_without_alerts_asks_for_alerts(self):
        rep = self._report("nsm")
        run = rep["runs"][0]
        assert run["test_profile"] == "nsm"
        assert "alert" in run["interpretation"].lower()

    def test_nsm_with_matching_alert_confirms(self):
        rep = self._report("nsm", alerts=["T0855"])
        run = rep["runs"][0]
        assert "expected alert" in run["interpretation"].lower()

    def test_nsm_with_no_alert_flags_gap(self):
        rep = self._report("nsm", alerts=[])
        run = rep["runs"][0]
        assert "gap" in run["interpretation"].lower()
