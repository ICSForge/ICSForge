"""Tests for the scenario engine and detection content generator."""
import json
import os

import pytest

from icsforge.scenarios.engine import load_scenarios, run_scenario



class TestLoadScenarios:
    def test_load_bundled_scenarios(self, scenarios_path):
        doc = load_scenarios(scenarios_path)
        scenarios = doc.get("scenarios", {})
        assert len(scenarios) > 100, "Bundled pack should have 100+ scenarios"

    def test_scenario_naming_convention(self, scenarios_path):
        """All scenario names should follow T0XXX__ or CHAIN__ prefix."""
        doc = load_scenarios(scenarios_path)
        for name in doc.get("scenarios", {}):
            assert name.startswith("T0") or name.startswith("CHAIN"), \
                f"Scenario '{name}' should start with T0 or CHAIN"
            assert "__" in name, f"Scenario '{name}' should use __ separator"

    def test_scenario_has_steps(self, scenarios_path):
        doc = load_scenarios(scenarios_path)
        for name, sc in doc.get("scenarios", {}).items():
            steps = sc.get("steps", [])
            assert len(steps) > 0, f"Scenario '{name}' has no steps"

    def test_scenario_has_technique(self, scenarios_path):
        doc = load_scenarios(scenarios_path)
        for name, sc in doc.get("scenarios", {}).items():
            for step in sc.get("steps", []):
                tech = step.get("technique")
                if tech:
                    assert tech.startswith("T0"), f"Invalid technique '{tech}' in {name}"


class TestRunScenario:
    def test_generate_offline(self, scenarios_path, tmp_outdir):
        """Run a known scenario offline and verify output artifacts."""
        result = run_scenario(
            scenarios_path,
            "T0855__unauth_command__modbus",
            outdir=tmp_outdir,
            dst_ip="198.51.100.42",
            src_ip="127.0.0.1",
            run_id="test-run-001",
        )
        assert result["run_id"] == "test-run-001"
        assert result["events"] is not None
        assert os.path.exists(result["events"])

        # Verify events JSONL content
        with open(result["events"], "r") as f:
            lines = [json.loads(ln) for ln in f if ln.strip()]
        assert len(lines) > 0
        assert all(ev.get("mitre.ics.technique") for ev in lines)

    def test_generate_pcap(self, scenarios_path, tmp_outdir):
        result = run_scenario(
            scenarios_path,
            "T0855__unauth_command__modbus",
            outdir=tmp_outdir,
            dst_ip="198.51.100.42",
            src_ip="127.0.0.1",
            build_pcap=True,
        )
        if result.get("pcap"):
            assert os.path.exists(result["pcap"])
            assert os.path.getsize(result["pcap"]) > 24  # more than just global header

    def test_unknown_scenario_raises(self, scenarios_path, tmp_outdir):
        with pytest.raises(ValueError, match="not found"):
            run_scenario(scenarios_path, "NONEXISTENT_SCENARIO", outdir=tmp_outdir)


class TestDetectionGenerator:
    def test_generate_suricata_rules(self):
        from icsforge.detections.generator import generate_all

        result = generate_all(technique_filter=["T0855", "T0801"])
        assert "suricata" in result
        assert result["count"] > 0
        assert "alert tcp" in result["suricata"]
        assert "sid:" in result["suricata"]

    def test_generate_sigma_rules(self):
        from icsforge.detections.generator import generate_all

        result = generate_all(technique_filter=["T0855"])
        assert "sigma" in result
        assert len(result["sigma"]) > 0
        for sc_id, rule in result["sigma"].items():
            assert "title:" in rule
            assert "attack.ics" in rule

    def test_techniques_covered(self):
        from icsforge.detections.generator import generate_all

        result = generate_all()
        assert len(result["techniques"]) > 30, "Should cover 30+ techniques"


class TestAlertMapping:
    def test_map_modbus_write(self):
        from icsforge.detection.mapping import map_alert_to_techniques

        alert = {"signature": "ET ICS Modbus Write Multiple Registers"}
        techs = map_alert_to_techniques(alert)
        assert "T0855" in techs

    def test_map_scan(self):
        from icsforge.detection.mapping import map_alert_to_techniques

        alert = {"signature": "ICS Network Scanning Detected"}
        techs = map_alert_to_techniques(alert)
        assert "T0840" in techs

    def test_correlate_run(self):
        from icsforge.detection.mapping import correlate_run

        expected = ["T0855", "T0801", "T0840"]
        alerts = [
            {"signature": "Modbus Write to PLC"},
            {"signature": "Network scan sweep detected"},
        ]
        result = correlate_run(expected, alerts)
        assert "expected" in result
        assert "observed" in result
        assert "gaps" in result
        assert "coverage_ratio" in result
        assert result["coverage_ratio"] >= 0.0
        assert result["coverage_ratio"] <= 1.0
