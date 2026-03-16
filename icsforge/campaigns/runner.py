"""
ICSForge Campaign Playbook Runner

A campaign is a time-sequenced list of scenario steps with configurable
delays between them.  Campaigns produce a single run_id and a unified
events artifact so the full campaign appears as one entry in run history
and the ATT&CK matrix overlay.

Campaign YAML format:
    name: My Campaign
    description: "Simulates a 3-phase OT attack"
    steps:
      - scenario: T0801__monitor_process__modbus_poll
        delay: 0s          # delay BEFORE this step
      - scenario: T0830__aitm__opcua_relay_session
        delay: 30s
      - scenario: T0889__modify_program__s7comm_upload_dl
        delay: 60s
"""
import json
import os
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

from icsforge.core import generate_run_id, parse_interval


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CampaignRunner:
    """Execute a campaign playbook, emitting progress callbacks."""

    def __init__(
        self,
        campaign: dict,
        scenarios_path: str,
        dst_ip: str,
        iface: str | None = None,
        timeout: float = 2.0,
        outdir: str = "out",
        progress_cb: Callable[[dict], None] | None = None,
    ):
        self.campaign     = campaign
        self.scenarios_path = scenarios_path
        self.dst_ip       = dst_ip
        self.iface        = iface
        self.timeout      = timeout
        self.outdir       = outdir
        self.progress_cb  = progress_cb or (lambda ev: None)
        self.run_id       = generate_run_id()
        self.events_path  = os.path.join(outdir, f"campaign_{self.run_id}_events.jsonl")
        self._stop        = threading.Event()

    def _emit(self, ev: dict):
        ev["run_id"]        = self.run_id
        ev["campaign"]      = self.campaign.get("name", "unnamed")
        ev["@timestamp"]    = _now()
        os.makedirs(os.path.dirname(self.events_path) or ".", exist_ok=True)
        with open(self.events_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        self.progress_cb(ev)

    def run(self) -> dict:
        from icsforge.live.sender import send_scenario_live

        steps   = self.campaign.get("steps", [])
        total   = len(steps)
        results = []
        errors  = []

        self._emit({
            "event": "campaign_start",
            "total_steps": total,
            "scenarios": [s.get("scenario") for s in steps],
        })

        for idx, step in enumerate(steps, start=1):
            if self._stop.is_set():
                self._emit({"event": "campaign_aborted", "at_step": idx})
                break

            sc_name = step.get("scenario", "")
            delay   = parse_interval(str(step.get("delay", "0s")))
            label   = step.get("label", sc_name)

            if delay > 0:
                self._emit({"event": "delay", "step": idx, "seconds": delay,
                             "next": sc_name})
                deadline = time.time() + delay
                while time.time() < deadline and not self._stop.is_set():
                    time.sleep(min(0.5, deadline - time.time()))

            if self._stop.is_set():
                break

            self._emit({"event": "step_start", "step": idx, "total": total,
                         "scenario": sc_name, "label": label})

            try:
                res = send_scenario_live(
                    scenario_file=self.scenarios_path,
                    scenario_name=sc_name,
                    dst_ip=self.dst_ip,
                    iface=self.iface,
                    confirm_live_network=True,
                    receiver_allowlist=[self.dst_ip],
                    timeout=self.timeout,
                )
                results.append({"step": idx, "scenario": sc_name,
                                 "sent": res.get("sent", 0),
                                 "warnings": res.get("warnings", [])})
                self._emit({"event": "step_ok", "step": idx, "scenario": sc_name,
                             "sent": res.get("sent", 0)})
            except Exception as e:
                errors.append({"step": idx, "scenario": sc_name, "error": str(e)})
                self._emit({"event": "step_error", "step": idx,
                             "scenario": sc_name, "error": str(e)})

        self._emit({"event": "campaign_complete",
                     "steps_ok": len(results), "steps_err": len(errors)})

        return {
            "run_id":      self.run_id,
            "events_path": self.events_path,
            "steps_ok":    len(results),
            "steps_err":   len(errors),
            "results":     results,
            "errors":      errors,
        }

    def stop(self):
        self._stop.set()
