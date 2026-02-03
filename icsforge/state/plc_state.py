class PLCState:
    """Lightweight in-memory tag/alarm model to support stateful scenarios."""
    def __init__(self):
        self.tags={}; self.alarms={}
    def read(self,tag): return self.tags.get(tag)
    def write(self,tag,val): self.tags[tag]=val
    def set_alarm(self,alarm,active=True): self.alarms[alarm]=active
    def snapshot(self): return {"tags":dict(self.tags),"alarms":dict(self.alarms)}
