from main import SOCEngine
from models import Alert, Severity
from datetime import datetime

def test_engine_initialization():
    engine = SOCEngine()
    assert engine.queue.size() == 0
    assert len(engine.resolved_incidents) == 0

def test_engine_process_alert():
    engine = SOCEngine()
    alert = Alert(
        id="test-001",
        type="test_alert",
        source="1.1.1.1",
        severity=Severity.HIGH,
        description="Test alert",
        timestamp=datetime.now(),
        ioc_confidence=0.9,
        asset_criticality=0.8
    )
    engine.process_new_alert(alert)
    assert engine.queue.size() == 1
