from datetime import datetime, timedelta

from authlog.alerts import Alert, Severity
from authlog.engine import Engine
from authlog.events import LoginEvent

T0 = datetime(2026, 10, 15, 14, 0, 0)


def event(seconds: int = 0, ip: str = "203.0.113.5") -> LoginEvent:
    return LoginEvent(
        timestamp=T0 + timedelta(seconds=seconds),
        host="web01",
        user="root",
        ip=ip,
        port=4000,
        success=False,
        method="password",
        invalid_user=False,
    )


# Fake rules: they don't inherit from Rule, they just have a matching process().


class AlwaysAlerts:
    """Raises one alert per event, tagged with its own name."""

    def __init__(self, name: str) -> None:
        self.name = name

    def process(self, event: LoginEvent) -> list[Alert]:
        return [Alert(event.timestamp, self.name, "T0000", Severity.LOW, event.ip)]


class NeverAlerts:
    def process(self, event: LoginEvent) -> list[Alert]:
        return []


class AlertsOnThirdEvent:
    """Only alerts once it has seen three events, so it needs state kept between calls."""

    def __init__(self) -> None:
        self.seen = 0

    def process(self, event: LoginEvent) -> list[Alert]:
        self.seen += 1
        if self.seen == 3:
            return [Alert(event.timestamp, "third", "T0000", Severity.LOW, event.ip)]
        return []


def test_no_rules_no_alerts():
    assert Engine([]).process(event()) == []


def test_rules_that_dont_fire_give_empty_list():
    assert Engine([NeverAlerts(), NeverAlerts()]).process(event()) == []


def test_alerts_come_out_in_rule_order():
    engine = Engine([AlwaysAlerts("first"), NeverAlerts(), AlwaysAlerts("second")])
    alerts = engine.process(event())
    assert [a.rule for a in alerts] == ["first", "second"]


def test_alert_carries_the_triggering_event():
    alerts = Engine([AlwaysAlerts("r")]).process(event(seconds=42, ip="198.51.100.7"))
    assert alerts[0].timestamp == T0 + timedelta(seconds=42)
    assert alerts[0].ip == "198.51.100.7"


def test_rule_state_persists_across_calls():
    engine = Engine([AlertsOnThirdEvent()])
    results = [engine.process(event(seconds=s)) for s in range(4)]
    assert [len(r) for r in results] == [0, 0, 1, 0]


def test_every_rule_sees_every_event():
    a, b = AlertsOnThirdEvent(), AlertsOnThirdEvent()
    engine = Engine([a, b])
    for s in range(3):
        engine.process(event(seconds=s))
    assert a.seen == 3
    assert b.seen == 3
