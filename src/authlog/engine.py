"""Engine module for handling authentication log events and applying detection rules."""

from typing import Protocol

from authlog.alerts import Alert
from authlog.events import LoginEvent


class Rule(Protocol):
    def process(self, event: LoginEvent) -> list[Alert]:
        ...


class Engine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    def process(self, event: LoginEvent) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            alerts.extend(rule.process(event))
        return alerts
    