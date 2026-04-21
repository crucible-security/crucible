
from __future__ import annotations

from abc import ABC, abstractmethod

from crucible.models import ScanResult

class BaseReporter(ABC):

    @abstractmethod
    def render(self, result: ScanResult) -> None:
        ...

