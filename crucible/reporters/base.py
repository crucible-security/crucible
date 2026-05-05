from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from crucible.models import ScanResult


class BaseReporter(ABC):

    @abstractmethod
    def render(self, result: ScanResult) -> None: ...
