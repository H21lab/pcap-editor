from abc import ABC, abstractmethod
from typing import List, Tuple
from models import Layer
from context import DissectionContext

class Dissector(ABC):
    @abstractmethod
    def check(self, data: bytes, ctx: DissectionContext) -> bool:
        pass

    @abstractmethod
    def dissect(self, data: bytes, ctx: DissectionContext, idx: int, offset: int) -> Tuple[List[Layer], int]:
        pass