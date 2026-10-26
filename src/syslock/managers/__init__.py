"""Package manager backends, in detection order."""

from typing import Dict, List

from .apk import Apk
from .apt import Apt
from .base import Manager
from .brew import Brew
from .pacman import Pacman
from .rpm import Rpm

ALL: Dict[str, Manager] = {m.name: m for m in (Apt(), Rpm(), Apk(), Pacman(), Brew())}


def detect() -> List[Manager]:
    return [m for m in ALL.values() if m.available()]


def get(name: str) -> Manager:
    if name not in ALL:
        raise KeyError(name)
    return ALL[name]
