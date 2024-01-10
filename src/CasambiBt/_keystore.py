import binascii
import logging
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass()
class Key:
    id: int
    type: int
    role: int
    name: str
    key: bytes


class KeyStore:
    def __init__(self, cacheDir: Path) -> None:
        self._keys: list[Key] = []
        self._logger = logging.getLogger(__name__)

        self._storePath = cacheDir / "keys.pck"
        if self._storePath.exists():
            self._load()

    def _load(self) -> None:
        self._logger.debug("Loading keys...")
        self._keys = pickle.load(self._storePath.open("rb"))
        self._logger.debug(f"Loaded {len(self._keys)} keys.")

    def _save(self) -> None:
        self._logger.debug("Saving keys...")
        pickle.dump(self._keys, (self._storePath.open("wb")))

    def addKey(self, _dict: dict) -> None:
        if "id" not in _dict:
            raise KeyError("id")
        id = int(_dict["id"])
        if id < 0:
            raise ValueError("id")

        if any(filter(lambda k: k.id == id, self._keys)):  # type: ignore
            self._logger.debug(f"Key with id {id} already exists. Skipping...")
            return

        if "type" not in _dict:
            raise KeyError("type")
        type = int(_dict["type"])
        if type < 0 or type > 0xFF:
            raise ValueError("type")

        if "role" not in _dict:
            raise KeyError("role")
        role = int(_dict["role"])
        if role < 0 or role > 3:
            raise ValueError("role")

        if "name" not in _dict:
            raise KeyError("name")
        name = _dict["name"]

        if "key" not in _dict:
            raise KeyError("key")
        try:
            key = binascii.a2b_hex(_dict["key"])
            # get binary representation of hexadecimal string _dict["key"]
        except binascii.Error:
            raise ValueError("key")

        keyObj = Key(id, type, role, name, key)
        self._keys.append(keyObj)
        self._logger.debug(f"Added key {name} with role {role} to store.")
        self._save()

    def clear(self, save: bool = False) -> None:
        self._keys.clear()
        self._logger.debug("Keystore cleared.")
        if save:
            self._save()

    def size(self) -> int:
        return len(self._keys)
    
    def getKey(self) -> Optional[Key]:
        key: Optional[Key] = None
        for k in self._keys:
            if not key:
                key = k
            elif key.role < k.role:
                key = k
        return key
