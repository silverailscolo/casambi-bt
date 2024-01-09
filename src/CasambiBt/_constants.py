from typing import Final
from enum import IntEnum, unique

DEVICE_NAME: Final = "Casambi BT Python"

CASA_UUID: Final = "0000fe4d-0000-1000-8000-00805f9b34fb"
CASA_AUTH_CHAR_UUID: Final = "c9ffde48-ca5a-0001-ab83-8f519b482f77"
CASA_AUTH_CHAR_UUID2: Final = "c9ffde48-ca5a-0002-ab83-8f519b482f77"
CASA_AUTH_CHAR_UUID3: Final = "c9ffde48-ca5a-0003-ab83-8f519b482f77"

@unique
class NetworkGrade(IntEnum):
    CLASSIC = 0
    EVOLUTION = 1
