import struct
from enum import IntEnum, unique


@unique
class OpCode(IntEnum):
    Response = 0
    SetLevel = 1
    SetVertical = 4
    SetWhite = 5
    SetColor = 7
    SetTemperature = 10
    SetState = 48


class OperationsContext:
    def __init__(self) -> None:
        self.origin: int = 1
        self.lifetime: int = 5

    def prepareOperation(self, op: OpCode, target: int, payload: bytes) -> bytes:
        if len(payload) > 63:
            raise ValueError("Payload too long")

        flags = (self.lifetime & 15) << 11 | len(payload)

        # Ensure that origin can't overflow.
        # TODO: Check that unsigned is actually correct here.
        packet = struct.pack(
            ">HBHHH", flags, op, self.origin & (2**16 - 1), target, 0
        )
        self.origin += 1

        return packet + payload

    def prepareOperationClassic(self, op: OpCode, target: int, payload: bytes) -> bytes:
        if len(payload) > 13:  # EBR shorter payload in CLASSSIC
            raise ValueError("Payload too long")
        # turn off: 0x00 invoegen voor laatste paar
        # turn on = lamp + helderheid

        flags = (self.lifetime & 15) << 11 | len(payload)
        # bitwise: & = AND, | = OR, << = shiftleft

        # Ensure that origin can't overflow.
        # TODO: Check that unsigned is actually correct here.
        packet = struct.pack(
            ">BIBBB", b'\x02', target, op, 0
        ) # H = unsigned short, B = unsigned char
        self.origin += 1

        return packet + payload
