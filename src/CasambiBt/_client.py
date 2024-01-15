import asyncio
import logging
import struct
from binascii import b2a_hex as b2a
from enum import IntEnum, unique
from hashlib import sha256
from typing import Any, Callable, Optional, Union

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.client import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import (
    BleakNotFoundError,
    close_stale_connections,
    establish_connection,
    get_device,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from ._constants import CASA_AUTH_CHAR_UUID, CASA_AUTH_CHAR_UUID2, CASA_AUTH_CHAR_UUID3, NetworkGrade
from ._encryption import Encryptor
from ._keystore import KeyStore


@unique
class ConnectionState(IntEnum):
    NONE = 0
    CONNECTED = 1
    KEY_EXCHANGED = 2
    AUTHENTICATED = 3
    CONNECTED_UNENCRYPTED = 4  # for CLASSIC TODO required?
    ERROR = 99


# We need to move these imports here to prevent a cycle.
from .errors import (  # noqa: E402
    BluetoothError,
    ConnectionStateError,
    NetworkNotFoundError,
    ProtocolError,
)


@unique
class IncomingPacketType(IntEnum):
    ClassicOffline = 2
    UnitState = 6
    NetworkConfig = 9
    ClassicStateSet = 130 # 0x82
    ClassicOff = 162 # 0xA2
    ClassicSetScene = 194 # 0xC2


class CasambiClient:
    def __init__(
        self,
        address_or_device: Union[str, BLEDevice],
        dataCallback: Callable[[IncomingPacketType, dict[str, Any]], None],
        disconnectedCallback: Callable[[], None],
    ) -> None:
        self._gattClient: BleakClient
        self._notifySignal = asyncio.Event()

        self._mtu: int
        self._unitId: int
        self._flags: int
        self._nonce: bytes
        self._key: bytearray

        self._encryptor: Encryptor

        self._outPacketCount = 0
        self._inPacketCount = 0

        self._networkGrade = NetworkGrade.EVOLUTION  # or .CLASSIC # todo use json grade attribute?

        self._callbackQueue: asyncio.Queue[tuple[BleakGATTCharacteristic, bytes]]
        self._callbackTask: Optional[asyncio.Task[None]] = None

        self._address_or_device = address_or_device
        self.address = (
            address_or_device.address
            if isinstance(address_or_device, BLEDevice)
            else address_or_device
        )
        self._logger = logging.getLogger(__name__)
        self._connectionState: ConnectionState = ConnectionState.NONE
        self._dataCallback = dataCallback
        self._disconnectedCallback = disconnectedCallback
        self._activityLock = asyncio.Lock()

    def _checkState(self, desired: ConnectionState) -> None:
        if self._connectionState != desired:
            raise ConnectionStateError(desired, self._connectionState)

    async def connect(self) -> None:
        self._checkState(ConnectionState.NONE)

        self._logger.debug(f"Client connecting to {self.address}")

        # Reset packet counters
        self._outPacketCount = 2
        self._inPacketCount = 1

        # Reset callback queue
        self._callbackQueue = asyncio.Queue()
        self._callbackTask = asyncio.create_task(self._processCallbacks())

        # To use bleak_retry_connector we need to have a BLEDevice, so get one if we only have the address.
        device = (
            self._address_or_device
            if isinstance(self._address_or_device, BLEDevice)
            else await get_device(self.address)
        )

        if not device:
            self._logger.error("Failed to discover client.")
            raise NetworkNotFoundError

        try:
            # If we are already connected to the device, the key exchange will fail.
            await close_stale_connections(device)
            # TODO: Should we try to get access to the network name here?
            self._gattClient = await establish_connection(
                BleakClient, device, "Casambi Network", self._on_disconnect
            )
        except BleakNotFoundError as e:
            # Guess that this is the error reason since there are no better error types
            self._logger.error("Failed to find client.", exc_info=True)
            raise NetworkNotFoundError from e
        except BleakError as e:
            self._logger.error("Failed to connect.", exc_info=True) # error on Classic network
            raise BluetoothError(e.args) from e
        except Exception as e:
            self._logger.error("Unknown connection failure.", exc_info=True)
            raise BluetoothError from e

        self._logger.debug(f"Connected to {self.address}")
        self._connectionState = ConnectionState.CONNECTED

    def _on_disconnect(self, client: BleakClient) -> None:
        if self._connectionState != ConnectionState.NONE:
            self._logger.debug(f"Received disconnect callback from {self.address}")
        if self._connectionState == ConnectionState.AUTHENTICATED or self._connectionState == ConnectionState.CONNECTED_UNENCRYPTED: # for CLASSIC
            self._disconnectedCallback()
        self._connectionState = ConnectionState.NONE

    async def exchangeKey(self, keystore: KeyStore) -> None:
        # only for EVOLUTION, not used in CLASSIC
        self._checkState(ConnectionState.CONNECTED)

        self._logger.debug("Starting secure key exchange...")

        await self._activityLock.acquire()
        try:
            # Initiate communication with device            
            firstResp = await self._gattClient.read_gatt_char(CASA_AUTH_CHAR_UUID)
                        
            # Check type and protocol version
            if not (firstResp[0] == 0x1 and firstResp[1] == 0xA):
                self._connectionState = ConnectionState.ERROR
                raise ProtocolError(
                    "Unexpected answer from device! Wrong device or non-Evolution network protocol?"
                )

            # Parse device info
            self._mtu, self._unitId, self._flags, self._nonce = struct.unpack_from(
                ">BHH16s", firstResp, 2 # "BHH16s" = format string, 2 = offset
            )
            self._logger.debug(
                f"Parsed Evolution mtu {self._mtu}, unit {self._unitId}, flags {self._flags}, nonce {b2a(self._nonce)}"
            )

            # Device will initiate key exchange, so listen for that
            self._logger.debug("Starting notify")
            await self._gattClient.start_notify(CASA_AUTH_CHAR_UUID, self._queueCallback)
            self._logger.debug("sleep notify")
            await asyncio.sleep(5.0)
            await self._gattClient.stop_notify(CASA_AUTH_CHAR_UUID)
            
            await self._gattClient.start_notify(
                CASA_AUTH_CHAR_UUID, self._queueCallback
            )
        finally:
            self._activityLock.release()

        # Wait for EVOLUTION key exchange, will get notified by _exchNotifyCallback
        self._logger.debug("Key exchange Evolution - _notifySignal")
        await self._notifySignal.wait()  # Classic blocked here. BLE4.0 without Secure Connect
        self._logger.debug("Key exchange - lock")
        await self._activityLock.acquire()
        try:
            self._logger.debug("Key exchange - clearing signal")
            self._notifySignal.clear()
            if self._connectionState == ConnectionState.ERROR:
                raise ProtocolError("Invalid key exchange initiation.")

            # Respond to key exchange
            pubNums = self._pubKey.public_numbers()
            keyExchResponse = struct.pack(
                ">B32s32sB",
                0x2,
                pubNums.x.to_bytes(32, byteorder="little", signed=False),
                pubNums.y.to_bytes(32, byteorder="little", signed=False),
                0x1,
            )
            self._logger.debug("Key exchange - write_gatt_char")
            await self._gattClient.write_gatt_char(CASA_AUTH_CHAR_UUID, keyExchResponse)
        finally:
            self._activityLock.release()

        # Wait for success response from _exchNotifyCallback
        self._logger.debug("waiting for _exchNotifyCallback")
        await self._notifySignal.wait()  # Classic blocked here
        # it seems there's no security key exchange on Classic networks
        await self._activityLock.acquire()
        try:
            self._notifySignal.clear()
            if self._connectionState == ConnectionState.ERROR:  # type: ignore[comparison-overlap]
                raise ProtocolError("Failed to negotiate key!")
            else:
                self._logger.debug("Key exchange successful")
                self._encryptor = Encryptor(self._transportKey)

                # Skip auth if the network doesn't use a key.
                if keystore.getKey():
                    self._connectionState = ConnectionState.KEY_EXCHANGED
                else:
                    self._connectionState = ConnectionState.AUTHENTICATED
        finally:
            self._activityLock.release()

    async def classicStart(self, keystore: KeyStore) -> None:
        # only for CLASSIC
        self._checkState(ConnectionState.CONNECTED)

        self._logger.debug("CLASSIC starting unencrypted connect")

        await self._activityLock.acquire()
        try:
            # Initiate communication with device

            services = self._gattClient.services
            # try to learn. Only 1 returned in my CLASSIC grade network, we see 3 Characeristics in sniffer EBR
            for s in services:
                self._logger.debug(f"service: {s}") 
            # Result: service: 0000fe4d-0000-1000-8000-00805f9b34fb (Handle: 7): Casambi Technologies Oy

            # matches expected _constants.CASA_UUID. Try to connect...
            firstResp = await self._gattClient.read_gatt_char(CASA_AUTH_CHAR_UUID) # also correct for Classic
            self._logger.debug(f"Response: {firstResp}")

            # test2 Got b'9b8ae399081d1b58 06 a24d 05 00'
            # test3 Got b'dac9cfd20e5b5ab3 06 a24d 05 00'
            # test4 Got b'1ab4c23dea967629 08 a24d 05 00'
            # test5 Got b'236f2ba0486eb51a 06 a24d 05 00'
            # test6 Got b'7b78f2d6d62fce73 08 a24d 05 00'
##            service: 0000fe4d-0000-1000-8000-00805f9b34fb (Handle: 7): Casambi Technologies Oy
##            Service bytearray(b'\x19\xf1\xe8\xa9\xa7\xbe[A\x08\xa2M\x05\x00')
##            Service bytearray(b'\x00') < always returns value 0

##            Service bytearray(b'\x83\x0c\xfcSL\x82*=\x08\xa2M\x05\x00')
##            service: c9ffde48-ca5a-0002-ab83-8f519b482f77 (not in GATT)

##            Response: bytearray(b'\xda\xb8\xd8\x1d_\xc8\x16\xae\x08\xa2M\x05\x00')

##            Response: bytearray(b'\xec\x0fRll\x19\xdeI\x08\xa2M\x05\x00')

##            Response: bytearray(b'"\xa8\x90Y\xdb\xf5\x95X\x08\xa2M\x05\x00')
            
##            Response: bytearray(b'\xd29\x9f\x88\x97\x9a\x95f\x06\xa2M\x05\x00')
##            Parsed Classic nonce 15148314230645232998, unitId 6, flags 162, Brightness 5, Vertical 77

##            Response: bytearray(b'\xfcg5\xeb\xadRF\x8c\x06\xa2M\x05\x00')
##            Parsed Classic nonce 18187564906500474508, unitId 6, flags 162, Brightness 5, Vertical 77

##            Response: bytearray(b'SY\xa8f\xd8V*u\x08\xa2M\x05\x00')
##            Parsed Classic nonce 6006016737744923253, unitId 8, flags 162, Brightness 5, Vertical 77

##            Response: bytearray(b'\xae\xddx\x9f\x19\xe8|\x14\x06\xa2M\x05\x00')
##            Parsed Classic nonce 12600359957182315540, unitId 6, flags 162, Brightness 77, Vertical 5
            
##            Response: bytearray(b'\xc6\xa5\xc5\x0f\x01W\xe7\xeb\x06\xa2M\x05\x00')
##            Parsed Classic nonce:14314063658904709099, unitId:6, opc:162, opc2:77, Brightness:5, Vertical:0

##            Response: bytearray(b'\xa0mhS!\x1fq\x86\x08\xa2M\x05\x00')
##            Parsed Classic nonce:11560010524777214342, unitId:8, opc:162, opc2:77, Brightness:5, Vertical:0

##            Response: bytearray(b'\x04\xaf\xb79f\xafK\xfb\x08\xa2M\x05\x00')
##            Parsed Classic nonce:337689954239859707, unitId:8, opc:162, opc2:77, Brightness:5, Vertical:0

            # unpack first read response from Slave
            self._nonce, self._unitId, opc, mtu, B, V = struct.unpack_from(
                ">QBBBBB", firstResp, 0  # patroon random(16) + altijd 08 a2 4d 05 00
                  # "BHH4s" = format string, 2 = offset
            )
            self._logger.debug(
                f"Parsed Classic nonce:{self._nonce}, unitId:{self._unitId}, opc:{opc}, mtu:{mtu}, Brightness:{B}, Vertical:{V}"
            )
             
            # (Classic firstResp size is 13 hex bytes)
                
            # descr = self._gattClient.read_gatt_descriptor
            # self._logger.debug(f"descriptor: {descr}")
            # descriptor: <bound method BleakClient.read_gatt_descriptor of <BleakClient, EB6F92F7-3599-159F-9782-0398CE2AA4E5, <class 'bleak.backends.corebluetooth.client.BleakClientCoreBluetooth'>>>

            #characteristics = self._gattClient.characteristics # .characteristics not available in Casambi
            #for c in characteristics:
            #    self._logger.debug(f"characteristics: {c}") 
                        
            self._logger.debug("Connect followup - start notify")
            # Device will initiate connection, so listen for that
            #await self._gattClient.start_notify(CASA_AUTH_CHAR_UUID, self.my_notification_handler)

            #self._logger.debug("sleep notify")
            #await asyncio.sleep(5.0)
            #await self._gattClient.stop_notify(CASA_AUTH_CHAR_UUID)

            self._logger.debug("Starting notify 2")
            await self._gattClient.start_notify(
                CASA_AUTH_CHAR_UUID, self._queueCallback
            )

##            Connect followup - write_gatt_char
##            Starting notify
##            sleep notify
##            Starting notify 2
##            waiting for _ClassicStartCallback
            
        finally:
            self._activityLock.release()

        # Wait for success response from _ClassicStartCallback
##        self._logger.debug("waiting for _ClassicStartCallback")
##        await self._notifySignal.wait()  # <<<<<<<< blocking here
##
##        await self._activityLock.acquire()
##        try:
##            self._notifySignal.clear()
##            if self._connectionState == ConnectionState.ERROR:  # type: ignore[comparison-overlap]
##                raise ProtocolError("Failed to follow up!")
##            # Skip auth because CLASSIC network doesn't use encryption.
##
##        finally:
##            self._activityLock.release()

        # CLASSIC uses simple connect() or Just Works, STK = 0 ?
        self._connectionState = ConnectionState.CONNECTED_UNENCRYPTED
        self._logger.debug("Classic connect successful")

        #TODO EBR fetch 0002?
##        self._logger.debug("uuid: c9ffde48-ca5a-0002-ab83-8f519b482f77 (not in GATT)") 
##        secondResp = await self._gattClient.read_gatt_char(CASA_AUTH_CHAR_UUID2) # seen on Classic
##        self._logger.debug(f"Response: {secondResp}")
        # EBR process first read response via Notify

        # Write Request 1
        await self._activityLock.acquire()
        try:
            self._logger.debug("Classic connect - clearing signal")
            self._notifySignal.clear()
            if self._connectionState == ConnectionState.ERROR:
                raise ProtocolError("Invalid key exchange initiation.")

            # Respond to first read response
            #self._key = keystore.getKey().key  # Session key
            self._key = b'1234' # PRIVATE EBR
            self._logger.debug(f"Key {self._key} length={len(self._key)}") # <<< TODO fix Error Key b'Triangel1' length=9
            self._encryptor = Encryptor(self._key) # special transport_key?
            messagePrefix = b'\x02'
            index = b'\x0001'
            messageOpc = b'\x00'
            messageState = b'\x010b'
            mac = self._encryptor.cmac(bytes(index + messageOpc + messageState))

##            c = cmac.CMAC(algorithms.AES(b'7226a03a5f8d34b7e581b2a9fdef3767')) < key
##            c.update(b"000100010b")
##            c.finalize()
##            E296B93AEEB81B1DE994 = 10x2 = te lang, verwacht 4 byte/8 hex cijfers. Slice
##            met prefix: 02 E296B93AEEB81B1DE994 000100010b
##            packet[:8] use first part, length = 8

            firstResponse = messagePrefix + mac + index + messageOpc + messageState
##            firstResponse = struct.pack(
##                ">BIHBH",
##                messagePrefix,
##                mac, # cmac4, # 
##                index, #startnum,
##                messageOpc,
##                messageState
##            )
            self._logger.debug(f"Write gatt_char {firstResponse}")
            await self._gattClient.write_gatt_char(CASA_AUTH_CHAR_UUID, firstResponse)

##            Starting notify 2
##            Classic connect successful
##            Classic connect - clearing signal
##            Key b'9226a03a53fd34b7e5d7b2a9fdbf3780' length=32
##            CMAC is b'd283062bd7f6dc7a4766bab8b5aba018'
##            Write gatt_char b'\x02\xd2\x83\x06+\xd7\xf6\xdczGf\xba\xb8\xb5\xab\xa0\x18\x0001\x00\x010b'
##            Demo connected

        finally:
            self._activityLock.release()
 
    def setNetworkGrade(self, grade: NetworkGrade) -> None:
        self._networkGrade = grade

    async def my_notification_handler(sender, data):
        # Notify function for CLASSIC first response EBR
        sender._logger.debug("_notify" + (', '.join('{:02x}'.format(x) for x in data)))
        sender._logger.debug(f"Notify Response: {data}")
    
    def _queueCallback(self, handle: BleakGATTCharacteristic, data: bytes) -> None:
        self._logger.debug("Starting _queueCallback")
        self._callbackQueue.put_nowait((handle, data))

    async def _processCallbacks(self) -> None:
        self._logger.debug("_processCallbacks")
        while True:
            handle, data = await self._callbackQueue.get()
            await self._activityLock.acquire()
            try:
                self._callbackMultiplexer(handle, data)
            finally:
                self._callbackQueue.task_done()
                self._activityLock.release()

    def _callbackMultiplexer(
        self, handle: BleakGATTCharacteristic, data: bytes
    ) -> None:
        self._logger.debug(f"Callback on handle {handle}: {b2a(data)}")

        if self._connectionState == ConnectionState.CONNECTED:
            self._exchNotifyCallback(handle, data)
        elif self._connectionState == ConnectionState.KEY_EXCHANGED:
            self._authNotifyCallback(handle, data)
        elif self._connectionState == ConnectionState.AUTHENTICATED:
            self._establishedNotifyCallback(handle, data)
        elif self._connectionState == ConnectionState.CONNECTED_UNENCRYPTED: # CLASSIC
            self._establishedNotifyCallback(handle, data)
        else:
            self._logger.warning(
                f"Unhandled notify in state {self._connectionState}: {b2a(data)}"
            )

    def _exchNotifyCallback(self, handle: BleakGATTCharacteristic, data: bytes) -> None:
        # only for EVOLUTION
        self._logger.debug(f"_exchNotifyCallback data: {b2a(data)}.")
        if data[0] == 0x2:
            # Parse device pubkey
            x, y = struct.unpack_from("<32s32s", data, 1)
            x = int.from_bytes(x, byteorder="little")
            y = int.from_bytes(y, byteorder="little")
            self._logger.debug(f"Got public key {x}, {y}")

            self._devicePubKey = ec.EllipticCurvePublicNumbers(
                x, y, ec.SECP256R1()
            ).public_key()

            # Generate key pair for client
            self._privKey = ec.generate_private_key(ec.SECP256R1())
            self._pubKey = self._privKey.public_key()

            # Generate shared secret
            secret = bytearray(self._privKey.exchange(ec.ECDH(), self._devicePubKey))
            secret.reverse()
            hashAlgo = sha256()
            hashAlgo.update(secret)
            digestedSecret = hashAlgo.digest()

            # Compute transport key
            self._transportKey = bytearray()
            for i in range(16):
                self._transportKey.append(digestedSecret[i] ^ digestedSecret[16 + i])

            # Inform exchangeKey that packet has been parsed
            self._notifySignal.set()

        elif data[0] == 0x3:
            self._logger.debug("NotifyCallback - data[0] == 0x3")
            if len(data) == 1:
                # Key exchange is acknowledged by device
                self._notifySignal.set()
            else:
                self._logger.error(
                    f"Unexpected package length for key exchange response: {b2a(data)}"
                )
                self._connectionState = ConnectionState.ERROR
                self._notifySignal.set()
        else:
            self._logger.error(f"Unexpected package type in {b2a(data)}.")
            self._connectionState = ConnectionState.ERROR
            self._notifySignal.set()

    async def authenticate(self, keystore: KeyStore) -> None:
        # only for EVOLUTION
        self._checkState(ConnectionState.KEY_EXCHANGED)

        self._logger.debug("Authenticating channel...")
        key = keystore.getKey()  # Session key, returns key with the highest role (0-3)

        if not key:
            self._logger.debug("No key in keystore. Skipping auth.")
            # The channel already has to be set to authenticated by exchangeKey.
            # This needs to be done because a non-handshake packet could be sent right after acking the key exch,
            # and we don't want that packet to end up in _authNotifyCallback.
            return

        await self._activityLock.acquire()
        try:
            # Compute client auth digest
            hashFcnt = sha256()
            hashFcnt.update(key.key)
            hashFcnt.update(self._nonce)
            hashFcnt.update(self._transportKey) # AttributeError: 'CasambiClient' object has no attribute '_transportKey'
            authDig = hashFcnt.digest()
            self._logger.debug(f"Auth digest: {b2a(authDig)}")

            # Send auth packet
            authPacket = int.to_bytes(1, 4, "little")
            authPacket += b"\x04"
            authPacket += key.id.to_bytes(1, "little")
            authPacket += authDig
            await self._writeEncPacket(authPacket, 1, CASA_AUTH_CHAR_UUID)
        finally:
            self._activityLock.release()

        # Wait for auth response
        await self._notifySignal.wait()

        await self._activityLock.acquire()
        try:
            self._notifySignal.clear()
            if self._connectionState == ConnectionState.ERROR:
                raise ProtocolError("Failed to verify authentication response.")
            else:
                self._connectionState = ConnectionState.AUTHENTICATED
                self._logger.debug("Authentication successful")
        finally:
            self._activityLock.release()

    def _authNotifyCallback(self, handle: BleakGATTCharacteristic, data: bytes) -> None:
        # only for EVOLUTION
        self._logger.debug("Processing authentication response...")

        # TODO: Verify counter
        self._inPacketCount += 1

        try:
            self._encryptor.decryptAndVerify(data, data[:4] + self._nonce[4:])
        except InvalidSignature:
            self._logger.fatal("Invalid signature for auth response!")
            self._connectionState = ConnectionState.ERROR
            return

        # TODO: Verify Digest 2 (to compare with response from device); SHA256(key.key||self pubKey point||self._transportKey)

        self._notifySignal.set()

    async def _writeEncPacket(
        self, packet: bytes, _id: int, char: Union[str, BleakGATTCharacteristic]
    ) -> None:
        encPacket = self._encryptor.encryptThenMac(packet, self._getNonce(_id))
        try:
            await self._gattClient.write_gatt_char(char, encPacket)
        except BleakError as e:
            if e.args[0] == "Not connected":
                self._connectionState = ConnectionState.NONE
            else:
                raise e

    def _getNonce(self, _id: Union[int, bytes]) -> bytes:
        if isinstance(_id, int):
            _id = _id.to_bytes(4, "little")
        return self._nonce[:4] + _id + self._nonce[8:]

    async def send(self, packet: bytes) -> None:
        if self._networkGrade == NetworkGrade.EVOLUTION:
            self._checkState(ConnectionState.AUTHENTICATED)

            await self._activityLock.acquire()
            try:
                self._logger.debug(
                    f"Sending packet {b2a(packet)} with counter {self._outPacketCount}"
                )

                counter = int.to_bytes(self._outPacketCount, 4, "little")
                headerPacket = counter + b"\x07" + packet

                self._logger.debug(f"Packet with header: {b2a(headerPacket)}")

                await self._writeEncPacket(
                    headerPacket, self._outPacketCount, CASA_AUTH_CHAR_UUID
                )
                self._outPacketCount += 1
            finally:
                self._activityLock.release()
                
        elif self._networkGrade == NetworkGrade.CLASSIC:
            self._checkState(ConnectionState.CONNECTED_UNENCRYPTED) # TODO EBR fix before for Classic
            await self._activityLock.acquire()
            try:
                self._logger.debug(
                    f"Sending packet {b2a(packet)} with counter {self._outPacketCount}"
                )
                # prepare response
                messagePrefix = b'\02'
                mac = self._encryptor.cmac(self._outPacketCount + packet)
                m = struct.pack(
                    ">BIHBH",
                    messagePrefix,
                    mac,
                    self._outPacketCount,
                    packet
                )
                
                self._logger.debug(f"Packet with header: {b2a(headerPacket)}")
                # READ-ONLY for DEV EBR
                #currentval = await self._gattClient.read_gatt_char(CASA_AUTH_CHAR_UUID)
                self._logger.debug(f"Read packet currentval = {b2a(currentval)}. Notify started")
                                
                await self._gattClient.write_gatt_char(CASA_AUTH_CHAR_UUID, m, response=True) # experimental for Classic
                # await self._writeEncPacket( # EncPacket = only for Evolution
                #    headerPacket, self._outPacketCount, CASA_AUTH_CHAR_UUID
                #)
                self._outPacketCount += 1
            finally:
                self._activityLock.release()
        else:
            self._logger.debug(f"Unknown network grade {self._networkGrade}")

    def notifyCallback(
        self, sender: BleakGATTCharacteristic, data: bytearray
    ) -> None:
        print(f"{sender}: {data}")
    
    def _establishedNotifyCallback(
        self, handle: BleakGATTCharacteristic, data: bytes
    ) -> None:
        # TODO: Check incoming counter and direction flag
        self._inPacketCount += 1

        if self._networkGrade == NetworkGrade.EVOLUTION:
            try:
                data = self._encryptor.decryptAndVerify(data, data[:4] + self._nonce[4:])
            except InvalidSignature:
                # We simply drop packets with invalid signature here instead of going into an error state
                self._logger.error(f"Invalid signature for packet {b2a(data)}!")
                return
            
            packetType = data[0]
            self._logger.debug(f"Incoming data of type {packetType}: {b2a(data)}")

            if packetType == IncomingPacketType.UnitState:
                self._parseUnitStates(data[1:])
            elif packetType == IncomingPacketType.NetworkConfig:
                # We don't care about the config the network thinks it has.
                # We assume that cloud config and local config match.
                # If there is a mismatch the user can solve it using the app.
                # In the future we might want to parse the revision and issue a warning if there is a mismatch.
                pass
            else:
                self._logger.info(f"Packet type {packetType} not implemented. Ignoring!")
        elif self._networkGrade == NetworkGrade.CLASSIC:
            self._logger.debug(f"Incoming data {b2a(data)} Len {len(data)}")
            #if len(data) < 8:
            self._parseUnitStatesClassic(data)
        else:
            self._logger.debug(f"Unknown network grade {self._networkGrade}")

    def _parseUnitStates(self, data: bytes) -> None:
        self._logger.debug("Parsing incoming unit states...")
        self._logger.debug(f"Incoming unit state: {b2a(data)}")

        pos = 0
        oldPos = 0
        try:
            while pos <= len(data) - 4:
                id = data[pos]
                flags = data[pos + 1]
                stateLen = ((data[pos + 2] >> 4) & 15) + 1
                prio = data[pos + 2] & 15
                pos += 3

                online = flags & 2 != 0
                on = flags & 1 != 0

                if flags & 4:
                    pos += 1  # TODO: con?
                if flags & 8:
                    pos += 1  # TODO: sid?
                if flags & 16:
                    pos += 1  # Unknown value

                state = data[pos : pos + stateLen]
                pos += stateLen

                pos += (flags >> 6) & 3  # Padding?

                self._logger.debug(
                    f"Parsed state: Id {id}, prio {prio}, online {online}, on {on}, state {b2a(state)}1"
                )

                self._dataCallback(
                    IncomingPacketType.UnitState,
                    {"id": id, "online": online, "on": on, "state": state},
                )

                oldPos = pos
        except IndexError:
            self._logger.error(
                f"Ran out of data while parsing unit state! Remaining data {b2a(data[oldPos:])} in {b2a(data)}."
            )

    def _parseUnitStatesClassic(self, data: bytes) -> None:
        self._logger.debug(f"Parsing incoming Classic unit state: {b2a(data)}")

        # unpack notification data
        opc2 = 0
        # IncomingPacketType(IntEnum):
        # ClassicOffline  = 2
        # ClassicStateSet = 130 = 0x82
        # ClassicOff      = 162 = 0xA2
        # ClassicSetScene = 194 = 0xC2
        if len(data) == 4:
            unitId, opc, B, V = struct.unpack_from(
                ">BBBB", data, 0  # pattern: 08 82 05 00
            )
            online = 1
            on = B > 0
        elif len(data) == 5: # Turn OFF or set Scene
            unitId, opc, opc2, B, V = struct.unpack_from(
                ">BBBBB", data, 0  # pattern: 08 a2 (4d) 05 00
            )
            self._logger.debug(f"5 byte data of type {opc}")
            online = opc & 0x80 # use bitmask on opc bit 7
            on = B > 0
            # EVOLUTION: state = data[pos : pos + stateLen]
            if opc == IncomingPacketType.ClassicOffline:
                # turn off, ignore opc2
                pass
            elif opc == IncomingPacketType.ClassicOff:
                # ignore opc2, simply turn off
                if B > 0:
                    self._logger.warn(f"Turned off with Brightness {B}>0")
            elif opc == IncomingPacketType.ClassicSetScene:
                # use scene number from opc2
                sceneId = opc2
                # TODO
                pass
            else:
                self._logger.warn("unknown packettype")
        else:
            self._logger.debug(f"Received message of length{len(data)}")

        state = struct.pack('>BB', B, V) # repack state bytes
        self._dataCallback(
            IncomingPacketType.UnitState,
            {"id": unitId, "online": online, "on": on, "state": state},
        )            
        self._logger.debug(
            f"Parsed Classic status update for unitId {unitId}: opcode {self._flags}, Brightness {B}, Vertical {V}"
        )

    async def disconnect(self) -> None:
        self._logger.debug("Disconnecting...")

        if self._callbackTask:
            self._callbackTask.cancel()
            self._callbackTask = None
        # EBR: Classic Casambi Network returns error:
        # AttributeError: 'CasambiClient' object has no attribute '_gattClient'
        if hasattr(self, '_gattClient') and self._gattClient.is_connected:
            try:
                await self._gattClient.disconnect()
            except Exception:
                self._logger.error("Failed to disconnect BleakClient.", exc_info=True)

        self._connectionState = ConnectionState.NONE
        self._logger.debug("Disconnected.")
