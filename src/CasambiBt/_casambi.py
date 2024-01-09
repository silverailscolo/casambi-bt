import asyncio
import logging
from binascii import b2a_hex as b2a
from itertools import pairwise  # type: ignore[attr-defined]
from typing import Any, Callable, Optional, Union, cast

from bleak.backends.device import BLEDevice
from httpx import AsyncClient, RequestError

from ._client import CasambiClient, ConnectionState, IncomingPacketType
from ._network import Network
from ._constants import NetworkGrade
from ._operation import OpCode, OperationsContext
from ._unit import Group, Scene, Unit, UnitState
from .errors import ConnectionStateError, ProtocolError

class Casambi:
    """Class to manage one Casambi network.

    This is the central point of interaction and should be preferred to dealing with the internal components,
    e.g. ``Network`` or ``CasambiClient``, directly.
    """

    def __init__(self, httpClient: Optional[AsyncClient] = None) -> None:
        self._casaClient: Optional[CasambiClient] = None
        self._casaNetwork: Optional[Network] = None

        self._unitChangedCallbacks: list[Callable[[Unit], None]] = []

        self._logger = logging.getLogger(__name__)
        self._opContext = OperationsContext()
        self._ownHttpClient = httpClient is None
        self._httpClient = httpClient
        self._networkGrade = NetworkGrade.EVOLUTION # if it is a 5.0 BLE network
        # TODO this is updated to CLASSIC upon discovery as in demo EBR

    def _checkNetwork(self) -> None:
        if not self._casaNetwork or not self._casaNetwork._networkRevision:
            raise ConnectionStateError(
                ConnectionState.AUTHENTICATED,
                ConnectionState.NONE,
                "Network information missing.",
            )

    @property
    def networkName(self) -> str:
        self._checkNetwork()
        return self._casaNetwork._networkName  # type: ignore

    @property
    def networkId(self) -> str:
        return self._casaNetwork._id  # type: ignore

    @property
    def units(self) -> list[Unit]:
        """Get the units in the network if connected.

        :return: A list of all units in the network.
        :raises ConnectionStateError: There is no connection to the network.
        """
        self._checkNetwork()
        return self._casaNetwork.units  # type: ignore

    @property
    def groups(self) -> list[Group]:
        """Get the groups in the network if connected.

        :return: A list of all groups in the network.
        :raises ConnectionStateError: There is no connection to the network.
        """
        self._checkNetwork()
        return self._casaNetwork.groups  # type: ignore

    @property
    def scenes(self) -> list[Scene]:
        """Get the scenes of the network if connected.

        :return: A list of all scenes in the network.
        :raises ConnectionStateError: There is no connection to the network.
        """
        self._checkNetwork()
        return self._casaNetwork.scenes  # type: ignore

    @property
    def connected(self) -> bool:
        """Check whether there is an active connection to the network."""
        return (
            self._casaClient is not None
            and self._casaClient._connectionState == ConnectionState.AUTHENTICATED
        )

    async def connect(
        self,
        addr_or_device: Union[str, BLEDevice, tuple[BLEDevice, str]],
        password: str,
        forceOffline: bool = False,
    ) -> None:
        """Connect and authenticate to a network.

        :param addr_or_device: The MAC address of the network or a BLEDevice. Use `_discover` to find the address of a network.
        :param password: The password for the bluetooth network, also used to log in to api.casambi.com
        :param forceOffline: Whether to avoid contacting the api.casambi.com servers.
        :raises AuthenticationError: The supplied password is invalid.
        :raises ProtocolError: The network did not follow the expected protocol.
        :raises NetworkNotFoundError: No network was found under the supplied address.
        :raises NetworkOnlineUpdateNeededError: An offline update isn't possible in the current state.
        :raises BluetoothError: An error occurred in the bluetooth stack.
        """

        if isinstance(addr_or_device, tuple): # used for CLASSIC networks
                uuid = addr_or_device[1]
                addr_or_device = addr_or_device[0]
                self._networkGrade = NetworkGrade.CLASSIC
                self._logger.debug(f"CLASSIC uuid = {uuid}")
                
        if isinstance(addr_or_device, BLEDevice):
            addr = addr_or_device.address
        else:
            self._logger.debug(f"addr = {addr_or_device}")
            addr = addr_or_device
            # Add colons if necessary. # EBR: Why? They are taken out 20 lines later
            if ":" not in addr:
                addr_or_device = ":".join(["".join(p) for p in pairwise(addr)][::2])
            addr = addr_or_device

        self._logger.info(f"Trying to connect to Casambi BLE network address {addr}, uuid {uuid}")

        self._casaClient = CasambiClient(
            addr_or_device, self._dataCallback, self._disconnect_callback # same callback for CLASSIC Check EBR TODO?
        )
        self._casaClient.setNetworkGrade(self._networkGrade)

        if not self._httpClient:
            self._httpClient = AsyncClient()

        # Retrieve network information
        if (self._networkGrade == NetworkGrade.CLASSIC):
            uuid = uuid.replace(":", "").lower()
        else:
            uuid = addr.replace(":", "").lower()

        self._logger.debug(f"Look up info for uuid {uuid}")
        
        self._casaNetwork = Network(uuid, self._httpClient) # create new Network instance from uuid
        self._casaNetwork.setNetworkGrade(self._networkGrade) # TODO include as param in __init__ ?
        
        try:
            await self._casaNetwork.logIn(password, forceOffline) # logs in on api.casambi.com
        # TODO: I don't like that this logic is in this class but I couldn't think of a better way.
        except RequestError:
            self._logger.warning(
                "Network error while logging in on api.casambi.com. Trying to continue offline.",
                exc_info = True,
            )
            forceOffline = True

        await self._casaNetwork.update(forceOffline)
        await self._connectClient()

    async def _connectClient(self) -> None:
        """Initiate the bluetooth connection to a device."""
        self._casaClient = cast(CasambiClient, self._casaClient)
        await self._casaClient.connect() # connects to local Casambi BT client
        if self._networkGrade == NetworkGrade.EVOLUTION:
            try:
                await self._casaClient.exchangeKey(self._casaNetwork.getKeyStore())  # type: ignore[union-attr]
                await self._casaClient.authenticate(self._casaNetwork.getKeyStore())  # type: ignore[union-attr]
            except ProtocolError as e:
                await self._casaClient.disconnect()
                raise e

    async def setUnitState(self, target: Unit, state: UnitState) -> None:
        """Set the state of one unit directly.

        :param target: The targeted unit.
        :param state: The desired state.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        """
        stateBytes = target.getStateAsBytes(state)
        await self._send(target, stateBytes, OpCode.SetState)

    async def setLevel(self, target: Union[Unit, Group, None], level: int) -> None:
        """Set the level (brightness) for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param level: The desired level in range [0, 255]. If 0 the unit is turned off.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied level isn't in range
        """
        if level < 0 or level > 255:
            raise ValueError()

        payload = level.to_bytes(1, byteorder="big", signed=False)
        await self._send(target, payload, OpCode.SetLevel)

    async def setVertical(
        self, target: Union[Unit, Group, None], vertical: int
    ) -> None:
        """Set the vertical (balance between top and bottom LED) for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param vertical: The desired vertical balance in range [0, 255]. If 0 the unit is turned off.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied level isn't in range
        """
        if vertical < 0 or vertical > 255:
            raise ValueError()

        payload = vertical.to_bytes(1, byteorder="big", signed=False)
        await self._send(target, payload, OpCode.SetVertical)

    async def setWhite(self, target: Union[Unit, Group, None], level: int) -> None:
        """Set the white level for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param level: The desired level in range [0, 255].
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied level isn't in range
        """
        if level < 0 or level > 255:
            raise ValueError()

        payload = level.to_bytes(1, byteorder="big", signed=False)
        await self._send(target, payload, OpCode.SetWhite)

    async def setColor(
        self, target: Union[Unit, Group, None], rgbColor: tuple[int, int, int]
    ) -> None:
        """Set the rgb color for one or multiple units.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :param rgbColor: The desired color as a tuple of three ints in range [0, 255].
        :return: Nothing is returned by this function. To get the new state register a change handler.
        :raises ValueError: The supplied rgbColor isn't in range
        """

        state = UnitState()
        state.rgb = rgbColor
        hs: tuple[float, float] = state.hs  # type: ignore[assignment]
        hue = round(hs[0] * 1023)
        sat = round(hs[1] * 255)

        payload = hue.to_bytes(2, byteorder="little", signed=False) + sat.to_bytes(
            1, byteorder="little", signed=False
        )
        await self._send(target, payload, OpCode.SetColor)

    # TODO: Implement setTemperature
    # This isn't that easy since we don't have a min and max for the temperature.

    async def turnOn(self, target: Union[Unit, Group, None]) -> None:
        """Turn one or multiple units on to their last level.

        If ``target`` is of type ``Unit`` only this unit is affected.
        If ``target`` is of type ``Group`` the whole group is affected.
        if ``target`` is of type ``None`` all units in the network are affected.

        :param target: One or multiple targeted units.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        """

        # Use -1 to indicate special packet format
        # Use RestoreLastLevel flag (1) and UseFullTimeFlag (4).
        # Not sure what UseFullTime does but this is what the app uses.
        await self._send(target, b"\xff\x05", OpCode.SetLevel)

    async def switchToScene(self, target: Scene, level: int = 0xFF) -> None:
        """Switch the network to a predefined scene.

        :param target: The scene to switch to.
        :param level: An optional relative brightness for all units in the scene.
        :return: Nothing is returned by this function. To get the new state register a change handler.
        """
        await self.setLevel(target, level)  # type: ignore[arg-type]

    async def _send(
        self, target: Union[Unit, Group, Scene, None], state: bytes, opcode: OpCode
    ) -> None:
        if self._casaClient is None:
            raise ConnectionStateError(
                ConnectionState.AUTHENTICATED,
                ConnectionState.NONE,
            )

        targetCode = 0
        if isinstance(target, Unit):
            assert target.deviceId <= 0xFF
            targetCode = (target.deviceId << 8) | 0x01
        elif isinstance(target, Group):
            assert target.groudId <= 0xFF
            targetCode = (target.groudId << 8) | 0x02
        elif isinstance(target, Scene):
            assert target.sceneId <= 0xFF
            targetCode = (target.sceneId << 8) | 0x04
        elif target is not None:
            raise TypeError(f"Unknown target type {type(target)}")

        self._logger.debug(
            f"Sending operation {opcode.name} with payload {b2a(state)} for {targetCode:x}"
        )

        if self._networkGrade == NetworkGrade.CLASSIC:
            opPkt = self._opContext.prepareOperationClassic(opcode, targetCode, state)
        elif self._networkGrade == NetworkGrade.EVOLUTION:
            opPkt = self._opContext.prepareOperation(opcode, targetCode, state)
        else:
            raise TypeError(f"Unknown network grade {self._networkGrade}")
            
        try:
            await self._casaClient.send(opPkt)
        except ConnectionStateError as exc:
            if exc.got == ConnectionState.NONE:
                self._logger.info("Trying to reconnect broken connection once.")
                await self._connectClient()
                await self._casaClient.send(opPkt)
            else:
                raise exc

    def _dataCallback(
        self, packetType: IncomingPacketType, data: dict[str, Any]
    ) -> None:
        self._logger.info(f"Incoming data callback of type {packetType}")
        if packetType == IncomingPacketType.UnitState:
            self._logger.debug(
                f"Handling changed state {b2a(data['state'])} for unit {data['id']}"
            )

            found = False
            for u in self._casaNetwork.units:  # type: ignore[union-attr]
                if u.deviceId == data["id"]:
                    found = True
                    u.setStateFromBytes(data["state"])
                    u._on = data["on"]
                    u._online = data["online"]

                    # Notify listeners
                    for h in self._unitChangedCallbacks:
                        try:
                            h(u)
                        except Exception:
                            self._logger.error(
                                f"Exception occurred in unitChangedCallback {h}.",
                                exc_info=True,
                            )

            if not found:
                self._logger.error(
                    f"Changed state notification for unkown unit {data['id']}"
                )
        else:
            self._logger.warning(f"Handler for type {packetType} not implemented!")
            self.logger.debug(f"Notification: {data}")

    def registerUnitChangedHandler(self, handler: Callable[[Unit], None]) -> None:
        """Register a new handler for unit state changed.

        This handler is called whenever a new state for a unit is received.
        The handler is supplied by the unit for which the state changed
        and the state property of the unit is set to the new state.

        :param handler: The method to call when a new unit state is received.
        """
        self._unitChangedCallbacks.append(handler)
        self._logger.info(f"Registerd unit changed handler {handler}")

    def unregisterUnitChangedHandler(self, handler: Callable[[Unit], None]) -> None:
        """Unregister an existing unit state change handler.

        :param handler: The handler to unregister.
        :raises ValueError: If the handler isn't registered.
        """
        self._unitChangedCallbacks.remove(handler)
        self._logger.info(f"Removed unit changed handler {handler}")

    def _disconnect_callback(self) -> None:
        # Mark all units as offline on disconnect.
        for u in self.units:
            u._online = False
            for h in self._unitChangedCallbacks:
                try:
                    h(u)
                except Exception:
                    self._logger.error(
                        f"Exception occurred in unitChangedCallback {h}.",
                        exc_info=True,
                    )

    async def disconnect(self) -> None:
        """Disconnect from the network."""
        if self._casaClient:
            try:
                await asyncio.shield(self._casaClient.disconnect())
            except Exception:
                self._logger.error("Failed to disconnect from client.", exc_info=True)
        if self._casaNetwork:
            try:
                await asyncio.shield(self._casaNetwork.disconnect())
            except Exception:
                self._logger.error("Failed to disconnect from network.", exc_info=True)
            self._casaNetwork = None
        if self._ownHttpClient and self._httpClient is not None:
            try:
                await asyncio.shield(self._httpClient.aclose())
            except Exception:
                self._logger.error("Failed to close http client.", exc_info=True)
