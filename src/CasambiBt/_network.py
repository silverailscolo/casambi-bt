import json
import logging
import pickle
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, cast

import httpx
from httpx import AsyncClient, RequestError

from ._cache import getCacheDir
from ._constants import DEVICE_NAME
from ._keystore import KeyStore
from ._unit import Group, Scene, Unit, UnitControl, UnitControlType, UnitType
from .errors import (
    AuthenticationError,
    NetworkNotFoundError,
    NetworkOnlineUpdateNeededError,
    NetworkUpdateError,
)


@dataclass()
class _NetworkSession:
    session: str
    network: str
    manager: bool
    keyID: int
    expires: datetime

    role: int = 3  # TODO: Support other role types?

    def expired(self) -> bool:
        return datetime.utcnow() > self.expires


class Network:
    def __init__(self, uuid: str, httpClient: AsyncClient) -> None:
        self._session: Optional[_NetworkSession] = None

        self._networkName: Optional[str] = None
        self._networkRevision: Optional[int] = None

        self._unitTypes: dict[int, UnitType] = {}
        self.units: list[Unit] = []
        self.groups: list[Group] = []
        self.scenes: list[Scene] = []

        self._networkType = "Classic" # or "Evolution" # test EBR
        self._logger = logging.getLogger(__name__)
        # TODO: Create LoggingAdapter to prepend uuid.

        self._id: Optional[str] = None
        self._uuid = uuid
        self._logger.info(f"UUID = {self._uuid}")
        self._httpClient = httpClient

        self._cachePath = getCacheDir(uuid)
        self._keystore = KeyStore(self._cachePath)

        self._sessionPath = self._cachePath / "session.pck"
        if self._sessionPath.exists():
            self._loadSession()

        self._typeCachePath = self._cachePath / "types.pck"
        if self._typeCachePath.exists():
            self._loadTypeCache()

    def _loadSession(self) -> None:
        self._logger.info("Loading session...")
        self._session = pickle.load(self._sessionPath.open("rb"))

    def _saveSession(self) -> None:
        self._logger.info("Saving session...")
        pickle.dump(self._session, self._sessionPath.open("wb"))

    def _loadTypeCache(self) -> None:
        self._logger.info("Loading unit type cache...")
        self._unitTypes = pickle.load(self._typeCachePath.open("rb"))

    def _saveTypeCache(self) -> None:
        self._logger.info("Saving type cache...")
        pickle.dump(self._unitTypes, self._typeCachePath.open("wb"))

    async def getNetworkId(self, forceOffline: bool = False) -> None:
        """ Fetch network id from casambi.com

        :param forceOffline: Whether to skip online query e.g. for Classic network type
        :raises RequestError: request failed
        :raises NetworkOnlineUpdateNeededError: no network id found, either in cache or from casambi.com
        """
        self._logger.info(f"Getting network id for uuid {self._uuid}...")

        networkCacheFile = self._cachePath / "networkid"
        res = None
        
        if networkCacheFile.exists():
            self._id = networkCacheFile.read_text()

        if forceOffline:
            self._logger.info("forcedOffline network line 101")
            if not self._id:
                raise NetworkOnlineUpdateNeededError("Network isn't cached.")

            # Classic Casambi cannot connect to cloud, so must skip? TODO
        else :
            getNetworkIdUrl = f"https://api.casambi.com/network/uuid/{self._uuid}"
            self._logger.debug(f"Fetching {getNetworkIdUrl}")
            try:
                res = await self._httpClient.get(getNetworkIdUrl)
            except RequestError as err:
                if not self._id:
                    raise NetworkOnlineUpdateNeededError from err
                else:
                    self._logger.warning(
                        "Network error while fetching network id. Continuing with cache.",
                        exc_info = True,
                    )
                    #return

        self._logger.info(f"NetworkId = {self._id} Result from api: {res}")

        if not self._id:
            self._id = "BkofKL0JMXLEDUr4V1znQkGK5cqXgKNc" # EBR manually fetched from api.casambi.com

        self._logger.info(f"NetworkId = {self._id} Result from api: {res}")
        
        if res.status_code == httpx.codes.NOT_FOUND: # << Classic network/no Casambi API key: alternative login? TODO EBR
            raise NetworkNotFoundError(
                "API failed to find network. Is your network configured correctly?"
            )
        if res.status_code != httpx.codes.OK:
            raise NetworkNotFoundError(
                f"Getting network id from api.casambi.com returned unexpected status {res.status_code}"
            )

        if not forceOffline: # Classic?
            new_id = cast(str, res.json()["id"])
            if self._id != new_id:
                self._logger.info(f"Network id changed from {self._id} to {new_id}.")
                networkCacheFile.write_text(new_id)
                self._id = new_id
        self._logger.info(f"Got network id {self._id}.")

    def authenticated(self) -> bool:
        if not self._session:
            return False
        return not self._session.expired()

    def getKeyStore(self) -> KeyStore:
        return self._keystore

    async def logIn(self, password: str, forceOffline: bool = False) -> None:
        """ Login on api.casambi.com to fetch configurations; returned info was previously stored by client app during hardware setup

        """
        await self.getNetworkId(forceOffline)

        # No need to be authenticated if we try to be offline anyway.
        if self.authenticated() or forceOffline:
            return

        self._logger.info("Logging in to api.casambi.com ...")
        getSessionUrl = f"https://api.casambi.com/network/{self._id}/session"

        res = await self._httpClient.post(
            getSessionUrl, json={"password": password, "deviceName": DEVICE_NAME} # DEVICE_NAME is a placeholder name
        )
        if res.status_code == httpx.codes.OK:
            # Parse session
            sessionJson = res.json()
            sessionJson["expires"] = datetime.utcfromtimestamp(
                sessionJson["expires"] / 1000
            )
            self._session = _NetworkSession(**sessionJson) # stores session info returned from api.casambi.com for later use
            self._logger.info("Login successful.")
            self._saveSession()
        else:
            raise AuthenticationError(f"Login failed: {res.status_code}\n{res.text}")

    async def update(self, forceOffline: bool = False) -> None:
        self._logger.info("Updating network...")
        if not self.authenticated() and not forceOffline:
            raise AuthenticationError("Not authenticated!")

        assert self._id is not None, "Network id must be set."

        # TODO: Save and send revision to receive actual updates?

        cachedNetworkPath = self._cachePath / f"{self._id}.json"
        if cachedNetworkPath.exists():
            network = json.loads(cachedNetworkPath.read_bytes())
            self._networkRevision = network["network"]["revision"]
            self._logger.info(
                f"Loaded cached network. Revision: {self._networkRevision}"
            )
        else:
            #raise NetworkOnlineUpdateNeededError("Network isn't cached.")
            self._networkRevision = 0

        if not forceOffline:
            getNetworkUrl = f"https://api.casambi.com/network/{self._id}/"

            try:
                self._logger.debug("Fetch devices")
                # **SECURITY**: Do not set session header for client! This could leak the session with external clients.
                res = await self._httpClient.put(
                    getNetworkUrl,
                    json={
                        "formatVersion": 1,
                        "deviceName": DEVICE_NAME,
                        "revision": self._networkRevision,
                    },
                    headers={"X-Casambi-Session": self._session.session},  # type: ignore[union-attr]
                )

                if res.status_code != httpx.codes.OK:
                    self._logger.error(f"Update failed: {res.status_code}\n{res.text}")
                    raise NetworkUpdateError("Could not update network!")

                self._logger.debug(f"Network: {res.text}")

                updateResult = res.json()
                if updateResult["status"] != "UPTODATE":
                    self._networkRevision = updateResult["network"]["revision"]
                    cachedNetworkPath.write_bytes(res.content)
                    network = updateResult
                    self._logger.info(
                        f"Fetched updated network with revision {self._networkRevision}"
                    )
            except RequestError as err:
                if self._networkRevision == 0:
                    raise NetworkUpdateError from err
                self._logger.warning(
                    "Failed to update network. Continuing offline.", exc_info=True
                )

        # Parse general information
        #if forceOffline:
        #    self._networkName = "Mein Netzwerk" # EBR make a var to set on top
        #else :

        # Parse keys if there are any. Otherwise the network is probably a Classic network.
        if "keyStore" in network["network"]:
            self._logger.debug("parsing keys")
            keys = network["network"]["keyStore"]["keys"]
            for k in keys:
                self._keystore.addKey(k)

        self._networkName = network["network"]["name"]
            
        # TODO: Parse managerKey and visitorKey for Classic networks.
        
        # manually add Classic keys. Also without Casambi API access key?
        if (self._keystore.size() == 0) :
            self._logger.debug("Empty keystore, Classic?") # EBR
            _key1 = {
                  "id": 0,
                  "type": 1,
                  "role": 3,
                  "name": "managerKey",
                  "key": "547269616e67656c31"
            }
            self._keystore.addKey(_key1)

        # Parse units
        self.units = []
        if (self._networkType == "Classic") : # EBR
            # manually add 2 "Sento" units EBR TODO Occhio Sento unit type = 816
            _unitTypeId = "816"
            uType = await self._fetchUnitInfo(_unitTypeId) # fetch from api.casambi.com
            unit1 = Unit(
                _unitTypeId,
                "3",
                "D28C90BC-0330051A-1800C58B-144BCCD7",
                "81b4d28c90bc",
                "Sento beneden",
                "Classic/26.24",
                uType,
            )
            self.units.append(unit1)
            # TODO could get name from BLE reply
            unit2 = Unit(
                _unitTypeId,
                "2",
                "07003333-0330051C-0A00C58B-144BCCD7",
                "cadf07003333",
                "Sento boven",
                "Classic/26.24",
                uType,
            )
            self.units.append(unit2)
        else:
            units = network["network"]["units"]
            for u in units:
                uType = await self._fetchUnitInfo(u["type"]) # from api.casambi.com
                uObj = Unit(
                    u["type"],
                    u["deviceID"],
                    u["uuid"],
                    u["address"],
                    u["name"],
                    str(u["firmware"]),
                    uType,
                )
                self.units.append(uObj)
        
        # Parse cells
        self.groups = []
        cells = network["network"]["grid"]["cells"]
        for c in cells:
            # Only one type at top level is currently supported
            if c["type"] != 2:
                continue

            # Parse group members
            group_units = []
            # We assume no nested groups here
            for subC in c["cells"]:
                # Ignore everyting that isn't a unit
                if subC["type"] != 1:
                    continue

                unitMatch = list(
                    filter(lambda u: u.deviceId == subC["unit"], self.units)
                )
                if len(unitMatch) != 1:
                    self._logger.warning(
                        f"Incosistent unit reference to {subC['unit']} in group {c['groupID']}. Got {len(unitMatch)} matches."
                    )
                    continue
                group_units.append(unitMatch[0])

            gObj = Group(c["groupID"], c["name"], group_units)
            self.groups.append(gObj)

        # Parse scenes
        self.scenes = []
        if (self._networkType != "Classic") :
            scenes = network["network"]["scenes"]
            for s in scenes:
                sObj = Scene(s["sceneID"], s["name"])
                self.scenes.append(sObj)

        # TODO: Parse more stuff

        self._saveTypeCache()

        self._logger.info("Network updated.")

    async def _fetchUnitInfo(self, id: int) -> UnitType:
        self._logger.info(f"Fetching unit type for id {id}...")

        # Check whether unit type is already cached
        cachedType = self._unitTypes.get(id)
        if cachedType:
            self._logger.info("Using cached type.")
            return cachedType

        getUnitInfoUrl = f"https://api.casambi.com/fixture/{id}"
        async with AsyncClient() as request:
            res = await request.get(getUnitInfoUrl)

        if res.status_code != httpx.codes.OK:
            self._logger.error(f"Getting unit info returned {res.status_code}")

        unitTypeJson = res.json()

        # Parse UnitControls
        controls = []
        for controlJson in unitTypeJson["controls"]:
            typeStr = controlJson["type"].upper()
            try:
                type = UnitControlType[typeStr]
            except KeyError:
                self._logger.warning(
                    f"Unsupported control mode {typeStr} in fixture {id}."
                )
                type = UnitControlType.UNKOWN

            controlObj = UnitControl(
                type,
                controlJson["offset"],
                controlJson["length"],
                controlJson["default"],
                controlJson["readonly"],
                controlJson["min"] if "min" in controlJson else None,
                controlJson["max"] if "max" in controlJson else None,
            )

            controls.append(controlObj)

        # Parse UnitType
        unitTypeObj = UnitType(
            unitTypeJson["id"],
            unitTypeJson["model"],
            unitTypeJson["vendor"],
            unitTypeJson["mode"],
            unitTypeJson["stateLength"],
            controls,
        )

        # Chache unit type
        self._unitTypes[unitTypeObj.id] = unitTypeObj

        self._logger.info("Successfully fetched unit type.")
        return unitTypeObj

    async def disconnect(self) -> None:
        return None
