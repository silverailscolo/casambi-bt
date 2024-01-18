import json
import logging
import pickle
from dataclasses import dataclass
from datetime import datetime
import pytz
from typing import Optional, cast

import httpx
from httpx import AsyncClient, RequestError

from ._cache import getCacheDir
from ._constants import DEVICE_NAME, NetworkGrade
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
        return datetime.now(tz=pytz.UTC) > self.expires


class Network:
    def __init__(self, uuid: str, httpClient: AsyncClient) -> None:
        self._session: Optional[_NetworkSession] = None

        self._networkName: Optional[str] = None
        self._networkRevision: Optional[int] = None

        self._unitTypes: dict[int, UnitType] = {}
        self.units: list[Unit] = []
        self.groups: list[Group] = []
        self.scenes: list[Scene] = []

        self._networkGrade = NetworkGrade.EVOLUTION  # Default, updated from network info ["grade"]
        self._logger = logging.getLogger(__name__)
        # TODO: Create LoggingAdapter to prepend uuid.

        self._id: Optional[str] = None
        self._uuid = uuid
        self._logger.debug(f"UUID = {self._uuid}")
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
        self._logger.debug("Loading session...")
        self._session = pickle.load(self._sessionPath.open("rb"))

    def _saveSession(self) -> None:
        self._logger.debug("Saving session...")
        pickle.dump(self._session, self._sessionPath.open("wb"))

    def _loadTypeCache(self) -> None:
        self._logger.debug("Loading unit type cache...")
        self._unitTypes = pickle.load(self._typeCachePath.open("rb"))

    def _saveTypeCache(self) -> None:
        self._logger.debug("Saving type cache...")
        pickle.dump(self._unitTypes, self._typeCachePath.open("wb"))

    def setNetworkGrade(self, _networkGrade: type) -> None:
        self._networkGrade = type
        
    async def getNetworkId(self, forceOffline: bool = False) -> None:
        """ Fetch network id from casambi.com

        :param forceOffline: Whether to skip online query e.g. for Classic network type/when we have no Casambi API key
        :raises RequestError: request failed
        :raises NetworkOnlineUpdateNeededError: no network id found, either in cache or from casambi.com
        """
        self._logger.debug(f"Getting network id for uuid {self._uuid}...")

        networkCacheFile = self._cachePath / "networkid"
        gradeCacheFile = self._cachePath / "networkgrade"
        res = None
        
        if networkCacheFile.exists():
            self._id = networkCacheFile.read_text()
        if gradeCacheFile.exists():
            self._grade = gradeCacheFile.read_text()
            
        if forceOffline:
            if not self._id:
                raise NetworkOnlineUpdateNeededError("Network isn't cached.")

            # NOTE: Classic Casambi must access api.casambi.com using the network BT address as uuid
        else:
            getNetworkIdUrl = f"https://api.casambi.com/network/uuid/{self._uuid}"
            self._logger.debug(f"Fetching {getNetworkIdUrl} from api.casambi.com")
            try:
                res = await self._httpClient.get(getNetworkIdUrl)
            except RequestError as err:
                if not self._id:
                    raise NetworkOnlineUpdateNeededError from err
                else:
                    self._logger.warning(
                        "Network error while fetching network id. Continuing with cache.",
                        exc_info=True,
                    )
                    # return

        self._logger.debug(f"NetworkId = {self._id}. Result from api: {res}")
        
        if res.status_code == httpx.codes.NOT_FOUND:
            raise NetworkNotFoundError(
                "API failed to find network. Is your network configured correctly?"
            )
        if res.status_code != httpx.codes.OK:
            raise NetworkNotFoundError(
                f"Getting network id from api.casambi.com returned unexpected status {res.status_code}"
            )

        if not forceOffline:  # also works for CLASSIC
            new_id = cast(str, res.json()["id"])
            if self._id != new_id:
                self._logger.debug(f"Network id changed from {self._id} to {new_id} using api.casambi.com.")
                networkCacheFile.write_text(new_id)
                self._id = new_id
            new_grade = cast(str, res.json()["grade"])
            if self._networkGrade != new_grade:
                self._networkGrade = new_grade
        self._logger.debug(f"Got network id {self._id}, grade {self._networkGrade}.")

    def authenticated(self) -> bool:
        if not self._session:
            return False
        return not self._session.expired()

    def getKeyStore(self) -> KeyStore:
        return self._keystore

    async def logIn(self, password: str, forceOffline: bool = False) -> None:
        """ Login on api.casambi.com to fetch configurations.
            Returned info was previously stored there by gateway Casambi app during hardware setup.

        """
        await self.getNetworkId(forceOffline)

        # No need to be authenticated if we try to be offline anyway.
        if self.authenticated() or forceOffline:
            return

        self._logger.debug("Logging in to api.casambi.com with id {self._id}")
        getSessionUrl = f"https://api.casambi.com/network/{self._id}/session"

        res = await self._httpClient.post(
            getSessionUrl, json={"password": password, "deviceName": DEVICE_NAME}  # DEVICE_NAME is a placeholder name
        )
        if res.status_code == httpx.codes.OK:
            # Parse session
            sessionJson = res.json()
            sessionJson["expires"] = datetime.fromtimestamp(
                sessionJson["expires"] / 1000,
                tz=pytz.UTC
            )
            self._session = _NetworkSession(**sessionJson)
            # stores session info returned from api.casambi.com for later use
            self._logger.debug("Login successful.")
            self._saveSession()
        else:
            raise AuthenticationError(f"Login failed: {res.status_code}\n{res.text}")

    async def update(self, forceOffline: bool = False) -> None:
        self._logger.debug("Updating network...")
        if not self.authenticated() and not forceOffline:
            raise AuthenticationError("Not authenticated!")

        assert self._id is not None, "Network id must be set."
        network = None
        # TODO: Save and send revision to receive actual updates?

        cachedNetworkPath = self._cachePath / f"{self._id}.json"
        if cachedNetworkPath.exists():
            network = json.loads(cachedNetworkPath.read_bytes())
            self._networkRevision = network["network"]["revision"]
            self._logger.debug(
                f"Loaded cached network. Revision: {self._networkRevision}"
            )
        else:
            if forceOffline:
                raise NetworkOnlineUpdateNeededError("Network isn't cached.")
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
                    self._logger.debug(
                        f"Fetched updated network with revision {self._networkRevision}"
                    )
            except RequestError as err:
                if self._networkRevision == 0:
                    raise NetworkUpdateError from err
                self._logger.warning(
                    "Failed to update network. Continuing offline.", exc_info=True
                )

        # Parse general information

        # Parse keys if there are any. Otherwise the network is probably a Classic network. ?? EBR TODO
        if "keyStore" in network["network"]:
            self._logger.debug("parsing keys")
            keys = network["network"]["keyStore"]["keys"]
            for k in keys:
                self._keystore.addKey(k)
                self._logger.debug(f"Added key {k}")

        self._networkName = network["network"]["name"]
            
        # Parse managerKey and visitorKey for Classic networks already done. They are visible on api.casambi.com
        
        if self._keystore.size() == 0:
            self._logger.warning("Empty keystore")

        # Parse units
        self.units = []
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
                # Ignore everything that isn't a unit
                if subC["type"] != 1:
                    continue

                unitMatch = list(
                    filter(lambda u: u.deviceId == subC["unit"], self.units)
                )
                if len(unitMatch) != 1:
                    self._logger.warning(
                        f"Inconsistent unit reference to {subC['unit']} in group {c['groupID']}. Got {len(unitMatch)} matches."
                    )
                    continue
                group_units.append(unitMatch[0])

            gObj = Group(c["groupID"], c["name"], group_units)
            self.groups.append(gObj)

        # Parse scenes
        self.scenes = []
        # if (self._networkGrade != NetworkGrade.CLASSIC):  # or EVOLUTION) :
        scenes = network["network"]["scenes"]
        for s in scenes:
            sObj = Scene(s["sceneID"], s["name"])
            self.scenes.append(sObj)

        # TODO: Parse more stuff

        self._saveTypeCache()

        self._logger.debug("Network updated.")

    async def _fetchUnitInfo(self, _id: int) -> UnitType:
        self._logger.debug(f"Fetching unit type for id {_id}...")

        # Check whether unit type is already cached
        cachedType = self._unitTypes.get(_id)
        if cachedType:
            self._logger.debug("Using cached type.")
            return cachedType

        getUnitInfoUrl = f"https://api.casambi.com/fixture/{_id}"
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
                _type = UnitControlType[typeStr]
            except KeyError:
                self._logger.warning(
                    f"Unsupported control mode {typeStr} in fixture {_id}."
                )
                _type = UnitControlType.UNKOWN

            controlObj = UnitControl(
                _type,
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

        # Cache unit type
        self._unitTypes[unitTypeObj.id] = unitTypeObj

        self._logger.debug("Successfully fetched unit type.")
        return unitTypeObj

    async def disconnect(self) -> None:
        return None
