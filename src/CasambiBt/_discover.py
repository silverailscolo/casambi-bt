import logging
from typing import Tuple

# from binascii import b2a_hex as b2a

from bleak import BleakScanner, BLEDevice
# from bleak.backends.client import BLEDevice
from bleak.exc import BleakDBusError, BleakError

from ._constants import CASA_UUID
from .errors import BluetoothError

_LOGGER = logging.getLogger(__name__)


async def discover() -> list[Tuple[BLEDevice, bytes | None]]:
    """Discover all Casambi networks in range.

    :return: A list of all discovered Casambi devices.
    :raises BluetoothError: Bluetooth isn't turned on or in a failed state.
    """

    # Discover all devices in range
    try:
        devices_and_advertisement_data = await BleakScanner.discover(return_adv=True)  # new params
    except BleakDBusError as e:
        raise BluetoothError(e.dbus_error, e.dbus_error_details) from e
    except BleakError as e:
        raise BluetoothError from e

    # Filter out all devices that aren't primary communication endpoints for Casambi networks
    discovered = []
    mancode: int = 0
    for device, adv_data in devices_and_advertisement_data.values():
        for man in adv_data.manufacturer_data:
            mancode = man
        # _LOGGER.debug(f"Addr: {device.address}, manuf: {mancode} name: {adv_data.local_name} uuid: {adv_data.service_uuids}") #advert: {adv_data}")
        if mancode == 963:
            if CASA_UUID in adv_data.service_uuids:
                network_uuid = adv_data.manufacturer_data.get(963)
                # _LOGGER.debug(f"Discovered Casambi network at {device.address} with address {network_uuid.hex()}")
                discovered.append(tuple((device, network_uuid)))

    return discovered
