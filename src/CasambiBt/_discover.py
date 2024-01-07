import logging

from bleak import BleakScanner
from bleak.backends.client import BLEDevice
from bleak.exc import BleakDBusError, BleakError

from ._constants import CASA_UUID
from .errors import BluetoothError

_LOGGER = logging.getLogger(__name__)


async def discover() -> list[BLEDevice]:
    """Discover all Casambi networks in range.

    :return: A list of all discovered Casambi devices.
    :raises BluetoothError: Bluetooth isn't turned on or in a failed state.
    """

    # Discover all devices in range
    try:
        #devices = await BleakScanner.discover()
        devices_and_advertisement_data = await BleakScanner.discover(return_adv = True) # new params
    except BleakDBusError as e:
        raise BluetoothError(e.dbus_error, e.dbus_error_details) from e
    except BleakError as e:
        raise BluetoothError from e

    # Filter out all devices that aren't primary communication endpoints for Casambi networks
    discovered = []
    for device, adv_data in devices_and_advertisement_data.values():
    #for device in devices:
        for man in adv_data.manufacturer_data:
            mancode = man
        _LOGGER.debug(f"Addr {device.address}, manuf {mancode} name {adv_data.local_name} uuid {adv_data.service_uuids} advert: {adv_data}")
        #if "manufacturer_data" in device.metadata and 963 in device.metadata["manufacturer_data"]:
        if mancode == 963:
            if CASA_UUID in adv_data.service_uuids:
            #if CASA_UUID in device.metadata["uuids"]:
                _LOGGER.debug(f"Discovered network at {device.address}")
                discovered.append(device)

    return discovered
