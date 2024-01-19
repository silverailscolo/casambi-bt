import asyncio
import logging

from CasambiBt import Casambi, discover
# from _network import NetworkGrade

_LOGGER = logging.getLogger()
_LOGGER.addHandler(logging.StreamHandler())


async def main() -> None:
    logging.getLogger("CasambiBt").setLevel(logging.DEBUG)
    
    # Discover networks
    print("Searching...")
    devicesets = await discover()
    if len(devicesets) == 0:
        print("No Casambi BLE networks discovered")
        return 
    
    for i, devset in enumerate(devicesets):
        d = devset[0]
        print(f"[{i}]\t{d.address} address: {devset[1].hex(':')}")

    selection = int(input("Select a network: "))

    devset = devicesets[selection]
    device = devset[0]
    classic_uuid: str = devset[1].hex(':')  # we need this as uuid for macOS network lookup on api.casambi.com
    # TODO in discover.py replace await by
    # device = await BleakScanner.find_device_by_name(args.name, cb=dict(use_bdaddr=True))

    print(f"address:{device.address} uuid:{device.details}")
    
    pwd = input("Enter password: ")

    # Connect to the selected network
    casa = Casambi()
    try:
        if classic_uuid:  # CLASSIC
            await casa.connect(tuple((device, classic_uuid)), pwd)
        else:
            await casa.connect(device, pwd)  # EVOLUTION

        print("Demo connected")

        # Notify starts in _casambi
        
        # Turn all lights on
        # await casa.turnOn(None)
        # await asyncio.sleep(5)

        # Turn all lights off
        await casa.setLevel(6,255) # call unit by ID
        await asyncio.sleep(1)

        # Print the state of all units
        print("===========")
        for u in casa.units:
            print(u.__repr__())
            #print(u._state.level + " " + u._state.vertical)
        # Print the state of all scenes
        print("===========")
        for s in casa.scenes:
            print(s.__repr__())
            
        while True:
            await asyncio.sleep(10)
            print("...")
        # listen for notifications
        
    finally:
        await casa.disconnect()
        print("Demo finished, disconnected")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())
