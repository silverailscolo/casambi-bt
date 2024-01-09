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
    classic_uuid: str = devset[1].hex(':')  # we need this as uuid for CLASSIC network lookup on api.casambi.com

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
        # await casa.setLevel(None, 0)
        # await asyncio.sleep(1)

        # Print the state of all units
        print("===========")
        for u in casa.units:
            print(u.__repr__())
        # Print the state of all scenes
        print("===========")
        for s in casa.scenes:
            print(s.__repr__())
            
        # await asyncio.sleep(60)
        # listen for notifications
        
    finally:
        await casa.disconnect()


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())
