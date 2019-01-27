from common import Device

from handshake import handshake
from load_payload import load_payload

def main():
    dev = Device()
    dev.find_device()

    # 1) Handshake
    handshake(dev)

    # 2) Load brom payload
    load_payload(dev, "build/payload.bin")


if __name__ == "__main__":
    main()
