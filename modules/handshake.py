import sys

from common import Device
from logger import log


def handshake(dev):
    log("Handshake")
    dev.handshake()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        dev = Device(sys.argv[1])
    else:
        dev = Device()
        dev.find_device()
    handshake(dev)
