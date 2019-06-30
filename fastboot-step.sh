#!/bin/bash

set -e

fastboot flash boot bin/recovery-inj.img
fastboot flash recovery bin/recovery-inj.img
fastboot reboot

echo ""
echo ""
echo "If you don't see the recovery in a few seconds, press the power button twice"
echo ""
