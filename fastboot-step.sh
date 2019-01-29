#!/bin/bash

set -e

fastboot flash boot bin/recovery-inj.img
fastboot flash recovery bin/recovery-inj.img
fastboot reboot recovery

echo ""
echo ""
echo "If you don't see the recovery in a few seconds, try pressing the power button twice"
echo ""
