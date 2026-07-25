"""Boot-time configuration for the HexBee Stinger (Pico HID deployer).

Two jobs, both of which must happen before CircuitPython finishes starting:

1. **Filesystem direction.** CIRCUITPY is normally writable by the *host* and
   read-only to the board. Deployment logging needs the reverse. We flip it
   only when the board is armed, so a disarmed Stinger stays a normal drive
   you can drop payloads onto.

2. **Device identity.** A HID keyboard is the only interface advertised when
   armed — the mass-storage drive is hidden. A stick that both types and
   mounts is conspicuous; more importantly, hiding the drive stops the target
   host from writing to the evidence log.
"""

import board
import digitalio
import storage
import usb_cdc
import usb_hid

ARM_PIN = board.GP15

arm = digitalio.DigitalInOut(ARM_PIN)
arm.direction = digitalio.Direction.INPUT
arm.pull = digitalio.Pull.UP
armed = not arm.value          # pull-up: closed to GND == armed

if armed:
    # Board can write its own log; host cannot mount the drive at all.
    storage.remount("/", readonly=False)
    storage.disable_usb_drive()
    usb_cdc.disable()
    usb_hid.enable(( usb_hid.Devices.KEYBOARD, ))
else:
    # Disarmed: an ordinary USB drive for loading payloads, with the serial
    # console available so you can see what it would have done.
    usb_hid.disable()

arm.deinit()
