"""Boot configuration for the HexBee Sentinel (evidence-seal token).

The seal counter must survive a power cycle, which means the *board* has to
be able to write to its own filesystem. CIRCUITPY defaults to the opposite.

The trade this makes: while the Sentinel is running normally you cannot drag
files onto it from a host. To provision the key or read the counter, hold the
seal button (GP16) while plugging in — that leaves the drive host-writable and
skips the remount.

A second serial endpoint is enabled so the Queen's listener has a clean data
channel that is not competing with the REPL console.
"""

import board
import digitalio
import storage
import usb_cdc

PROVISION_PIN = board.GP16      # hold at boot for host-writable provisioning

pin = digitalio.DigitalInOut(PROVISION_PIN)
pin.direction = digitalio.Direction.INPUT
pin.pull = digitalio.Pull.UP
provisioning = not pin.value    # pull-up: closed to GND == provisioning
pin.deinit()

if not provisioning:
    # Normal operation: the board owns its filesystem so the counter advances.
    storage.remount("/", readonly=False)

# console = REPL for humans, data = the Queen's listener.
usb_cdc.enable(console=True, data=True)
