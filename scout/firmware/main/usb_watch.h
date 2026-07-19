/* USB acquisition interface (skeleton).
 *
 * Target design: the ESP32-S3 enumerates on the target computer via TinyUSB
 * (USB OTG device mode) and reports insertion/host events to scout_main,
 * which converts them to HexBee JSON events. MSC host mode (reading an
 * attached USB stick's file table for triage) is the next milestone and
 * needs the esp32-s3 usb_host MSC driver.
 *
 * This module is hardware-validation-gated: it compiles, registers its
 * callback, and emits a simulated insertion in CONFIG-less builds so the
 * end-to-end pipeline can be exercised before the USB work lands. */
#ifndef HEXBEE_USB_WATCH_H
#define HEXBEE_USB_WATCH_H

typedef enum {
    USB_EVT_INSERTED,
    USB_EVT_REMOVED,
} usb_watch_event_t;

typedef void (*usb_watch_cb_t)(usb_watch_event_t evt, const char *detail_json);

void usb_watch_start(usb_watch_cb_t cb);

#endif
