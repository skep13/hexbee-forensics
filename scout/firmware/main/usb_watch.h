/* USB acquisition for the Scout (ESP32-S3).
 *
 * The S3 acts as a USB **host**: a stick is plugged into the Scout, the MSC
 * driver enumerates it, the filesystem is mounted, and the Scout harvests
 * metadata for every file it finds. That is the forensically useful
 * direction — the Scout is the collector, not the thing being collected.
 *
 * Memory rules, forced by 520 KB of SRAM:
 *   - files are reported one at a time, streamed straight out as events;
 *     no directory listing is ever assembled in RAM,
 *   - hashing covers the first HEXBEE_USB_HASH_BYTES (default 4 KB) of each
 *     file, which is enough to fingerprint and to detect type mismatches.
 *     Full-file hashing on the S3 against a 64 GB stick would both OOM and
 *     take hours; Comb computes full hashes later on the Queen,
 *   - the walk is bounded by file count and directory depth.
 *
 * Without CONFIG_HEXBEE_USB_HOST the module keeps its original simulation
 * behaviour so the pipeline can still be demonstrated without hardware.
 */
#ifndef HEXBEE_USB_WATCH_H
#define HEXBEE_USB_WATCH_H

#include <stdbool.h>

typedef enum {
    USB_EVT_INSERTED,      /* stick enumerated; detail = device info      */
    USB_EVT_REMOVED,       /* stick unplugged                             */
    USB_EVT_FILE,          /* one file's metadata + prefix hash           */
    USB_EVT_SCAN_DONE,     /* walk finished; detail = counters            */
    USB_EVT_ERROR,         /* enumeration/mount/read failure              */
} usb_watch_event_t;

typedef void (*usb_watch_cb_t)(usb_watch_event_t evt, const char *detail_json);

/* Start the USB host stack (or the simulator). Safe to call once at boot. */
void usb_watch_start(usb_watch_cb_t cb);

/* True when a stick is currently mounted. */
bool usb_watch_media_present(void);

#endif
