/* Offline event buffer: RAM ring buffer of JSON event strings.
 *
 * When Wi-Fi/MQTT is down the Scout keeps collecting; events queue here and
 * flush in order once the link returns. Bounded so a long outage degrades
 * gracefully (oldest low-value events are dropped first is future work —
 * currently plain FIFO drop-oldest). */
#ifndef HEXBEE_EVENT_BUFFER_H
#define HEXBEE_EVENT_BUFFER_H

#include <stdbool.h>
#include <stddef.h>

#define EVENT_BUFFER_SLOTS 64
#define EVENT_MAX_LEN 512

void event_buffer_init(void);

/* Copy a JSON event string in. Drops the oldest entry when full.
 * Returns false if the event was too long to store. */
bool event_buffer_push(const char *json);

/* Peek the oldest buffered event; returns false when empty. */
bool event_buffer_peek(char *out, size_t out_len);

/* Discard the oldest buffered event (call after a successful publish). */
void event_buffer_pop(void);

size_t event_buffer_count(void);

#endif
