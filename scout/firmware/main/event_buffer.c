#include "event_buffer.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static char s_slots[EVENT_BUFFER_SLOTS][EVENT_MAX_LEN];
static size_t s_head; /* oldest */
static size_t s_count;
static SemaphoreHandle_t s_mutex;

void event_buffer_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    s_head = 0;
    s_count = 0;
}

bool event_buffer_push(const char *json)
{
    if (strlen(json) >= EVENT_MAX_LEN) {
        return false;
    }
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    size_t slot;
    if (s_count == EVENT_BUFFER_SLOTS) {
        /* full: overwrite oldest */
        slot = s_head;
        s_head = (s_head + 1) % EVENT_BUFFER_SLOTS;
    } else {
        slot = (s_head + s_count) % EVENT_BUFFER_SLOTS;
        s_count++;
    }
    strcpy(s_slots[slot], json);
    xSemaphoreGive(s_mutex);
    return true;
}

bool event_buffer_peek(char *out, size_t out_len)
{
    bool ok = false;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (s_count > 0 && out_len > strlen(s_slots[s_head])) {
        strcpy(out, s_slots[s_head]);
        ok = true;
    }
    xSemaphoreGive(s_mutex);
    return ok;
}

void event_buffer_pop(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (s_count > 0) {
        s_head = (s_head + 1) % EVENT_BUFFER_SLOTS;
        s_count--;
    }
    xSemaphoreGive(s_mutex);
}

size_t event_buffer_count(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    size_t n = s_count;
    xSemaphoreGive(s_mutex);
    return n;
}
