#include "usb_watch.h"

#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "usb_watch";
static usb_watch_cb_t s_cb;

/* TODO(hardware): replace with TinyUSB device-mode mount/unmount callbacks
 * (tud_mount_cb / tud_umount_cb) and, for MSC-host triage, the USB Host
 * Library's msc events. Until the S3 board is validated, emit one simulated
 * insertion 10 s after boot so the Hive pipeline can be demonstrated from
 * real firmware. */
static void simulate_insertion(void *arg)
{
    (void)arg;
    ESP_LOGW(TAG, "emitting SIMULATED usb insertion (hardware path not built yet)");
    if (s_cb) {
        s_cb(USB_EVT_INSERTED,
             "{\"volume_label\":\"SIMULATED\",\"fs\":\"FAT32\",\"capacity_mb\":0}");
    }
}

void usb_watch_start(usb_watch_cb_t cb)
{
    s_cb = cb;
    const esp_timer_create_args_t args = {
        .callback = simulate_insertion,
        .name = "usb_sim",
    };
    esp_timer_handle_t timer;
    ESP_ERROR_CHECK(esp_timer_create(&args, &timer));
    ESP_ERROR_CHECK(esp_timer_start_once(timer, 10 * 1000 * 1000));
    ESP_LOGI(TAG, "usb_watch started (simulation mode)");
}
