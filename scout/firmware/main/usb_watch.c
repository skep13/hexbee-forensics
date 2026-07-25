#include "usb_watch.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "usb_watch";
static usb_watch_cb_t s_cb;
static volatile bool s_media_present;

bool usb_watch_media_present(void) { return s_media_present; }

#if CONFIG_HEXBEE_USB_HOST

#include "esp_err.h"
#include "mbedtls/sha256.h"
#include "msc_host.h"
#include "msc_host_vfs.h"
#include "usb/usb_host.h"

#define MOUNT_POINT   "/usb"
#define HASH_BYTES    CONFIG_HEXBEE_USB_HASH_BYTES
#define MAX_FILES     CONFIG_HEXBEE_USB_MAX_FILES
#define MAX_DEPTH     6
#define PATH_MAX_LEN  256

/* One shared scratch buffer. Allocating per file would fragment the heap on a
 * device with no MMU and 520 KB to work with. */
static uint8_t  s_chunk[512];
static char     s_path[PATH_MAX_LEN];
static char     s_json[640];

static msc_host_device_handle_t s_dev;
static msc_host_vfs_handle_t    s_vfs;
static QueueHandle_t            s_events;
static uint32_t                 s_files_seen;
static uint32_t                 s_files_skipped;

typedef struct {
    enum { EV_CONNECT, EV_DISCONNECT } kind;
    uint8_t address;
} usb_msg_t;

static void emit(usb_watch_event_t evt, const char *json)
{
    if (s_cb) {
        s_cb(evt, json);
    }
}

/* --- JSON escaping -------------------------------------------------------
 * Filenames on a seized stick are attacker-controlled. An unescaped quote
 * would corrupt the event and, downstream, the evidence record. */
static void json_escape(const char *in, char *out, size_t out_len)
{
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 7 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = c;
        } else if (c < 0x20 || c == 0x7f) {
            o += snprintf(out + o, out_len - o, "\\u%04x", c);
        } else {
            out[o++] = c;
        }
    }
    out[o] = '\0';
}

/* --- prefix hashing ------------------------------------------------------ */
static bool hash_prefix(const char *path, char hex_out[65], size_t *read_out)
{
    FILE *fh = fopen(path, "rb");
    if (!fh) {
        return false;
    }
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); /* 0 = SHA-256, not SHA-224 */

    size_t total = 0;
    while (total < HASH_BYTES) {
        size_t want = HASH_BYTES - total;
        if (want > sizeof(s_chunk)) {
            want = sizeof(s_chunk);
        }
        size_t got = fread(s_chunk, 1, want, fh);
        if (got == 0) {
            break;
        }
        mbedtls_sha256_update(&ctx, s_chunk, got);
        total += got;
    }
    fclose(fh);

    uint8_t digest[32];
    mbedtls_sha256_finish(&ctx, digest);
    mbedtls_sha256_free(&ctx);
    for (int i = 0; i < 32; i++) {
        sprintf(hex_out + i * 2, "%02x", digest[i]);
    }
    hex_out[64] = '\0';
    *read_out = total;
    return true;
}

static bool looks_executable(const char *name)
{
    const char *dot = strrchr(name, '.');
    if (!dot) {
        return false;
    }
    static const char *exts[] = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd",
                                 ".ps1", ".vbs", ".js",  ".jar", ".msi", ".lnk",
                                 ".sh",  ".elf", NULL};
    for (int i = 0; exts[i]; i++) {
        if (strcasecmp(dot, exts[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* --- directory walk ------------------------------------------------------
 * Iterative in spirit but written recursively with a hard depth cap; the
 * default 4 kB task stack is nowhere near the limit at depth 6. */
static void walk(const char *dir, int depth)
{
    if (depth > MAX_DEPTH || s_files_seen >= MAX_FILES) {
        return;
    }
    DIR *d = opendir(dir);
    if (!d) {
        ESP_LOGW(TAG, "cannot open %s", dir);
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL && s_files_seen < MAX_FILES) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        int n = snprintf(s_path, sizeof(s_path), "%s/%s", dir, entry->d_name);
        if (n <= 0 || n >= (int)sizeof(s_path)) {
            s_files_skipped++;
            continue;
        }
        if (entry->d_type == DT_DIR) {
            /* s_path is shared, so copy the child name before recursing. */
            char child[PATH_MAX_LEN];
            strncpy(child, s_path, sizeof(child) - 1);
            child[sizeof(child) - 1] = '\0';
            walk(child, depth + 1);
            continue;
        }

        struct stat st;
        if (stat(s_path, &st) != 0) {
            s_files_skipped++;
            continue;
        }
        char hex[65] = {0};
        size_t hashed = 0;
        bool ok = hash_prefix(s_path, hex, &hashed);

        char safe_path[PATH_MAX_LEN + 32];
        json_escape(s_path + strlen(MOUNT_POINT), safe_path, sizeof(safe_path));

        snprintf(s_json, sizeof(s_json),
                 "{\"path\":\"%s\",\"size\":%ld,\"modified\":%ld,"
                 "\"sha256_prefix\":\"%s\",\"hashed_bytes\":%u,"
                 "\"executable\":%s,\"partial_hash\":true}",
                 safe_path, (long)st.st_size, (long)st.st_mtime,
                 ok ? hex : "", (unsigned)hashed,
                 looks_executable(entry->d_name) ? "true" : "false");
        emit(USB_EVT_FILE, s_json);
        s_files_seen++;

        /* Yield: a large stick would otherwise starve the Wi-Fi and MQTT
         * tasks for the whole walk, and the event buffer would overflow. */
        if ((s_files_seen % 8) == 0) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }
    closedir(d);
}

/* --- MSC lifecycle ------------------------------------------------------- */
static void msc_callback(const msc_host_event_t *event, void *arg)
{
    (void)arg;
    usb_msg_t msg = {0};
    if (event->event == MSC_DEVICE_CONNECTED) {
        msg.kind = EV_CONNECT;
        msg.address = event->device.address;
    } else {
        msg.kind = EV_DISCONNECT;
    }
    xQueueSend(s_events, &msg, 0);
}

static void usb_host_task(void *arg)
{
    (void)arg;
    while (1) {
        uint32_t flags = 0;
        usb_host_lib_handle_events(portMAX_DELAY, &flags);
        if (flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS) {
            usb_host_device_free_all();
        }
    }
}

static void handle_connect(uint8_t address)
{
    esp_err_t err = msc_host_install_device(address, &s_dev);
    if (err != ESP_OK) {
        snprintf(s_json, sizeof(s_json),
                 "{\"stage\":\"enumerate\",\"error\":\"%s\"}", esp_err_to_name(err));
        emit(USB_EVT_ERROR, s_json);
        return;
    }

    msc_host_device_info_t info;
    if (msc_host_get_device_info(s_dev, &info) == ESP_OK) {
        char vendor[64], product[64];
        char v_raw[36] = {0}, p_raw[36] = {0};
        /* Descriptor strings are UTF-16; take the low byte of each unit. */
        for (int i = 0; i < 32 && info.iManufacturer[i]; i++) {
            v_raw[i] = (char)info.iManufacturer[i];
        }
        for (int i = 0; i < 32 && info.iProduct[i]; i++) {
            p_raw[i] = (char)info.iProduct[i];
        }
        json_escape(v_raw, vendor, sizeof(vendor));
        json_escape(p_raw, product, sizeof(product));
        snprintf(s_json, sizeof(s_json),
                 "{\"vendor\":\"%s\",\"product\":\"%s\",\"capacity_mb\":%u,"
                 "\"sector_size\":%u,\"address\":%u}",
                 vendor, product,
                 (unsigned)((uint64_t)info.sector_count * info.sector_size / (1024 * 1024)),
                 (unsigned)info.sector_size, (unsigned)address);
    } else {
        snprintf(s_json, sizeof(s_json), "{\"address\":%u}", (unsigned)address);
    }
    emit(USB_EVT_INSERTED, s_json);

    const esp_vfs_fat_mount_config_t mount_cfg = {
        /* Never format: an unrecognised filesystem is evidence, and
         * formatting it would destroy the thing we came to collect. */
        .format_if_mount_failed = false,
        .max_files = 3,
        .allocation_unit_size = 1024,
    };
    err = msc_host_vfs_register(s_dev, MOUNT_POINT, &mount_cfg, &s_vfs);
    if (err != ESP_OK) {
        snprintf(s_json, sizeof(s_json),
                 "{\"stage\":\"mount\",\"error\":\"%s\"}", esp_err_to_name(err));
        emit(USB_EVT_ERROR, s_json);
        return;
    }

    s_media_present = true;
    s_files_seen = 0;
    s_files_skipped = 0;
    int64_t started = esp_timer_get_time();
    walk(MOUNT_POINT, 0);
    snprintf(s_json, sizeof(s_json),
             "{\"files\":%u,\"skipped\":%u,\"truncated\":%s,"
             "\"hash_bytes\":%u,\"seconds\":%lld}",
             (unsigned)s_files_seen, (unsigned)s_files_skipped,
             s_files_seen >= MAX_FILES ? "true" : "false",
             (unsigned)HASH_BYTES, (esp_timer_get_time() - started) / 1000000);
    emit(USB_EVT_SCAN_DONE, s_json);
}

static void handle_disconnect(void)
{
    if (s_vfs) {
        msc_host_vfs_unregister(s_vfs);
        s_vfs = NULL;
    }
    if (s_dev) {
        msc_host_uninstall_device(s_dev);
        s_dev = NULL;
    }
    s_media_present = false;
    emit(USB_EVT_REMOVED, "{\"reason\":\"device_disconnected\"}");
}

static void msc_task(void *arg)
{
    (void)arg;
    usb_msg_t msg;
    while (1) {
        if (xQueueReceive(s_events, &msg, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (msg.kind == EV_CONNECT) {
            handle_connect(msg.address);
        } else {
            handle_disconnect();
        }
    }
}

void usb_watch_start(usb_watch_cb_t cb)
{
    s_cb = cb;
    s_events = xQueueCreate(4, sizeof(usb_msg_t));

    const usb_host_config_t host_cfg = {
        .intr_flags = ESP_INTR_FLAG_LEVEL1,
    };
    ESP_ERROR_CHECK(usb_host_install(&host_cfg));
    xTaskCreate(usb_host_task, "usb_host", 4096, NULL, 5, NULL);

    const msc_host_driver_config_t msc_cfg = {
        .create_backround_task = true,
        .task_priority = 5,
        .stack_size = 4096,
        .callback = msc_callback,
    };
    ESP_ERROR_CHECK(msc_host_install(&msc_cfg));
    /* The walk hashes files, so this task gets a generous stack. */
    xTaskCreate(msc_task, "usb_msc", 6144, NULL, 4, NULL);

    ESP_LOGI(TAG, "usb_watch started (MSC host mode, hash prefix %d bytes, "
                  "max %d files)", HASH_BYTES, MAX_FILES);
}

#else  /* !CONFIG_HEXBEE_USB_HOST — simulation build ---------------------- */

static void simulate_insertion(void *arg)
{
    (void)arg;
    ESP_LOGW(TAG, "emitting SIMULATED usb insertion "
                  "(enable CONFIG_HEXBEE_USB_HOST for the real MSC path)");
    s_media_present = true;
    if (s_cb) {
        s_cb(USB_EVT_INSERTED,
             "{\"volume_label\":\"SIMULATED\",\"fs\":\"FAT32\",\"capacity_mb\":0}");
        s_cb(USB_EVT_FILE,
             "{\"path\":\"/SIMULATED/invoice.pdf.exe\",\"size\":184320,"
             "\"sha256_prefix\":\"\",\"hashed_bytes\":0,\"executable\":true,"
             "\"partial_hash\":true}");
        s_cb(USB_EVT_SCAN_DONE,
             "{\"files\":1,\"skipped\":0,\"truncated\":false,\"simulated\":true}");
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

#endif /* CONFIG_HEXBEE_USB_HOST */
