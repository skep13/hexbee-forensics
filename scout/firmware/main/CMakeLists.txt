idf_component_register(
    SRCS "scout_main.c" "event_buffer.c" "usb_watch.c"
    INCLUDE_DIRS "."
    REQUIRES nvs_flash esp_wifi esp_event mqtt json esp_timer
)
