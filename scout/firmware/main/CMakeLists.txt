set(hexbee_requires nvs_flash esp_wifi esp_event mqtt json esp_timer)

# USB MSC host acquisition pulls in the host stack, FATFS/VFS, and mbedTLS
# for prefix hashing. Kept conditional so a simulation build stays small.
if(CONFIG_HEXBEE_USB_HOST)
    list(APPEND hexbee_requires usb fatfs vfs mbedtls)
endif()

idf_component_register(
    SRCS "scout_main.c" "event_buffer.c" "usb_watch.c"
    INCLUDE_DIRS "."
    REQUIRES ${hexbee_requires}
)
