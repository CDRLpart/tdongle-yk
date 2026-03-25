/*
 * This file is part of the Pico FIDO2 distribution (https://github.com/polhenarejos/pico-fido2).
 * Copyright (c) 2026.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "pico_keys.h"

#if defined(ESP_PLATFORM) && defined(PICO_BOARD_TDONGLE_S3)

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "freertos/task.h"

#if !defined(CONFIG_IDF_TARGET_ESP32S3)
#error "The LilyGO T-Dongle S3 board support requires CONFIG_IDF_TARGET_ESP32S3."
#endif

#define TDONGLE_BUTTON_GPIO         GPIO_NUM_0
#define TDONGLE_APA102_DATA_GPIO    GPIO_NUM_40
#define TDONGLE_DISPLAY_MOSI_GPIO   GPIO_NUM_3
#define TDONGLE_DISPLAY_SCK_GPIO    GPIO_NUM_5
#define TDONGLE_DISPLAY_CS_GPIO     GPIO_NUM_4
#define TDONGLE_DISPLAY_DC_GPIO     GPIO_NUM_2
#define TDONGLE_DISPLAY_BL_GPIO     GPIO_NUM_38
#define TDONGLE_DISPLAY_SPI_HOST    SPI3_HOST
#define TDONGLE_DISPLAY_SPI_HZ      1000000
#define TDONGLE_DEFAULT_UP_TIMEOUT  15

static esp_err_t tdongle_display_send(spi_device_handle_t display, uint8_t value, bool data_mode) {
    gpio_set_level(TDONGLE_DISPLAY_DC_GPIO, data_mode ? 1 : 0);

    spi_transaction_t transaction = {
        .length = 8,
        .tx_buffer = &value,
    };
    return spi_device_transmit(display, &transaction);
}

static void tdongle_display_sleep(void) {
    gpio_config_t gpio_cfg = {
        .pin_bit_mask = (1ULL << TDONGLE_DISPLAY_DC_GPIO) | (1ULL << TDONGLE_DISPLAY_BL_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&gpio_cfg);
    gpio_set_level(TDONGLE_DISPLAY_BL_GPIO, 0);

    spi_bus_config_t bus_cfg = {
        .mosi_io_num = TDONGLE_DISPLAY_MOSI_GPIO,
        .miso_io_num = -1,
        .sclk_io_num = TDONGLE_DISPLAY_SCK_GPIO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4,
    };
    bool bus_initialized = false;
    esp_err_t err = spi_bus_initialize(TDONGLE_DISPLAY_SPI_HOST, &bus_cfg, SPI_DMA_DISABLED);
    if (err == ESP_OK) {
        bus_initialized = true;
    }
    else if (err != ESP_ERR_INVALID_STATE) {
        return;
    }

    spi_device_interface_config_t dev_cfg = {
        .clock_speed_hz = TDONGLE_DISPLAY_SPI_HZ,
        .mode = 0,
        .spics_io_num = TDONGLE_DISPLAY_CS_GPIO,
        .queue_size = 1,
    };
    spi_device_handle_t display = NULL;
    if (spi_bus_add_device(TDONGLE_DISPLAY_SPI_HOST, &dev_cfg, &display) != ESP_OK) {
        if (bus_initialized) {
            spi_bus_free(TDONGLE_DISPLAY_SPI_HOST);
        }
        return;
    }

    tdongle_display_send(display, 0x28, false);
    vTaskDelay(pdMS_TO_TICKS(10));
    tdongle_display_send(display, 0x10, false);
    vTaskDelay(pdMS_TO_TICKS(120));

    spi_bus_remove_device(display);
    if (bus_initialized) {
        spi_bus_free(TDONGLE_DISPLAY_SPI_HOST);
    }
}

int picokey_init() {
    gpio_pullup_en(TDONGLE_BUTTON_GPIO);
    gpio_pulldown_dis(TDONGLE_BUTTON_GPIO);

    if (!phy_data.up_btn_present) {
        phy_data.up_btn = TDONGLE_DEFAULT_UP_TIMEOUT;
        phy_data.up_btn_present = true;
    }
    if (!phy_data.led_driver_present) {
        phy_data.led_driver = PHY_LED_DRIVER_APA102;
        phy_data.led_driver_present = true;
    }
    if (!phy_data.led_gpio_present) {
        phy_data.led_gpio = TDONGLE_APA102_DATA_GPIO;
        phy_data.led_gpio_present = true;
    }
    if (!phy_data.led_brightness_present) {
        phy_data.led_brightness = MAX_BTNESS;
        phy_data.led_brightness_present = true;
    }

    tdongle_display_sleep();
    return 0;
}

#endif
