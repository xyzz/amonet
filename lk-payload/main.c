#include <inttypes.h>

#include "libc.h"

#include "common.h"

void low_uart_put(int ch) {
    volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11002014;
    volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11002000;

    while ( !((*uart_reg0) & 0x20) )
    {}

    *uart_reg1 = ch;
}

void _putchar(char character)
{
    if (character == '\n')
        low_uart_put('\r');
    low_uart_put(character);
}

size_t (*original_read)(struct device_t *dev, uint64_t block_off, void *dst, uint32_t sz, uint32_t part);

uint64_t g_boot, g_recovery, g_lk;

size_t read_func(struct device_t *dev, uint64_t block_off, void *dst, uint32_t sz, uint32_t part) {
    printf("read_func hook\n");
    int ret = 0;
    if (block_off == g_boot * 0x200 || block_off == g_recovery * 0x200) {
        // hex_dump(0x4BD5C000, 0x1000);
        printf("demangle boot image - from 0x%08X\n", __builtin_return_address(0));

        if (sz < 0x400) {
            ret = original_read(dev, block_off + 0x400, dst, sz, part);
        } else {
            void *second_copy = (char*)dst + 0x400;
            ret = original_read(dev, block_off, dst, sz, part);
            memcpy(dst, second_copy, 0x400);
            memset(second_copy, 0, 0x400);
        }
    } else {
        ret = original_read(dev, block_off, dst, sz, part);
    }
    return ret;
}

static void parse_gpt() {
    uint8_t raw[0x800] = { 0 };
    struct device_t *dev = get_device();
    dev->read(dev, 0x400, raw, sizeof(raw), USER_PART);
    for (size_t i = 0; i < sizeof(raw) / 0x80; ++i) {
        uint8_t *ptr = &raw[i * 0x80];
        uint8_t *name = ptr + 0x38;
        uint32_t start;
        memcpy(&start, ptr + 0x20, 4);
        if (memcmp(name, "b\x00o\x00o\x00t\x00\x00\x00", 10) == 0) {
            printf("found boot at 0x%08X\n", start);
            g_boot = start;
        } else if (memcmp(name, "r\x00\x65\x00\x63\x00o\x00v\x00\x65\x00r\x00y\x00\x00\x00", 18) == 0) {
            printf("found recovery at 0x%08X\n", start);
            g_recovery = start;
        } else if (memcmp(name, "l\x00k\x00\x00\x00", 6) == 0) {
            printf("found lk at 0x%08X\n", start);
            g_lk = start;
        }
    }
}

int main() {
    printf("This is LK-payload (for mustang) by xyz. Copyright 2019.\n");

    int fastboot = 0;

    parse_gpt();

    if (!g_boot || !g_recovery || !g_lk) {
        printf("failed to find boot, recovery or lk\n");
        while (1) {}
    }

    struct device_t *dev = get_device();

    // Restore the 0x4BD00200-0x4BD01200 range, a part of it was overwritten by microloader
    // this is way more than we actually need to restore, but it shouldn't hurt
    // we can't restore 0x4BD00000-0x4BD00200 as that contains important pointers
    dev->read(dev, g_lk * 0x200 + 0x200 + 0x200, (char*)LK_BASE + 0x200, 0x1000, USER_PART); // +0x200 to skip lk header

    char tmp[0x10] = { 0 };
    dev->read(dev, g_boot * 0x200 + 0x400, tmp, sizeof(tmp) - 1, USER_PART);
    if (strcmp(tmp, "FASTBOOT_PLEASE") == 0) {
        printf("well since you're asking so nicely...\n");
        fastboot = 1;
    }

    uint16_t *patch;

    // force fastboot mode
    if (fastboot) {
        patch = (void*)0x4BD27380;
        *patch = 0;
        patch = (void*)0x4BD27386;
        *patch = 0;
    }

    // enable all commands
    patch = (void*)0x4BD0D854;
    *patch++ = 0x2000; // movs r0, #0
    *patch = 0x4770;   // bx lr

    // device is unlocked
    patch = (void*)0x4BD01EA0;
    *patch++ = 0x2001; // movs r0, #1
    *patch = 0x4770;   // bx lr

    // hook bootimg read function
    uint32_t *patch32;
    original_read = dev->read;
    patch32 = (void*)&dev->read;
    *patch32 = (uint32_t)read_func;

    printf("Clean lk\n");
    cache_clean((void*)LK_BASE, LK_SIZE);

    printf("Jump lk\n");
    int (*app)() = (void*)0x4BD2730D;
    app();

    while (1) {

    }
}
