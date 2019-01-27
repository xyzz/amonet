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

int (*original_read)(struct device_t *dev, uint64_t block_off, void *dst, size_t sz, int part) = 0x4BD1E839;

uint64_t g_boot, g_recovery, g_lk;

int read_func(struct device_t *dev, uint64_t block_off, void *dst, size_t sz, int part) {
    int ret = 0;
    if (block_off == g_boot * 0x200 || block_off == g_recovery * 0x200) {
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
    for (int i = 0; i < sizeof(raw) / 0x80; ++i) {
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
    int ret = 0;
    printf("This is LK-payload by xyz. Copyright 2019\n");

    uint32_t **argptr = (void*)0x4BD00020;
    uint32_t *arg = *argptr;
    arg[0x53] = 4; // force 64-bit linux kernel

    int fastboot = 0;

    /*
    [300] [LK/LCM] lcm_init enter, build type: PVT, vendor type: FITI_KD
    [300] [LK/LCM] lcm_init No LCM connected. Just Return
    [340] DSI_WaitForNotBusy:Error:DSI_INTSTA is 0...
    */

    parse_gpt();

    if (!g_boot || !g_recovery || !g_lk) {
        printf("failed to find boot, recovery or lk\n");
        while (1) {}
    }

    struct device_t *dev = get_device();

    void *lk_tmp = (void*)0x44000000;
    #define LK_SIZE (0x800 * 0x200)
    ret = dev->read(dev, g_lk * 0x200 + 0x200, lk_tmp, LK_SIZE, USER_PART);
    printf("read lk: 0x%08X\n", ret);

    uint8_t tmp[0x10] = { 0 };
    dev->read(dev, g_boot * 0x200 + 0x400, tmp, 0x10, USER_PART);
    if (strcmp(tmp, "FASTBOOT_PLEASE") == 0) {
        printf("well since you're asking so nicely...\n");
        fastboot = 1;
    }

    printf("Disable interrupts\n");
    asm volatile ("cpsid if");

    printf("Copy lk\n");
    void *lk_dst = (void*)0x4BD00000;
    memcpy(lk_dst, lk_tmp, LK_SIZE);

    uint16_t *patch;

    // force fastboot mode
    if (fastboot) {
        patch = (void*)0x4BD2717C;
        *patch = 0;
        patch = (void*)0x4BD27182;
        *patch = 0;
    }

    // enable all commands
    patch = (void*)0x4BD0D838;
    *patch++ = 0x2000; // movs r0, #0
    *patch = 0x4770;   // bx lr

    // fix display?
    patch = (void*)0x4bd2fe76;
    *patch++ = 0x20A7;
    *patch++ = 0;

    // device is unlocked
    patch = (void*)0x4BD01E84;
    *patch++ = 0x2001; // movs r0, #1
    *patch = 0x4770;   // bx lr

    // don't sprintf disable printk
    // patch = (void*)0x4BD26766;
    // *patch++ = 0;
    // *patch++ = 0;

    // hook bootimg read function
    uint32_t *patch32;
    patch32 = (void*)0x4BD5538C;
    *patch32 = read_func;

    printf("Clean lk\n");
    cache_clean(lk_dst, LK_SIZE);

    printf("About to jump to LK\n");
    asm volatile (
        "mov r4, %0\n" 
        "mov r3, %1\n"
        "blx r3\n"
        : : "r" (arg), "r" (lk_dst) : "r3", "r4");

    printf("Failure\n");

    while (1) {

    }
}
