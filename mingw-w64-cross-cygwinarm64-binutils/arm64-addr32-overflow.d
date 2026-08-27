#source: arm64-addr32-overflow.s
#ld: --image-base 0x1000 --defsym overflow=0x100000000
#error: .*\(\.text\+0x0\): relocation truncated to fit: IMAGE_REL_ARM64_ADDR32 against symbol `overflow'.*
