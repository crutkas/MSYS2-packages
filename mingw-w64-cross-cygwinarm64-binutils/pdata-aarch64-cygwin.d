#name: AArch64 Cygwin PE .pdata
#target: aarch64-*-cygwin*
#source: pdata-aarch64.s
#ld: -e function
#objdump: -p

#...
The Function Table \(interpreted \.pdata section contents\)
 vma:		Begin    Unwind
     		Address  Data
 0000000100403000	0000000000001000 0000000000004000
#...
