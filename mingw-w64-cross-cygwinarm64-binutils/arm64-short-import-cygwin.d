
.*:     file format pei-aarch64-little


Disassembly of section .text:

0000000100401000 <___tls_end__>:
   100401000:	14000001 	b	100401004 <test_reloc>

0000000100401004 <test_reloc>:
   100401004:	d0000010 	adrp	x16, 100403000 <__IMPORT_DESCRIPTOR_arm64-short-import>
   100401008:	91014210 	add	x16, x16, #0x50
   10040100c:	f9400210 	ldr	x16, \[x16\]
   100401010:	d61f0200 	br	x16
#pass
