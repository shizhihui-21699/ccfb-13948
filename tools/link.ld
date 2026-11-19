OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(_start)
SECTIONS
{
  . = 0x00000000;
  .text : { *(.text.entry) *(.text*) }
  . = ALIGN(4);
  .rodata : { *(.rodata*) }
  . = ALIGN(4);
  . = 0x10000000;
  .data : { *(.data*) }
  . = ALIGN(4);
  .bss : { *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.ARM.attributes) *(.ARM.exidx*) *(.comment) *(.note*) *(.eh_frame*) }
}
