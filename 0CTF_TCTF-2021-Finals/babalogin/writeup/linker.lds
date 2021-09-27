SECTIONS
{
    .text 0x1000 :
    {
        *(.text.startup)
        *(.text)
        *(.data .data*)
        *(.rodata .rodata*)
        *(textend)
    }
}

