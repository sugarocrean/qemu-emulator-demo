.globl _start
    .code16
_start:
    xorw %ax, %ax

loop1:
    out %ax, $0x10

    //mmio accessing
    mov $0x1234, %ax
    mov %ax, 0x2000 
    mov 0x2000, %ax
    out %ax, $0x10

    //read from ram, not mmio fault
    mov 0x1000, %ax
    out %ax, $0x10
    
    hlt
