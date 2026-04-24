// +build amd64

// EnergyFlow(a1 uintptr, id uint32, ep uintptr, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 uintptr) uint32
TEXT ·EnergyFlow(SB), $0-112
    // Diversion layer
    PUSHQ R15
    XORQ R15, R15
    MOVQ a1+0(FP), R10   
    MOVL id+8(FP), AX      
    MOVQ ep+16(FP), R11 
    
    // Entropy Noise
    NOP
    MOVQ R15, R15
    
    MOVQ a2+24(FP), DX   
    MOVQ a3+32(FP), R8    
    MOVQ a4+40(FP), R9    
    
    // Dynamic stack re-alignment
    MOVQ a5+48(FP), CX; MOVQ CX, 32(SP)
    MOVQ a6+56(FP), CX; MOVQ CX, 40(SP)
    MOVQ a7+64(FP), CX; MOVQ CX, 48(SP)
    MOVQ a8+72(FP), CX; MOVQ CX, 56(SP)
    MOVQ a9+80(FP), CX; MOVQ CX, 64(SP)
    MOVQ a10+88(FP), CX; MOVQ CX, 72(SP)
    MOVQ a11+96(FP), CX; MOVQ CX, 80(SP)
    
    POPQ R15
    JMP R11
    RET
