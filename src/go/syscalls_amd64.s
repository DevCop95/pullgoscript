// +build amd64

#include "textflag.h"

// EnergyFlow(a1 uintptr, id uint32, ep uintptr, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 uintptr) uint32
// Reconstrucción Técnica: Equilibrio de Nash en el Stack
// Convención Windows x64: RCX(R10), RDX, R8, R9 + Stack (Shadow Space 32 bytes)

TEXT ·EnergyFlow(SB), NOSPLIT, $128-112
    // Cargamos los registros de control desde el stack de Go (FP)
    MOVQ a1+0(FP), R10      // arg1 para syscall
    MOVL id+8(FP), AX       // SSN (System Service Number)
    MOVQ ep+16(FP), R11     // Dirección de salto (ntdll gadget)
    
    // Mapeo de argumentos 2-4 a registros
    MOVQ a2+24(FP), DX      // arg2
    MOVQ a3+32(FP), R8       // arg3
    MOVQ a4+40(FP), R9       // arg4
    
    // Mapeo de argumentos 5-11 al stack (siguiendo Windows x64 Calling Convention)
    // El Shadow Space ocupa los primeros 32 bytes (0-31), el 5to arg empieza en 32(SP)
    MOVQ a5+48(FP), CX;  MOVQ CX, 32(SP)
    MOVQ a6+56(FP), CX;  MOVQ CX, 40(SP)
    MOVQ a7+64(FP), CX;  MOVQ CX, 48(SP)
    MOVQ a8+72(FP), CX;  MOVQ CX, 56(SP)
    MOVQ a9+80(FP), CX;  MOVQ CX, 64(SP)
    MOVQ a10+88(FP), CX; MOVQ CX, 72(SP)
    MOVQ a11+96(FP), CX; MOVQ CX, 80(SP)
    
    // Ejecución indirecta
    // Usamos CALL para mantener la higiene del stack y permitir un retorno limpio a Go
    CALL R11
    
    // El resultado del syscall ya está en AX
    RET
