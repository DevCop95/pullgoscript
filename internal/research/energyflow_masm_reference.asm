; OBLITERATUS - Syscall Orchestrator (Grade S)
; Syntax: MASM (x64)
; Purpose: Indirect Syscall Execution with Signal Minimization

.code

; ExecuteS(rcx: arg1, rdx: ssn, r8: jump_addr, r9: arg2, [rsp+40]: arg3, [rsp+48]: arg4, ...)
; Note: We must preserve the shadow space and align the stack for the jump.

ExecuteS proc
    ; Preserve original R10 as per Windows x64 syscall convention
    mov r10, rcx
    
    ; Move SSN into EAX
    mov eax, edx
    
    ; The jump address to ntdll's 'syscall' instruction
    mov r11, r8
    
    ; Shift arguments for the syscall (RCX is already in R10)
    ; In Windows x64: rcx, rdx, r8, r9 are first 4 args.
    ; For syscall: r10, rdx, r8, r9 are first 4 args.
    
    mov rdx, r9          ; arg2 -> rdx
    mov r8, [rsp + 40]   ; arg3 -> r8
    mov r9, [rsp + 48]   ; arg4 -> r9
    
    ; If the syscall needs more than 4 args, they are already on the stack 
    ; but we might need to adjust their position if we were calling a function.
    ; Since we are JUMPING to a 'syscall' instruction, the stack must look
    ; exactly like it would if we were at the start of the syscall stub in ntdll.
    
    ; Adjust stack: we need to skip the return address of ExecuteS 
    ; so the syscall returns directly to our Go caller.
    ; However, 'jmp r11' will execute 'syscall' and then 'ret' (in ntdll or after).
    ; Actually, 'syscall' returns to the instruction after 'syscall'.
    ; In ntdll, it's 'ret'. So it will return to whoever called ExecuteS.
    
    jmp r11
ExecuteS endp

end
