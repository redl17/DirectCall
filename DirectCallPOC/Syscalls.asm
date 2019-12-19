.code

NtCreateFile10 proc
	mov r10, rcx
	mov eax, 55h
	syscall
	ret
NtCreateFile10 endp

ZwQuerySystemInformation10 proc
	mov r10, rcx                        
	mov eax, 36h
	syscall        
	ret
ZwQuerySystemInformation10 endp

NtAllocateVirtualMemory10 proc
	mov r10, rcx                        
	mov eax, 18h
	syscall        
	ret
NtAllocateVirtualMemory10 endp

NtFreeVirtualMemory10 proc
	mov r10, rcx                        
	mov eax, 1Eh
	syscall        
	ret
NtFreeVirtualMemory10 endp

ZwOpenProcess10 proc
	mov r10, rcx                        
	mov eax, 26h
	syscall        
	ret
ZwOpenProcess10 endp

end