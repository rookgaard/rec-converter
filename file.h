#pragma once
#include <windows.h>

FILE* pFile;
WORD clientVersion;
DWORD sumTime;

class GenericFile {
protected:
	HANDLE File;

public:
	GenericFile() : File(INVALID_HANDLE_VALUE) {}
	~GenericFile() {
		if (File != INVALID_HANDLE_VALUE) {
			CloseHandle(File);
		}
	}

	DWORD GetSize() CONST {
		LARGE_INTEGER Size;
		if (!GetFileSizeEx(File, &Size)) {
			return 0;
		}
		if (Size.HighPart) {
			return INVALID_SET_FILE_POINTER;
		}
		return Size.LowPart;
	}
};

struct ReadingFile : public GenericFile {
	BOOL Open(CONST LPCSTR FileName, DWORD Flag) {
		File = CreateFileA(FileName, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, Flag, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		return File != INVALID_HANDLE_VALUE;
	}
	BOOL Skip(CONST DWORD Size) CONST {
		LONG High = 0;
		return SetFilePointer(File, Size, &High, FILE_CURRENT) != INVALID_SET_FILE_POINTER || GetLastError() == NO_ERROR;
	}
	BOOL Read(CONST LPVOID Data, CONST DWORD Size) CONST {
		DWORD Read;
		return ReadFile(File, Data, Size, &Read, NULL) && Read == Size;
	}
	BOOL ReadByte(BYTE& Data) CONST {
		return Read(&Data, 1);
	}
	BOOL ReadWord(WORD& Data) CONST {
		return Read(&Data, 2);
	}
	BOOL ReadDword(DWORD& Data) CONST {
		return Read(&Data, 4);
	}
};

struct WritingFile : public GenericFile {
	BOOL Open(CONST LPCSTR FileName, DWORD Flag) {
		File = CreateFileA(FileName, FILE_WRITE_DATA | DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, Flag, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		return File != INVALID_HANDLE_VALUE;
	}
	BOOL Write(CONST LPCVOID Data, CONST DWORD Size) CONST {
		DWORD Written;
		return WriteFile(File, Data, Size, &Written, NULL) && Written == Size;
	}
	BOOL WriteByte(CONST BYTE Data) CONST {
		return Write(&Data, 1);
	}
	BOOL WriteWord(CONST WORD Data) CONST {
		return Write(&Data, 2);
	}
	BOOL WriteDword(CONST DWORD Data) CONST {
		return Write(&Data, 4);
	}
};

class BufferedFile {
protected:
	LPBYTE Ptr;
	LPBYTE Data;
	LPBYTE End;
public:

	BufferedFile() : Ptr(NULL) {}
	~BufferedFile() {
		delete[] Ptr;
	}

	LPBYTE Start(CONST DWORD Size) {
		return Data = Ptr = new(std::nothrow) BYTE[Size];
	}
	VOID Reset(CONST DWORD Pos) {
		Data = Ptr + Pos;
	}
	LPBYTE Skip(CONST DWORD Size) {
		if (Data + Size > End) {
			return NULL;
		}
		LPBYTE Result = Data;
		Data += Size;
		return Result;
	}
	VOID Write(CONST LPCVOID Src, CONST DWORD Size) {
		CopyMemory(Data, Src, Size);
		Data += Size;
	}
	VOID WriteByte(CONST BYTE Src) {
		return Write(&Src, 1);
	}
	VOID WriteWord(CONST WORD Src) {
		return Write(&Src, 2);
	}
	VOID WriteDword(CONST DWORD Src) {
		return Write(&Src, 4);
	}
	BOOL Read(CONST LPVOID Dest, CONST DWORD Size) {
		if (Data + Size > End) {
			return FALSE;
		}
		CopyMemory(Dest, Data, Size);
		Data += Size;
		return TRUE;
	}
	BOOL ReadByte(BYTE& Dest) {
		return Read(&Dest, 1);
	}
	BOOL ReadWord(WORD& Dest) {
		return Read(&Dest, 2);
	}
	BOOL ReadDword(DWORD& Dest) {
		return Read(&Dest, 4);
	}
	DWORD Open(CONST LPCSTR FileName) {
		ReadingFile File;
		if (File.Open(FileName, OPEN_EXISTING)) {
			DWORD Size = File.GetSize();
			if (Size) {
				if (Start(Size + 1)) {
					if (File.Read(Data, Size)) {
						End = Data + Size;
						return Size;
					}
				}
			}
		}
		return 0;
	}
};
