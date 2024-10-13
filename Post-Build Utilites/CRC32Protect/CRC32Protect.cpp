//*****************************************************************************
// Вспомогательная утилита, используемая на Post-build step'е сборки
// проекта защищенного приложения.
// Назначение: вычисление хэш-значений для помеченных соответствующими 
// маркерами участков данных/кода (с использованием алгоритма CRC32), 
// размещение вычисленных хэш-значений в указанном месте защищенного приложения. 
//
// Автор - Сергей Усков (a9wdk@yandex.ru, Telegram: @a9wdk)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "macros.h"

#define UtilityName		"Post-Build CRC Calculation Tools"
#define UtilityVersion	"2.0"
#define UtilityDate	    "2013"

#define SignatureLength	  7
#define FirstChar		 '-'

//////////////////////////////////////////////////////////////////////////////////////////////
// Глобальные переменные.

CHAR	SrcFile[255], Str[255];
DWORD	dwFileSize, Done, MarkersDone = 0;
HANDLE	hSrcFile, hFileMapping;
LPVOID	lpFileMap;
PBYTE	Buffer, LastDsc = NULL;

//////////////////////////////////////////////////////////////////////////////////////////////

void	PrintDump(PBYTE buffer, DWORD offset);
DWORD   VAtoRAW(PBYTE Base, PBYTE VA);
BOOL	SavingImageBaseValue(PBYTE buffer, DWORD length);
DWORD	SearchCrcDataMarker(PBYTE buffer, DWORD length);
DWORD	SearchCrcCodeMarker(PBYTE buffer, DWORD length);
DWORD	SearchCrcLibsMarker(PBYTE buffer, DWORD length);
DWORD	SearchDscListEntryPoint(PBYTE buffer, DWORD length);
void	ReplaceData(PBYTE buffer, DWORD length);
void	ReplaceCode(PBYTE buffer, DWORD length);
DWORD	CalcCRC32(PBYTE buffer, DWORD length);

//////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[]) {
	printf("\n \n############################################################################################\n");
	printf("#                 %s, version %s, SU(C) %s                #\n", UtilityName, UtilityVersion, UtilityDate);
	printf("############################################################################################\n \n");

	// Разбираем командную строку
	if(argc != 2) {
		printf("Usage:   CRC32Protect <target file>\nExample: CRC32Protect Sample.exe\n\n");
		return -1;
	}
	sprintf_s(SrcFile, sizeof(SrcFile), "%s", argv[1]); 

	// Открываем целевой файл
	printf("Open the target file ........................... %s -> ", SrcFile);
	hSrcFile = CreateFile(SrcFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if(hSrcFile == INVALID_HANDLE_VALUE) {
		printf("Error\n");
		return -2;
	}
	printf("Ok\n");

	// Создаем объект-отображение для исходного файла
	printf("Create the FileMapping object .................. ");
	dwFileSize = GetFileSize(hSrcFile, NULL);
	hFileMapping = CreateFileMapping(hSrcFile, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);
	if(hFileMapping == NULL) {
		printf("Error\n");
		return -3;
	}	
	printf("Ok\n");
	
	// Выполняем отображение файла на память. В переменную lpFileMap будет записан указатель на отображаемую область памяти
	printf("Maps a view of a file into the address space ... ");
	lpFileMap = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if(lpFileMap == 0) {
		printf("Error\n");
		return -4;
	}	
	Buffer = (PBYTE)lpFileMap;
	printf("Ok\n \n");

	srand(GetTickCount());

	SavingImageBaseValue(Buffer, dwFileSize);

	printf("\n----------------------------- CRC32 Data Markers processing --------------------------------\n \n");

	Done = SearchCrcDataMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;

	printf("\n---------------------------- CRC32 Code Markers processing ---------------------------------\n \n");
	
	Done = SearchCrcCodeMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;
	
	printf("\n------------------------- CRC32 Library Code Markers processing ----------------------------\n \n");
	
	Done = SearchCrcLibsMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;
	
	printf("\n---------------------- CRC-Descriptor's list Entry Point searching -------------------------\n \n");

	Done = SearchDscListEntryPoint(Buffer, dwFileSize);

	printf("\n--------------------- Processing is completed. %.2d marker(s) are found ----------------------\n \n", MarkersDone);

	// Отменяем отображение файла и освобождаем идентификатор созданного объекта-отображения
	printf("\nClose the target file .......................... ");
	UnmapViewOfFile(lpFileMap);
	CloseHandle(hFileMapping);	
	printf("Ok\n \n");

	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура печатает HEX/ASCII-дамп параграфа памяти (16 байт) с указанного смещения.
void PrintDump(PBYTE buffer, const DWORD offset) {
	DWORD i;

	printf("%08X ", offset);
	for(i = 0; i < 16; i++) printf(" %02X", buffer[offset+i]);
	printf("  ");
	for(i = 0; i < 16; i++) printf("%c", buffer[offset+i] > 0x1F && buffer[offset+i] < 0xFF ? buffer[offset+i] : '.');
	printf("\n");
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура переводит VA-адрес объекта в целевом файле в смещение относительно начала этого 
// файла, загруженного в буфер по адресу Base.

#define ALIGN_DOWN(x, align)  (x & ~(align - 1))										//выравнивание вниз
#define ALIGN_UP(x, align)    ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x)	//выравнивание вверх

DWORD VAtoRAW(PBYTE Base, PBYTE VA) {
	DWORD VirtualAddress, PointerToRawData, i;
	BOOL flag = FALSE;

	PIMAGE_NT_HEADERS32 PEHeader  = (PIMAGE_NT_HEADERS32)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	DWORD RVA                     = (DWORD)(VA - PEHeader->OptionalHeader.ImageBase);
	DWORD SectionAlign            = PEHeader->OptionalHeader.SectionAlignment;
	WORD NumberOfSection          = PEHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Section = (PIMAGE_SECTION_HEADER)(PEHeader->FileHeader.SizeOfOptionalHeader + 
		(DWORD)&(PEHeader->FileHeader) + sizeof(IMAGE_FILE_HEADER));

	for(i = 0; i < NumberOfSection; i++) {
		if((RVA >= Section->VirtualAddress) && 
			(RVA <  Section->VirtualAddress + ALIGN_UP(Section->Misc.VirtualSize, SectionAlign))) {

				VirtualAddress   = Section->VirtualAddress;
				PointerToRawData = Section->PointerToRawData;
				flag = TRUE;
				break;
		}
		Section++;
	}
	if(flag) return(RVA - VirtualAddress + PointerToRawData); else return(RVA);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура ищет в целевом файле дескриптор-контейнер для сохранения оригинального значения
// ImageBase, т.к. в случае использования технологии ASLR, оригинальное значение ImageBase
// произвольно перезаписывается системным загрузчиком. 

BOOL SavingImageBaseValue(PBYTE buffer, DWORD length) {
	DWORD i;
	PBYTE startPtr;
	POrgPE descriptor;
	PIMAGE_NT_HEADERS32 PEHeader  = (PIMAGE_NT_HEADERS32)(buffer + ((PIMAGE_DOS_HEADER)buffer)->e_lfanew);

	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, OrgPESig, SignatureLength)) {

			// Найден дескриптор-контейнер для хранения ImageBase.
			printf("\n-------------------------- Saving the ImageBase original value -----------------------------\n \n");

			descriptor = (POrgPE)(buffer + i);
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// Маркер

			// Сохраняем оригинальное значение ImageBase.
			printf("> Saving ImageBase original value ................ ");
			descriptor->ImageBase = PEHeader->OptionalHeader.ImageBase;
			printf("Ok\n");

			// Заполняем мусором сигнатуру дескриптора.
			printf("> Descriptor's signature replacement ............. ");
			ReplaceData(startPtr, SignatureLength);
			printf("Ok\n");

			// Выводим дамп дескриптора после обработки.
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// Маркер
			printf("\n \n");
			return TRUE;
		}	
	}	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура ищет в целевом файле структуры, описывающие данные, которые необходимо зашифровать.
DWORD SearchCrcDataMarker(PBYTE buffer, DWORD length) {
	DWORD i, descriptor_raw, data_raw, done = 0;
	PBYTE startPtr;
	PCrcDataMrk marker;
	PCrcDsc descriptor;

	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, CrcDataSig, SignatureLength)) {
			
			// Найден маркер, описывающий данные, выводим дампы маркера и данных.
			done++;
			marker = (PCrcDataMrk)startPtr;
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->CrcDscAddr);
			descriptor = (PCrcDsc)(buffer + descriptor_raw);
			data_raw = VAtoRAW(buffer, (PBYTE)marker->Addr);
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, marker->Length, marker->Length);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// Дескриптор
			printf("DATA_RAW ....... "); PrintDump(buffer, data_raw);			// Данные
			
			// Заполняем данными структуру-описатель, выводим расчитанное значение контрольной суммы.
			printf("> Calculation CRC ................................ ");
			descriptor->NextDsc = LastDsc;					// Адрес последнего найденного дескриптора
			LastDsc = (PBYTE)marker->CrcDscAddr;			// Теперь последний - текущий дескриптор
			descriptor->Addr = (PBYTE)marker->Addr;
			descriptor->Length = marker->Length;
			descriptor->OrgCrc = CalcCRC32(buffer + data_raw, descriptor->Length);
			descriptor->CurrCrc = 0;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("%08Xh\n", descriptor->OrgCrc);
			
			// Заполняем мусором маркер.
			printf("> Marker's content replacement ................... ");
			ReplaceData(startPtr, sizeof(CrcDataMrk)); 
			printf("Ok\n");

			// Выводим дампы маркера и описателя.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// Дескриптор
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура ищет в целевом файле структуры, описывающие данные, которые необходимо зашифровать.
DWORD SearchCrcCodeMarker(PBYTE buffer, DWORD length) {
	DWORD i, descriptor_raw, code_raw, code_len, done = 0;
	PBYTE startPtr;
	PCrcCodeMrk marker;
	PCrcDsc descriptor;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, CrcCodeSig, SignatureLength)){
			
			// Найден маркер, описывающий код, выводим дампы маркера и кода.
			done++;
			marker = (PCrcCodeMrk)startPtr;
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
			descriptor = (PCrcDsc)(buffer + descriptor_raw);
			code_raw = VAtoRAW(buffer, (PBYTE)marker->StartAddr);
			code_len = marker->EndAddr - marker->StartAddr;
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, code_len, code_len);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// Дескриптор
			printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);			// Код
			
			// Заполняем данными структуру-описатель, выводим расчитанное значение контрольной суммы.
			printf("> Calculation CRC ................................ ");
			descriptor->NextDsc = LastDsc;					// Адрес последнего найденного дескриптора
			LastDsc = (PBYTE)marker->DescriptorAddr ;		// Теперь последний - текущий дескриптор
			descriptor->Addr = (PBYTE)marker->StartAddr;
			descriptor->Length = code_len;
			descriptor->OrgCrc = CalcCRC32(buffer + code_raw, descriptor->Length);
			descriptor->CurrCrc = 0;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("%08Xh\n", descriptor->OrgCrc);
	
			// Заполняем мусором маркер.
			printf("> Marker's content replacement ................... ");
			ReplaceCode(startPtr, sizeof(CrcCodeMrk)); 	
			printf("Ok\n");
			
			// Выводим дампы маркера и описателя.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// Дескриптор
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура ищет в целевом файле структуры, описывающие данные, которые необходимо зашифровать.
DWORD SearchCrcLibsMarker(PBYTE buffer, DWORD length) {
	DWORD i, descriptor_raw, code_raw, code_len, done = 0;
	PBYTE startPtr;
	PCrcLibsMrk marker;
	PCrcDsc descriptor;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, CrcLibsSig, SignatureLength)){
			
			// Найден маркер, описывающий код, выводим дампы маркера и кода.
			done++;
			marker = (PCrcLibsMrk)startPtr;
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
			descriptor = (PCrcDsc)(buffer + descriptor_raw);
			code_raw = VAtoRAW(buffer, (PBYTE)marker->EntryPointAddr);
			code_len = marker->CodeLength ;
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, code_len, code_len);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// Дескриптор
			printf("LIB_CODE_RAW ... "); PrintDump(buffer, code_raw);			// Код
			
			// Заполняем данными структуру-описатель, выводим расчитанное значение контрольной суммы.
			printf("> Calculation CRC ................................ ");
			descriptor->NextDsc = LastDsc;						// Адрес последнего найденного дескриптора
			LastDsc = (PBYTE)marker->DescriptorAddr;			// Теперь последний - текущий дескриптор
			descriptor->Addr = (PBYTE)marker->EntryPointAddr;
			descriptor->Length = code_len;
			descriptor->OrgCrc = CalcCRC32(buffer + code_raw, descriptor->Length);
			descriptor->CurrCrc = 0;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("%08Xh\n", descriptor->OrgCrc);
			
			// Заполняем мусором маркер.
			printf("> Marker's content replacement ................... ");
			ReplaceCode(startPtr, sizeof(CrcLibsMrk)); 	
			printf("Ok\n");
			
			// Выводим дампы маркера и описателя.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// Дескриптор
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура ищет в целевом файле дескриптор точки входа в односвязный список дескрипторов
// _CrcDsc и инициализирует её адресом последнего найденного дескриптора.
DWORD SearchDscListEntryPoint(PBYTE buffer, DWORD length) {
	DWORD i;
	PBYTE startPtr;
	PCrcDscList marker;

	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, CrcDscListSig, SignatureLength)) {

			// Найден дескриптор точки входа, выводим дамп дескриптора.
			marker = (PCrcDscList)(buffer + i);
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// Маркер

			// Инициализируем указатель точки входа адресом последнего найденного дескриптора.
			printf("> Entry Point initialization ..................... ");
			marker->EntryPoint = (PCrcDsc)LastDsc;
			printf("Ok\n");

			// Заполняем мусором сигнатуру дескриптора.
			printf("> Descriptor's signature replacement ............. ");
			ReplaceData(startPtr, SignatureLength);
			printf("Ok\n");

			// Выводим дамп дескриптора после обработки.
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// Маркер
			printf("\n \n");
			return 0;
		}	
	}	

	if(MarkersDone) printf("\nDescriptor not found. List entry point is not created.\n \n");
		else printf("\nList is empty.\n \n");

	return 1;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура замещает содержимое указанного буфера с данными на "мусор". 
void ReplaceData(PBYTE buffer, DWORD length) {
	for(DWORD i = 0; i < length; i++) buffer[i] = rand() % 0xFF;	// Генерируем мусор
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура замещает содержимое указанного буфера с кодом на "мусор". 
void ReplaceCode(PBYTE buffer, DWORD length) {
	DWORD i;
		
	if(length > 2 && length < 128) {
		// Если длина маркера допускает использование инструкции короткого перехода, то формируем 
		// jmp short вокруг всего маркера, а внутренности маркера забиваем мусором.
		buffer[0] = 0xEB;										// Опкод jmp short ххх
		buffer[1] = (BYTE)(length - 2);							// Вычисляем операнд инструкции
		for(i = 2; i < length; i++) buffer[i] = rand() % 0xFF;	// Генерируем мусор
	} else {
		// Если маркер очень короткий или слишком длинный для использования короткого перехода, забиваем его NOP'ами, 
		for(i = 0; i < length; i++) buffer[i] = 0x90;	
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура вычисляет контрольную сумму, используя одну из реализаций алгоритма CRC32.
DWORD CalcCRC32(PBYTE buffer, DWORD length) {
    DWORD i, j, crc, crc_table[256]; 
	
    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
        crc_table[i] = crc;
    }
	
    crc = 0xFFFFFFFFUL;
    while(length--) crc = crc_table[(crc ^ *buffer++) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFUL;
}