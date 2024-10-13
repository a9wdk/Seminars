//*****************************************************************************
// (v11) Вспомогательная утилита, используемая на Post-build step'е сборки
// проекта защищенного приложения.
// Назначение: зашифрование помеченных соответствующими маркерами участки кода. 
//
// Автор - Сергей Усков (a9wdk@yandex.ru, Telegram: @a9wdk)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "hasp_api.h"
#include "hasp_vcode.h"
#include "macros.h"

#define UtilityName     "Post-Build Code Encryption Tools"
#define UtilityVersion  "2.0"
#define UtilityDate     "2013"

#define SignatureLength   7
#define FirstChar        '-'

//////////////////////////////////////////////////////////////////////////////////////////////
// Глобальные переменные.

CHAR    SrcFile[255];
DWORD   dwFileSize, Done, MarkersDone = 0;
HANDLE  hSrcFile, hFileMapping;
LPVOID  lpFileMap;
PBYTE   Buffer;

//////////////////////////////////////////////////////////////////////////////////////////////

void    PrintDump(PBYTE buffer, DWORD offset);
DWORD   VAtoRAW(PBYTE Base, PBYTE VA);
BOOL    SavingImageBaseValue(PBYTE buffer, DWORD length);
DWORD   SearchExceptionData(PBYTE buffer, DWORD length);    
DWORD   SearchCustomEncryptCodeMarker(PBYTE buffer, DWORD length);      
DWORD   SearchKeyEncryptCodeMarker(PBYTE buffer, DWORD length);     
void    CustomEncryptCode(PBYTE buffer, DWORD length);
DWORD   KeyEncryptCode(PBYTE buffer, DWORD length, DWORD feature);
void    ReplaceData(PBYTE buffer, DWORD length);
void    ReplaceCode(PBYTE buffer, DWORD length);
void    ConsolErrMsg(PCHAR format, ...);
DWORD   MsgBox(PCHAR title, UINT style, PCHAR format, ...);

//////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[]) {
    UINT major_ver, minor_ver, build_srv, build_num;
    hasp_get_version(&major_ver, &minor_ver, &build_srv, &build_num, NULL);

    printf("\n \n############################################################################################\n");
    printf("#                 %s, version %s, SU(C) %s                #\n", UtilityName, UtilityVersion, UtilityDate);
    printf("#                                  LDK API v%u.%u.%u.%u                                    #\n", major_ver, minor_ver, build_srv, build_num);
    printf("############################################################################################\n \n");

    // Разбираем командную строку
    if(argc != 2) {
        printf("Usage:   CodeEncrypt <target file>\nExample: CodeEncrypt Sample.exe\n\n");
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

    printf("\n-------------------- Processing the Data site for Exception Handler ------------------------\n \n");

    Done = SearchExceptionData(Buffer, dwFileSize);
    if(!Done) printf("Data site for Exception Handler not found.\n \n");
        else  printf("Data site for Exception Handler processed: %d\n \n", Done);

    printf("\n------------------------ Custom Encrypt Code Markers processing ----------------------------\n \n");

    Done = SearchCustomEncryptCodeMarker(Buffer, dwFileSize);
    if(!Done) printf("Markers not found.\n \n");
    MarkersDone += Done;

    printf("\n-------------------------- Key Encrypt Code Markers processing -----------------------------\n \n");

    Done = SearchKeyEncryptCodeMarker(Buffer, dwFileSize);
    if(!Done) printf("Markers not found.\n \n");
    MarkersDone += Done;

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

#define ALIGN_DOWN(x, align)  (x & ~(align - 1))                                        //выравнивание вниз
#define ALIGN_UP(x, align)    ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x)    //выравнивание вверх

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
            printf("Descriptor_RAW . "); PrintDump(buffer, i);          // Маркер

            // Сохраняем оригинальное значение ImageBase.
            printf("> Saving ImageBase original value ................ ");
            descriptor->ImageBase = PEHeader->OptionalHeader.ImageBase;
            printf("Ok\n");

            // Заполняем мусором сигнатуру дескриптора.
            printf("> Descriptor's signature replacement ............. ");
            ReplaceData(startPtr, SignatureLength);
            printf("Ok\n");

            // Выводим дамп дескриптора после обработки.
            printf("Descriptor_RAW . "); PrintDump(buffer, i);          // Маркер
            printf("\n \n");
            return TRUE;
        }   
    }   
    return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура ищет в целевом файле инструкции, предназначенные для передачи данных в обработчик
// исключительной ситуации (шаблон для поиска - 0F xx BC xx xx xx xx BC xx xx xx xx). В случае
// обнаружения места размещения таких инструкций выполняется замена их опкодов (0xBC - mov ESP, ...)
// на случайные байты с целью предотвращения возникновения характерных сигнатур в местах возбуждения
// исключительных ситуаций  

DWORD SearchExceptionData(PBYTE buffer, DWORD length) {
    DWORD i, done = 0;
    PRaiseExcept DataSite;
    PBYTE startPtr;
    
    for(i = 0; i < length; i++) {
        startPtr = (PBYTE)memchr(buffer+i, FirstByteBadOpCode, length-i);
        if(startPtr == NULL) continue;
        i = startPtr - buffer;
        DataSite = (PRaiseExcept)startPtr ;
        if(DataSite->OpCode0 == ExceptionDataOpCode && DataSite->OpCode1 == ExceptionDataOpCode) {
            
            // Обнаружены инструкции, предназначенные для передачи данных в обработчик исключительной
            // ситуации и соответствующие шаблону поиска 0F xx BC xx xx xx xx BC xx xx xx xx
            done++;
            PrintDump(buffer, i);               // Дамп до обработки

            // Заменяем опкоды инструкций на случайные байты.
            printf("OpCode replacement ............................. ");
            ReplaceData(&DataSite->OpCode0, 1);     
            ReplaceData(&DataSite->OpCode1, 1);     
            printf("Ok\n");

            PrintDump(buffer, i);               // Дамп после обработки
            printf("\n \n");
        }
    }   
    return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура ищет в целевом файле структуры-маркеры, описывающие данные, которые необходимо 
// зашифровать алгоритмом, ранее использованным для маскировки характерных сигнатур.

DWORD SearchCustomEncryptCodeMarker(PBYTE buffer, DWORD length) {
    DWORD i, descriptor_raw, code_raw, code_len, done = 0;
    PCstEncCodeMrk marker;      // Маркер
    PCstEncCodeDsc descriptor;  // Дескриптор
    PBYTE startPtr;

    for(i = 0; i < length; i++) {
        startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
        if(startPtr == NULL) continue;
        i = startPtr - buffer;
        if(!memcmp(startPtr, CstEncCodeSig, SignatureLength)) {
            
            // Найдена структура-маркер, описывающая код, подлежащий зашифрованию. Определяем и выводим 
            // основные параметры, переданные через маркер.
            done++;
            marker = (PCstEncCodeMrk)(buffer + i);
            descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
            descriptor = (PCstEncCodeDsc)(buffer + descriptor_raw);
            code_raw = VAtoRAW(buffer, (PBYTE)marker->StartAddr);
            code_len = marker->EndAddr - marker->StartAddr;

            // Выводим дампы маркера, дескриптора и целевого кода (вид до обработки).
            printf("Marker_RAW ..... "); PrintDump(buffer, i);              // Маркер
            printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw); // Дескриптор
            printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);       // Код

            // Зашифровываем целевой код
            printf("> Encrypt the target CODE ........................ ");
            CustomEncryptCode(buffer + code_raw, code_len);
            printf("Ok, CODE length %d(%Xh) byte(s)\n", code_len, code_len);

            // Заполняем дескриптор на основе данных из маркера.
            printf("> Descriptor filling ............................. ");
            descriptor->Addr = (PBYTE)marker->StartAddr;
            descriptor->Length = code_len;
            descriptor->ValidateFlag = FALSE;
            printf("Ok\n");
    
            // Заполняем маркер корректным машинным кодом.
            printf("> Marker's content replacement ................... ");
            ReplaceCode(startPtr, sizeof(CstEncCodeMrk));   
            printf("Ok\n");

            // Выводим дампы маркера, дескриптора и целевого кода (вид после обработки).
            printf("Marker_RAW ..... "); PrintDump(buffer, i);              // Маркер
            printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw); // Дескриптор
            printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);       // Код
            printf("\n \n");
        }
    }   
    return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура ищет в целевом файле структуры-маркеры, описывающие данные, которые необходимо 
// зашифровать алгоритмом, ранее использованным для маскировки характерных сигнатур.

DWORD SearchKeyEncryptCodeMarker(PBYTE buffer, DWORD length) {
    DWORD i, code_raw, code_len, descriptor_raw, session_raw, feature, status, done = 0;
    PKeyEncCodeMrk marker;      // Маркер
    PKeyEncCodeDsc descriptor;  // Дескриптор
    PHaspSession session;
    PBYTE startPtr;
    
    for(i = 0; i < length; i++) {
        startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
        if(startPtr == NULL) continue;
        i = startPtr - buffer;
        if(!memcmp(startPtr, KeyEncCodeSig, SignatureLength)) {
            
            // Найдена структура-маркер, описывающая код, подлежащий зашифрованию. Определяем и выводим 
            // основные параметры, переданные через маркер.
            done++;
            marker = (PKeyEncCodeMrk)(buffer + i);
            descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
            descriptor = (PKeyEncCodeDsc)(buffer + descriptor_raw);
            session_raw = VAtoRAW(buffer, (PBYTE)marker->KeySessionAddr);
            session = (PHaspSession)(buffer + session_raw);
            feature = session->feature;
            code_raw = VAtoRAW(buffer, (PBYTE)marker->StartAddr);
            code_len = marker->EndAddr - marker->StartAddr;
            
            // Выводим дампы маркера, дескрипторов и целевого кода (вид до обработки).
            printf("Marker_RAW ..... "); PrintDump(buffer, i);              // Маркер
            printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw); // Дескриптор
            printf("KeySession_RAW . "); PrintDump(buffer, session_raw);    // Дескриптор сессии с ключом
            printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);       // Код
            
            // Зашифровываем целевой код
            printf("> Encrypt the target CODE ........................ ");
            status = KeyEncryptCode((PBYTE)(buffer + code_raw), code_len, feature);
            if(status == HASP_STATUS_OK) {
                printf("Ok, CODE length %d(%Xh) byte(s)\n", code_len, code_len);
                
                // Заполняем дескриптор на основе данных из маркера.
                printf("> Descriptor filling ............................. ");
                descriptor->KeySessionAddr = (PHaspSession)marker->KeySessionAddr;
                descriptor->Addr = (PBYTE)marker->StartAddr;
                descriptor->Length = code_len;
                descriptor->ValidateFlag = FALSE;
                printf("Ok\n");

                // Заполняем маркер корректным машинным кодом.
                printf("> Marker's content replacement ................... ");
                ReplaceCode(startPtr, sizeof(KeyEncCodeMrk));   
                printf("Ok\n");

                // Выводим дампы маркера, дескриптора и целевого кода (вид после обработки).
                printf("Marker_RAW ..... "); PrintDump(buffer, i);              // Маркер
                printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw); // Дескриптор
                printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);       // Код
                printf("\n \n");

            } else {

                printf("LDK API Error #%d\n", status);
                ConsolErrMsg("Code key-encryption error #%d", status);
                MsgBox(UtilityName, MB_ICONERROR, "Code key-encryption error #%d", status);
            }
        }
    }   
    return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура зашифровывает указанные данные в целевом файле. Алгоритм и его параметры 
//  (начальное значение - XOR) должны соответствовать используемым в целевом файле.

#define XOR 0x53

void CustomEncryptCode(PBYTE buffer, DWORD length) {

    buffer[0] ^= XOR;
    for(DWORD i = 1; i < length; i++) buffer[i] ^= buffer[i-1];
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура зашифровывает указанные данные с использованием указанной фичи ключа.

DWORD KeyEncryptCode(PBYTE buffer, DWORD length, DWORD feature) {
    DWORD status;
    hasp_handle_t handle = HASP_INVALID_HANDLE_VALUE;
    
    // Выполняем Login на Feature ID указанный в маркере региона.
    status = hasp_login((hasp_feature_t)feature, vendor_code, &handle);
    if(status != HASP_STATUS_OK) return status; 
    
    // Зашифровываем регион
    status = hasp_encrypt(handle, buffer, length);
    if(status != HASP_STATUS_OK) {
        hasp_logout(handle);
        return status; 
    }
    
    // Закрываем сессию с ключом
    status = hasp_logout(handle);
    return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура замещает содержимое указанного буфера на "мусор". 

void ReplaceData(PBYTE buffer, DWORD length) {
    for(DWORD i = 0; i < length; i++) buffer[i] = rand() % 0xFF;    // Генерируем мусор
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура замещает содержимое указанного буфера на "мусор". 
void ReplaceCode(PBYTE buffer, DWORD length) {
    DWORD i;
    
    if(length > 2 && length < 128) {
        // Если длина маркера допускает использование инструкции короткого перехода, то формируем 
        // jmp short вокруг всего маркера, а внутренности маркера забиваем мусором.
        buffer[0] = 0xEB;                                       // Опкод jmp short ххх
        buffer[1] = (BYTE)length - 2;                           // Вычисляем операнд инструкции
        for(i = 2; i < length; i++) buffer[i] = rand() % 0xFF;  // Генерируем мусор
    } else {
        // Если маркер очень короткий или слишком длинный для использования короткого перехода, забиваем его NOP'ами, 
        for(i = 0; i < length; i++) buffer[i] = 0x90;   
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Вывод сообщения в черной рамке (для заметности) в окно вывода.
void ConsolErrMsg(PCHAR format, ...) {
    char buffer[128];
    va_list arg_ptr;
    DWORD i, gap, len = 92;

    va_start(arg_ptr, format);
    vsprintf_s(buffer, sizeof(buffer), format, arg_ptr);
    va_end(arg_ptr);

    gap = (len - 2 - strlen(buffer)) / 2;

    printf("\n \n");
    for(i = 0; i < len; i++) printf("\xdb");
    printf("\n");
    for(i = 0; i < gap; i++) printf("\xdb");
    printf(" %s ", buffer);
    if((len - strlen(buffer)) % 2) printf(" ");
    for(i = 0; i < gap; i++) printf("\xdb");
    printf("\n");
    for(i = 0; i < len; i++) printf("\xdb");
    printf("\n \n");
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Вызов MessageBox с форматным выводом строки.
DWORD MsgBox(PCHAR title, UINT style, PCHAR format, ...) {
    char buffer[1024];
    va_list arg_ptr;

    va_start(arg_ptr, format);
    vsprintf_s(buffer, sizeof(buffer), format, arg_ptr);
    va_end(arg_ptr);
    return MessageBox(NULL, buffer, title, style);
}