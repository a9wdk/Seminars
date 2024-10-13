//*****************************************************************************
// (v09) Защита кода методом каскадного динамического шифрования.
//
// После сборки исполняемый файл примера нужно обработать вспомогательными утилитами:
// ..\Post-Build Utilites\DataEncrypt
// ..\Post-Build Utilites\CodeEncrypt
//
// Автор - Сергей Усков (a9wdk@yandex.ru, Telegram: @a9wdk)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "hasp_api.h"
#include "macros.h"         // Сигнатуры и структуры данных, используемые для передачи информации во внешнюю утилиту.
#include "enc_str.h"        // Данные, подлежащие зашифрованию при помощи внешней утилиты.

#define MAX_LOADSTRING 100

#define xGap 50             // Расстояние между соседними символами при выводе текста.
#define yGap 20             // Расстояние между соседними строками при выводе текста.

#define CheckKeyTimeout     500                     // Интервал фонового опроса ключа (в миллисекундах).
#define CheckThreadTimeout  CheckKeyTimeout*2       // Интервал проверки состояния потока фонового опроса ключа
#define MinReactionTimeout  10                      // Минимальная задержка (в сек.) до реакции на отсутствие потока.
#define MaxReactionTimeout  20                      // Максимальная задержка (в сек.) до реакции на отсутствие потока.

//////////////////////////////////////////////////////////////////////////////////////////////
// Глобальные переменные.
HINSTANCE hInst;                            
HMENU hMainMenu;
TCHAR szTitle[MAX_LOADSTRING]; 
TCHAR szWindowClass[MAX_LOADSTRING];
TCHAR szText;   

HANDLE hF1Thread, hF2Thread, hKeyBackgroundChk;     // Идентификаторы запущенных потоков
BOOL f1Terminate = TRUE, f2Terminate = TRUE;        // Признаки завершения потоков
BOOL HaspKeyPresent = FALSE;                        // Флаг устанавливается потоком, выполняющим фоновый опрос ключа

HaspSession Main = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, HASP_DEFAULT_FID};

int TimerID, ProtectTimeout = MaxReactionTimeout;

//////////////////////////////////////////////////////////////////////////////////////////////

ATOM                RegisterWindowClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
void                Function1(PVOID hwnd);
void                Function2(PVOID hwnd);
void                KeyBackgroundChk(PVOID hwnd);
void                KeyBackgroundChkMsg(PVOID err);
void    CALLBACK    KBChkProtect(HWND, UINT, UINT, DWORD);
PBYTE               Enc(PBYTE buffer, DWORD length);
PBYTE               Dec(PBYTE buffer, DWORD length);
void    __stdcall   UserEnc(PCstEncCodeDsc data, DWORD exitaddr);
void    __stdcall   UserDec(PCstEncCodeDsc data, DWORD exitaddr);
void    __stdcall   KeyEnc(PKeyEncCodeDsc data);
void    __stdcall   KeyDec(PKeyEncCodeDsc data);
void                HaspReLogin(PHaspSession session);
DWORD               MsgBox(PCHAR title, UINT style, PCHAR format, ...);

//////////////////////////////////////////////////////////////////////////////////////////////

CstEncCodeDsc WM_CstEnc = {(PBYTE)0x78563412};      // Encrypt-дескриптор участка кода между метками l1 и l2.

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    MSG msg;
    HWND hWnd;
    HACCEL hAccelTable;
    UCHAR vc[sizeof(vendor_code)];
    DWORD exitaddr;

    // Сохраняем идентификатор приложения в глобальной переменной.
    hInst = hInstance;
    
    // Копируем зашифрованный вендор-код данные в локальную переменную.
    CopyMemory(vc, vendor_code, sizeof(vc));

    UserDec(&WM_CstEnc, NULL);
    l1:         // Начало региона.

    // Выполняем Login на Feature ID 0, проверка результата будет выполнена в InitInstance(). Перед вызовом Login
    // производится расшифрование Vendor-кода, сразу после вызова - обратное зашифрование.
    Main.status = hasp_login(Main.feature, Dec(vc, sizeof(vc)), &Main.handle);
    Enc(vc, sizeof(vc));

    // Загрузка строк и акселераторов из ресурсов
    LoadString(hInst, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadString(hInst, IDC_CppSample, szWindowClass, MAX_LOADSTRING);
    hAccelTable = LoadAccelerators(hInst, (LPCTSTR)IDC_CppSample);

    // Проверяем, не было ли это приложение запущено ранее. 
    // Если было, выдвигаем окно приложения на передний план.
    hWnd = FindWindow(szWindowClass, NULL);
    if(hWnd) {
        if(IsIconic(hWnd)) ShowWindow(hWnd, SW_RESTORE);
        SetForegroundWindow(hWnd);
        __asm mov exitaddr, offset l3;      // Адрес, куда UserEnc передаст управление после своего завершения.
        UserEnc(&WM_CstEnc, exitaddr);
    }
    
    // Регистрируем класс окна, создаем главное окно приложения и отображаем его.
    RegisterWindowClass(hInst);
    if (!InitInstance (hInst, nCmdShow)) {
        __asm mov exitaddr, offset l4;      // Адрес, куда UserEnc передаст управление после своего завершения.
        UserEnc(&WM_CstEnc, exitaddr);
    }

    // Запускаем поток, выполняющий фоновый опрос ключа и понижаем ему приоритет.
    hKeyBackgroundChk = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChk, 0, 0, NULL);
    SetThreadPriority(hKeyBackgroundChk, THREAD_PRIORITY_LOWEST);

    UserEnc(&WM_CstEnc, NULL);
    l2:         // Конец региона.

    // Запускаем цикл обработки сообщений.
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    Main.status = hasp_logout(Main.handle);
    return 0;

    l3:     // Выход - приложение уже запущено.
    MsgBox("WinMain", MB_SYSTEMMODAL | MB_ICONINFORMATION, "The application already started!");
    return -1;
    
    l4:
    return -2;

    AsmCstEncCodeMrk(WM_CstEnc, l1, l2);        // Encrypt-маркер участка кода между метками l1 и l2.
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура выполняет регистрацию класса окна.
ATOM RegisterWindowClass(HINSTANCE hInstance) {
    WNDCLASSEX wcex;

    wcex.cbSize         = sizeof(WNDCLASSEX); 
    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = (WNDPROC)WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, (LPCTSTR)IDI_CppSample);
    wcex.hCursor        = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName   = (LPCSTR)IDC_CppSample;
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, (LPCTSTR)IDI_CppSample);
    
    // Выдача сообщения об отсутствии ключа.
    if(Main.status != HASP_STATUS_OK) MsgBox("Feature ID = 0", MB_SYSTEMMODAL | MB_ICONERROR, "Login error #%d", Main.status);
    
    return RegisterClassEx(&wcex);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура выполняет создание и отображение главного окна приложения.
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    HWND hWnd;
    
    hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, 930, 606, NULL, NULL, hInstance, NULL);

    // Завершение приложения, если нет ключа. Ну, или, если какие-либо проблемы при вызове CreateWindow(...)
   if(!hWnd || Main.status) return FALSE;
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);
    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура выполняет обработку сообщений диалога About
LRESULT CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UINT major_ver, minor_ver, build_srv, build_num;
    TCHAR api_ver[64];

    switch (message) {
    case WM_INITDIALOG:
        hasp_get_version(&major_ver, &minor_ver, &build_srv, &build_num, NULL);
        sprintf_s(api_ver, sizeof(api_ver), "LDK API v%u.%u.%u.%u", major_ver, minor_ver, build_srv, build_num);
        SetWindowText(GetDlgItem(hDlg, IDC_STATIC_API), api_ver);
        return TRUE;
        
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return TRUE;
        }
        break;
    }
    return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура выполняет обработку сообщений главного окна приложения
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    int wmId, wmEvent;

    hMainMenu = GetMenu(hWnd);
    switch (message) {
        case WM_COMMAND:
            wmId    = LOWORD(wParam); 
            wmEvent = HIWORD(wParam); 
            
            // Реакция на выбор пунктов меню. 
            switch (wmId) {
                    
                case IDM_F1Start:
                    // Запускаем поток. Если нет ошибки, разблокируем пункт меню "Stop" и заблокируем "Start".
                    hF1Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Function1, (LPVOID)hWnd, 0, NULL);
                    if(hF1Thread != NULL) {
                        f1Terminate = FALSE;
                        EnableMenuItem(hMainMenu, IDM_F1Start, MF_GRAYED);
                        EnableMenuItem(hMainMenu, IDM_F1Stop, MF_ENABLED);
                    }
                    break;
                    
                case IDM_F1Stop:
                    // Завершаем поток. 
                    f1Terminate = TRUE;
                    break;
                    
                case IDM_F2Start:
                    // Запускаем поток. Если нет ошибки, разблокируем пункт меню "Stop" и заблокируем "Start".
                    hF2Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Function2, (LPVOID)hWnd, 0, NULL);
                    if(hF2Thread != NULL) {
                        f2Terminate = FALSE;
                        EnableMenuItem(hMainMenu, IDM_F2Start, MF_GRAYED);
                        EnableMenuItem(hMainMenu, IDM_F2Stop, MF_ENABLED);
                    }
                    break;
                    
                case IDM_F2Stop:
                    // Завершаем поток.
                    f2Terminate = TRUE;
                    break;
                
                case IDM_ABOUT:
                    DialogBox(hInst, (LPCTSTR)IDD_ABOUTBOX, hWnd, (DLGPROC)About);
                    break;

                case IDM_EXIT:
                    DestroyWindow(hWnd);
                    break;

                default:
                    return DefWindowProc(hWnd, message, wParam, lParam);
            }
            break;
            
        case WM_CREATE:
            srand(GetTickCount());
            // Создаем виртуальный таймер, периодически передающий управление в функцию KBChkProtect
            TimerID = SetTimer(hWnd, 0,  CheckThreadTimeout, (TIMERPROC)KBChkProtect);
            break;

        case WM_DESTROY:
            KillTimer(hWnd, TimerID);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура генерирует псевдо-случайные числа в диапазоне [0;128] с контролем ошибок.
//  Все входящие в диапазон значения выводятся зеленым цветом, все прочие - красным.
//  Так же, в процедуре реализована реакция на "редкое событие" - три одинаковых 
//  числа подряд, последнее из них выводится синим цветом.

#define F1_Feature 1                                // Номер фичи ключа, которую будет использовать функция.

HaspSession Fn1 = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F1_Feature};

// Это очень простая, прямолинейная, и, поэтому, страдающая определенными недостатками, реализация
// динамического шифрования кода. Все нормально работает только при штатном выполнении приложения.
// Не обрабатываются случаи разрушения сессии с ключом и случаи передачи управления изнутри/внутрь
// зашифрованного региона. Поэтому, использовать только для участков кода, имеющих один вход и выход.

KeyEncCodeDsc  Fn1_KeyEnc1 = {(PHaspSession)0x78563412};    // Encrypt-дескриптор участка кода между метками l1 и l2.
KeyEncCodeDsc  Fn1_KeyEnc2 = {(PHaspSession)0x78563412};    // Encrypt-дескриптор участка кода между метками l2 и l3.

void Function1(PVOID hwnd) {
    HDC     hDC;
    RECT    rect;
    INT     delay, x, y;
    UINT    z_min = 0x0000, z_max = 0x0080, z_xor = 0xFF00, z_and = 0x00FF;
    UINT    z0 = 0, z1 = 0, z2 = 0;
    TCHAR   szTxt[8];
    UCHAR vc[sizeof(vendor_code)];
    
    hasp_decrypt(Fn1_KeyEnc1.KeySessionAddr->handle, Fn1_KeyEnc1.Addr, Fn1_KeyEnc1.Length);
    l1:     // Начало 1-го региона.

    // Копируем зашифрованный вендор-код в локальную переменную.
    CopyMemory(vc, vendor_code, sizeof(vc));
    
    // Выполняем Login на Feature 1, если ошибка - выводим сообщение и завершаем работу функции. Перед 
    // вызовом Login производится расшифрование Vendor-кода, сразу после вызова - обратное зашифрование.
    Fn1.status = hasp_login(Fn1.feature, Dec(vc, sizeof(vc)), &Fn1.handle);
    Enc(vc, sizeof(vc));
    if(Fn1.status != HASP_STATUS_OK) {
        MsgBox("Feature ID = 1", MB_SYSTEMMODAL | MB_ICONERROR, "Login error #%d", Fn1.status);
        EnableMenuItem(hMainMenu, IDM_F1Start, MF_ENABLED);
        EnableMenuItem(hMainMenu, IDM_F1Stop, MF_GRAYED);
        ExitThread(1);
    }

    hasp_decrypt(Fn1_KeyEnc2.KeySessionAddr->handle, Fn1_KeyEnc2.Addr, Fn1_KeyEnc2.Length);
    l2: // Конец 1-го и начало 2-го региона.
    hasp_encrypt(Fn1_KeyEnc1.KeySessionAddr->handle, Fn1_KeyEnc1.Addr, Fn1_KeyEnc1.Length);

    while(!f1Terminate) {
        hDC = GetDC((HWND)hwnd);
        GetWindowRect((HWND)hwnd, &rect);
        delay = 50;
        
        // Если нет ключа - никакой полезной работы не делаем. HaspKeyPresent преобразовываем, чтобы
        // не учитывать "шум", вносимый в переменную при работе защиты потока фоновой проверки ключа.
        if(!(BYTE)HaspKeyPresent) { 
            Sleep(delay); 
            continue;
        }
        
        for (y = 5; y < (rect.bottom - rect.top - 4*yGap); y += yGap) {
            for (x = 5; x < ((rect.right - rect.left)/2 - xGap); x += xGap) {
                z0 = ((rand() % (z_max - z_min) + z_min) ^ (z_xor & z_and)) & 0x0000FFFF;

                // Если произошло "редкое событие" - три одинаковых числа подряд - выводим 
                // последнее из них синим цветом и делаем большую задержку. Значения меньше чем 
                // 128 выводим зеленым цветом (это штатный режим), все прочее будет считаться 
                // ошибкой и выводиться красным цветом.
                
                if(z1 == z0 && z2 == z0) {
                    SetTextColor(hDC, RGB(0, 0, 192));
                    delay = 1500;
                } else z0 < 128 ? SetTextColor(hDC, RGB(0, 192, 0)) : SetTextColor(hDC, RGB(192, 0, 0));
                sprintf_s(szTxt, sizeof(szTxt), "%.4Xh ", z0);
                TextOut(hDC, x, y, szTxt, strlen(szTxt));
                z2 = z1;
                z1 = z0;
            }
        }
        ReleaseDC((HWND)hwnd, hDC);
        Sleep(delay);
    }
    // Разблокируем пункт меню "Start" и заблокируем "Stop".
    EnableMenuItem(hMainMenu, IDM_F1Start, MF_ENABLED);
    EnableMenuItem(hMainMenu, IDM_F1Stop, MF_GRAYED);

    DWORD res = hasp_encrypt(Fn1_KeyEnc2.KeySessionAddr->handle, Fn1_KeyEnc2.Addr, Fn1_KeyEnc2.Length);
    l3:     // Конец 2-го региона.

    Fn1.status = hasp_logout(Fn1.handle);
    ExitThread(0);

    AsmKeyEncCodeMrk(Fn1_KeyEnc1, l1, l2, Main);        // Encrypt-маркер участка кода между метками l1 и l2.
    AsmKeyEncCodeMrk(Fn1_KeyEnc2, l2, l3, Fn1);         // Encrypt-маркер участка кода между метками l2 и l3.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура генерирует псевдо-случайные числа в диапазоне [128; 255] с контролем ошибок.
//  Все входящие в диапазон значения выводятся зеленым цветом, все прочие - красным. Так же, 
//  в процедуре реализована реакция на "редкое событие" - монотонно возрастающая последовательность
//  из трёх чисел подряд, отличающиеся друг от друга на единицу, последнее из них выводится синим цветом.

#define F2_Feature 2                                // Номер фичи ключа, которую будет использовать функция.

HaspSession Fn2 = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F2_Feature};

// Это более корректная реализация динамического шифрования кода. Практически все нештатные ситуации
// обрабатываются адекватно.

KeyEncCodeDsc  Fn2_KeyEnc1 = {(PHaspSession)0x78563412};    // Encrypt-дескриптор участка кода между метками l1 и l2.
KeyEncCodeDsc  Fn2_KeyEnc2 = {(PHaspSession)0x78563412};    // Encrypt-дескриптор участка кода между метками l2 и l3.

void Function2(PVOID hwnd) {
    HDC     hDC;
    RECT    rect;
    INT     delay, x, y;
    UINT    z_min = 0x0080, z_max = 0x00FF, z_xor = 0xFF00, z_and = 0x00FF;
    UINT    z0 = 0, z1 = 0, z2 = 0;
    TCHAR   szTxt[8];
    UCHAR vc[sizeof(vendor_code)];
    
    KeyDec(&Fn2_KeyEnc1);
    l1:     // Начало 1-го региона.
    
    // Копируем зашифрованный вендор-код в локальную переменную.
    CopyMemory(vc, vendor_code, sizeof(vc));
    
    // Выполняем Login на Feature 2, если ошибка - выводим сообщение и завершаем работу функции. Перед 
    // вызовом Login производится расшифрование Vendor-кода, сразу после вызова - обратное зашифрование.
    Fn2.status = hasp_login(Fn2.feature, Dec(vc, sizeof(vc)), &Fn2.handle);
    Enc(vc, sizeof(vc));
    if(Fn2.status != HASP_STATUS_OK) {
        MsgBox("Feature ID = 2", MB_SYSTEMMODAL | MB_ICONERROR, "Login error #%d", Fn2.status);
        EnableMenuItem(hMainMenu, IDM_F2Start, MF_ENABLED);
        EnableMenuItem(hMainMenu, IDM_F2Stop, MF_GRAYED);
        goto l4;
    }
    
    KeyDec(&Fn2_KeyEnc2);
    l2: // Конец 1-го и начало 2-го региона.
    KeyEnc(&Fn2_KeyEnc1);

    while(!f2Terminate) {
        hDC = GetDC((HWND)hwnd);
        GetWindowRect((HWND)hwnd, &rect);
        delay = 50;

        // Если нет ключа - никакой полезной работы не делаем. HaspKeyPresent преобразовываем, чтобы
        // не учитывать "шум", вносимый в переменную при работе защиты потока фоновой проверки ключа.
        if(!(BYTE)HaspKeyPresent) { 
            Sleep(delay); 
            continue;
        }
        
        for (y = 5; y < (rect.bottom - rect.top - 4*yGap); y += yGap) {
            for (x = (rect.right - rect.left)/2; x < rect.right - rect.left - xGap; x += xGap) {
                z0 = ((rand() % (z_max - z_min) + z_min) ^ (z_xor & z_and)) & 0x0000FFFF;

                // Если произошло "редкое событие" - монотонно возрастающая последовательность из трёх чисел 
                // подряд, отличающиеся друг от друга на единицу - выводим последнее из них синим цветом и 
                // делаем большую задержку. Значения из диапазона [128; 255] выводим зеленым цветом, все 
                // прочее будет считаться ошибкой и выводиться красным цветом.
                
                if(z1 == z0-1 && z2 == z1-1) {
                    SetTextColor(hDC, RGB(0, 0, 192));
                    delay = 1500;
                } else (z0 > 127 && z0 < 256) ? SetTextColor(hDC, RGB(0, 192, 0)) : SetTextColor(hDC, RGB(192, 0, 0));
                sprintf_s(szTxt, sizeof(szTxt), "%.4Xh ", z0);
                TextOut(hDC, x, y, szTxt, strlen(szTxt));
                z2 = z1;
                z1 = z0;
            }
        }
        ReleaseDC((HWND)hwnd, hDC);
        Sleep(delay);
    }
    // Разблокируем пункт меню "Start" и заблокируем "Stop".
    EnableMenuItem(hMainMenu, IDM_F2Start, MF_ENABLED);
    EnableMenuItem(hMainMenu, IDM_F2Stop, MF_GRAYED);

    KeyEnc(&Fn2_KeyEnc2);
    l3:     // Конец 2-го региона.

    Fn2.status = hasp_logout(Fn2.handle);
    ExitThread(0);

    l4:     // Выход при отсутствии лицензии на работу функции.
    KeyEnc(&Fn2_KeyEnc1);
    ExitThread(1);

    AsmKeyEncCodeMrk(Fn2_KeyEnc1, l1, l2, Main);    // Encrypt-маркер участка кода между метками l1 и l2.
    AsmKeyEncCodeMrk(Fn2_KeyEnc2, l2, l3, Fn2);     // Encrypt-маркер участка кода между метками l2 и l3.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура выполняет фоновый опрос ключа с указанным интервалом. Строковые параметры,
//  позволяющие обнаружить процедуру через перекрестные ссылки (scope, format и vendorcode),
//  зашифрованы и расшифровываются непосредственно перед вызовом hasp_get_info(), после чего
//  снова зашифровываются.

CstEncCodeDsc KBChk_CstEnc = {(PBYTE)0x78563412};       // Encrypt-дескриптор участка кода между метками l1 и l2.

void KeyBackgroundChk(PVOID hwnd) {
    HANDLE hMsg = INVALID_HANDLE_VALUE;
    DWORD hMsgState = NULL;
    PCHAR info = 0;
    hasp_status_t status;
    UCHAR vc[sizeof(vendor_code)];
    
    // Копируем зашифрованный вендор-код в локальную переменную.
    CopyMemory(vc, vendor_code, sizeof(vc));

    while(TRUE) {
        UserDec(&KBChk_CstEnc, NULL);   
        l1:         // Начало региона.

        GetExitCodeThread(hMsg, &hMsgState);

        // Проверяем наличие ключа. Перед вызовом hasp_get_info производится расшифрование параметров 
        // scope, format и Vendor-код. Сразу после вызова выполняется их обратное зашифрование.
        status = hasp_get_info((CCHAR *)Dec(scope, sizeof(scope)), (CCHAR *)Dec(format, sizeof(format)), Dec(vc, sizeof(vc)), &info);
        Enc(scope, sizeof(scope)); Enc(format, sizeof(format)); Enc(vc, sizeof(vc));
        
        if(status != HASP_STATUS_OK) {  
            // Ключ не обнаружен.
            HaspKeyPresent = FALSE;
            if(hMsgState == 0) hMsg = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChkMsg, (LPVOID)status, 0, NULL);
        } else {                            
            // Ключ обнаружен.
            HaspKeyPresent = TRUE;
            if(hMsgState == STILL_ACTIVE) TerminateThread(hMsg, 0);
            hasp_free(info);
        }

        UserEnc(&KBChk_CstEnc, NULL);   
        l2:         // Конец региона.

        Sleep(CheckKeyTimeout);
    }
    ExitThread(0);

    AsmCstEncCodeMrk(KBChk_CstEnc, l1, l2);     // Encrypt-маркер участка кода между метками l1 и l2.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура выводит сообщение, немодальное относительно потока фоновой проверки ключа.
void KeyBackgroundChkMsg(PVOID err) {
    MsgBox("Background Check", MB_SYSTEMMODAL | MB_ICONERROR, "Background check error #%d", err);
    ExitThread(0);
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура защищает поток фоновой проверки ключа.

BOOL Noise = FALSE;

void CALLBACK KBChkProtect(HWND hwnd, UINT msg, UINT idTimer, DWORD dwTime) {

    if(Noise != HaspKeyPresent) {       // Поток KeyBacgroundChk работает штатно. Рандомизируем таймаут реакции.
        ProtectTimeout = rand() % (MaxReactionTimeout - MinReactionTimeout) + MinReactionTimeout;
    } else {                            // Поток KeyBacgroundChk не работает.
        if(ProtectTimeout) {            // Если таймаут не истек - уменьшаем его на единицу.
            ProtectTimeout -= 1;    
        } else {                        // Таймаут истек - наступает реакция.
            // Вариант №1. Аварийное завершение приложения с разрушением стека.
            __asm ret 0x7FFF;
            // Вариант №2. Перезапуск потока KeyBacgroundChk.
//          hKeyBackgroundChk = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChk, 0, 0, NULL);
//          SetThreadPriority(hKeyBackgroundChk, THREAD_PRIORITY_LOWEST);
        }  
    }
    // Вносим "шум" в HaspKeyPresent и сохраняем ее новое значение в Noise для сравнения на следующем входе 
    // в процедуру. Если поток KeyBacgroundChk "жив", он перезапишет HaspKeyPresent "правильным" значением.
    Noise = HaspKeyPresent |= 0x00010000;
    return;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедуры, выполняющие динамическое расшифрование/зашифрование данных.

#define XOR 0x53

PBYTE Enc(PBYTE buffer, DWORD length) {

    buffer[0] ^= XOR;
    for(DWORD i = 1; i < length; i++) buffer[i] ^= buffer[i-1];
    return buffer;
}

PBYTE Dec(PBYTE buffer, DWORD length) {

    for(DWORD i = length-1; i > 0 ; i--) buffer[i] ^= buffer[i-1];
    buffer[0] ^= XOR;
    return buffer;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедуры, выполняющие динамическое расшифрование/зашифрование кода сторонним алгоритмом.
// В связи с возможным использованием функций внутри зашифрованных участков кода (на границе
// участка), применено соглашение о вызовах __stdcall.

void __stdcall UserEnc(PCstEncCodeDsc data, DWORD exitaddr) {
    // Если exitaddr не равен NULL, меняем в стеке адрес, куда вернуть управление, на указанный в exitaddr.
    if(exitaddr != NULL) {
        __asm mov EAX, exitaddr;
        __asm mov dword ptr[EBP+4], EAX;
    }
    Enc(data->Addr, data->Length);  
}

void __stdcall UserDec(PCstEncCodeDsc data, DWORD exitaddr) {
    // Если exitaddr не равен NULL, меняем в стеке адрес, куда вернуть управление, на указанный в exitaddr.
    if(exitaddr != NULL) {
        __asm mov EAX, exitaddr;
        __asm mov dword ptr[EBP+4], EAX;
    }
    Dec(data->Addr, data->Length);  
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедуры, выполняющие динамическое расшифрование/зашифрование кода через ключ. Состояние
//  сессии с ключом контролируется, в случае ее разрушения из-за кратковременного отсоединения
//  ключа, производится восстановление сессии. В связи с возможным использованием функций внутри
//  зашифрованных участков кода (на границе участка), применено соглашение о вызовах __stdcall.

void __stdcall KeyEnc(PKeyEncCodeDsc data) {

    data->KeySessionAddr->status = hasp_encrypt(data->KeySessionAddr->handle, data->Addr, data->Length);
    // Проверяем, не разрушена ли сессия с ключом
    if(data->KeySessionAddr->status == HASP_BROKEN_SESSION || data->KeySessionAddr->status == HASP_INV_HND) {
        HaspReLogin(data->KeySessionAddr);
        data->KeySessionAddr->status = hasp_encrypt(data->KeySessionAddr->handle, data->Addr, data->Length);
    }
}

void __stdcall KeyDec(PKeyEncCodeDsc data){

    data->KeySessionAddr->status = hasp_decrypt(data->KeySessionAddr->handle, data->Addr, data->Length);
    // Проверяем, не разрушена ли сессия с ключом
    if(data->KeySessionAddr->status == HASP_BROKEN_SESSION || data->KeySessionAddr->status == HASP_INV_HND) {
        HaspReLogin(data->KeySessionAddr);
        data->KeySessionAddr->status = hasp_decrypt(data->KeySessionAddr->handle, data->Addr, data->Length);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура восстанавливает сессию, разрушенную из-за кратковременного отсоединения ключа.
void HaspReLogin(PHaspSession session) {
    UCHAR vc[sizeof(vendor_code)];

    // Копируем зашифрованный вендор-код данные в локальную переменную.
    CopyMemory(vc, vendor_code, sizeof(vc));
    
    // Освобождаем хендл "старой" сессии
    hasp_logout(session->handle);
    
    // Повторно открываем сессию с ключом. Если ключа нет - ждем его появления в цикле.
    while(session->status != HASP_STATUS_OK) {
        session->status = hasp_login(session->feature, Dec(vc, sizeof(vc)), (PDWORD)&session->handle);
        Enc(vc, sizeof(vc));
        Sleep(CheckKeyTimeout);
    }
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
