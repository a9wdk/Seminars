//*****************************************************************************
// Реализация алгоритмов, использующих механизмы контрольных сумм, кодов 
// Рида-Соломона и динамическое шифрование исполняемого кода, предназначенных
// для использования в приложениях и библиотеках, содержащих перемещаемые элементы.
// 
// Контрольными суммами и кодами коррекции ошибок защищены точки входа LDK API,
// зашифрованный массив с коэффициентами для функции Function1 и код Function1.
// Код функции Function2 зашифрован.
//
// Автор - Сергей Усков (Sergey.Uskov@safenet-inc.com, uskov@smtp.ru)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "hasp_api.h"
#include "RSLib.h"		// Кодек Рида-Соломона.
#include "macros.h"		// Сигнатуры и структуры данных, используемые для передачи информации во внешнюю утилиту.
#include "enc_str.h"	// Данные, подлежащие зашифрованию при помощи внешней утилиты.

#define MAX_LOADSTRING 100

#define xGap 50				// Расстояние между соседними символами при выводе текста.
#define yGap 20				// Расстояние между соседними строками при выводе текста.

#define CheckKeyTimeout		500						// Интервал фонового опроса ключа (в миллисекундах).
#define CheckThreadTimeout	CheckKeyTimeout*2		// Интервал проверки состояния потока фонового опроса ключа
#define MinReactionTimeout	10						// Минимальная задержка (в сек.) до реакции на отсутствие потока.
#define MaxReactionTimeout	20						// Максимальная задержка (в сек.) до реакции на отсутствие потока.

#define F1Trigger			1						// Пороговое значение для Function1, включающее третий эшелон защиты.

//////////////////////////////////////////////////////////////////////////////////////////////
// Структура содержит коэффициенты, необходимые для работы функций F1 и F2 
//
struct Factors {		
	DWORD   Min;			// Минимальное значение
	DWORD   Max;			// Максимальное значение
	DWORD   Xor;			// Вспомогательный коэффициент
	DWORD   And;			// Вспомогательный коэффициент
};

//////////////////////////////////////////////////////////////////////////////////////////////
// Обработчик исключительных ситуаций.

LONG WINAPI VEH_Handler(PEXCEPTION_POINTERS ExceptionInfo);

// Противодействие отладке с использованием аппаратных точек останова (HW BreakPoint)
DWORD HardwareBPFlag(struct _CONTEXT *ContextRecord);

//////////////////////////////////////////////////////////////////////////////////////////////
// Глобальные переменные.
HINSTANCE hInst;							
HMENU hMainMenu;
TCHAR szTitle[MAX_LOADSTRING]; 
TCHAR szWindowClass[MAX_LOADSTRING];
TCHAR szText;

HANDLE hF1Thread, hF2Thread, hKeyBackgroundChk;		// Идентификаторы запущенных потоков
BOOL f1Terminate = TRUE, f2Terminate = TRUE;		// Признаки завершения потоков
BOOL HaspKeyPresent = FALSE;						// Флаг устанавливается потоком, выполняющим фоновый опрос ключа

DWORD	CurrentImageBase;
PIMAGE_NT_HEADERS32 PEHeader;

int	TimerID, ProtectTimeout = MaxReactionTimeout;

DWORD F1ErrCount = 0;

// Перед началом исполнения кода примера "скрытно" устанавливаем векторный обработчик исключительных ситуаций.
// Это будет выполнено как инициализация переменной hVEH_Handler, на этапе выполнения startup-кода примера.

PVOID  hVEH_Handler = AddVectoredExceptionHandler(0, VEH_Handler);	// Идентификатор VEH-обработчика

// Адресные поля дескрипторов инициализируем не просто каким-либо числом, а реальным адресом, чтобы
// компоновщик занес эти поля в список перемещаемых элементов.
CrcDscList CrcListEntry = {CrcDscListSig, (PCrcDsc)&AddrStub};		// Точка входа в список CRC-дескрипторов
EccDscList EccListEntry = {EccDscListSig, (PEccDsc)&AddrStub};		// Точка входа в список ECC-дескрипторов

OrgPE OrgPEValue = {OrgPESig};						// Контейнер для хранения исходного значения ImageBase

//////////////////////////////////////////////////////////////////////////////////////////////

ATOM				RegisterWindowClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
void				Function1(PVOID hwnd);
void				Function2(PVOID hwnd);
void				KeyBackgroundChk(PVOID hwnd);
void				KeyBackgroundChkMsg(PVOID err);
void	CALLBACK	KBChkProtect(HWND, UINT, UINT, DWORD);
PBYTE 				Enc(PBYTE buffer, DWORD length);
PBYTE				Dec(PBYTE buffer, DWORD length);

void __stdcall		KeyEncWithFixUp(PKeyEncCodeDsc data);						// Fixup-конверт для KeyEnc 
void				KeyEnc(PKeyEncCodeDsc data);
void __stdcall		KeyDecWithFixUp(PKeyEncCodeDsc data);						// Fixup-конверт для KeyDec
void				KeyDec(PKeyEncCodeDsc data);
void				HaspReLogin(PHaspSession session);

BOOL				CRCDataScan(PCrcDsc	EntryPoint);							// Проверка всей цепочки CRC-дескрипторов
BOOL				CheckCRC32WithFixUp(PCrcDsc descriptor);					// Fixup-конверт для CheckCRC32
BOOL				CheckCRC32(PCrcDsc descriptor);

void				RSCDataScan(PVOID EntryPoint);								// Проверка всей цепочки ECC-дескрипторов
DWORD				RSCDataFixingWithFixUp(PEccDsc descriptor);					// Fixup-конверт для RSCDataFixing
DWORD				RSCDataFixing(PEccDsc descriptor);

DWORD				SearchingRelocs(PDWORD Reloc, PBYTE Addr, DWORD Length);	// Поиск перемещаемых элементов в регионе

DWORD				MsgBox(PCHAR title, UINT style, PCHAR format, ...);


//////////////////////////////////////////////////////////////////////////////////////////////

HaspSession Main = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, HASP_DEFAULT_FID};

#define API_DEPTH		128		// На какую глубину сканировать код HASP API от точки входа
#define API_ECC_LEN		256		// Длина ECC для восстановления разрушенного кода

// Дескрипторы подлежащих контролю точек входа в LDK API. Адресные поля дескрипторов инициализируем не просто
// каким-либо числом, а реальным адресом, чтобы компоновщик занес эти поля в список перемещаемых элементов.
CrcDsc	login_CRC   = {&AddrStub, &AddrStub};		// CRC-дескриптор функции hasp_login
EccDsc	login_ECC   = {&AddrStub, &AddrStub};		// ECC-дескриптор функции hasp_login
CrcDsc	getinfo_CRC = {&AddrStub, &AddrStub};		// CRC-дескриптор функции hasp_getinfo
EccDsc	getinfo_ECC = {&AddrStub, &AddrStub};		// ECC-дескриптор функции hasp_getinfo

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	MSG msg;
	HWND hWnd;
	HACCEL hAccelTable;
	UCHAR vc[sizeof(vendor_code)];

	// Сохраняем идентификатор приложения, текущее значение ImageBase и адрес заголовка PE-файла.
	hInst = hInstance;
	CurrentImageBase = (DWORD)hInstance;
	PEHeader = (PIMAGE_NT_HEADERS32)(CurrentImageBase + ((PIMAGE_DOS_HEADER)CurrentImageBase)->e_lfanew);


	// Копируем зашифрованный вендор-код данные в локальную переменную.
	CopyMemory(vc, vendor_code, sizeof(vc));

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
		return -1;
	}
	
	// Регистрируем класс окна, создаем главное окно приложения и отображаем его.
	RegisterWindowClass(hInst);
	if (!InitInstance (hInst, nCmdShow)) return -2;

	// Запускаем поток, выполняющий фоновый опрос ключа и понижаем ему приоритет.
	hKeyBackgroundChk = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChk, 0, 0, NULL);
	SetThreadPriority(hKeyBackgroundChk, THREAD_PRIORITY_LOWEST);

	// Запускаем цикл обработки сообщений.
	while (GetMessage(&msg, NULL, 0, 0)) {
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	Main.status = hasp_logout(Main.handle);
	return 0;

	// CRC/ECC-маркеры для функций hasp_login и hasp_get_info
	AsmCrcLibsMrk(login_CRC, hasp_login, API_DEPTH, 0);
	AsmEccLibsMrk(login_ECC, hasp_login, API_DEPTH, API_ECC_LEN, 0);
	AsmCrcLibsMrk(getinfo_CRC, hasp_get_info, API_DEPTH, 1);
	AsmEccLibsMrk(getinfo_ECC, hasp_get_info, API_DEPTH, API_ECC_LEN, 1);
}


//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура выполняет регистрацию класса окна.
ATOM RegisterWindowClass(HINSTANCE hInstance) {
	WNDCLASSEX wcex;

	wcex.cbSize			= sizeof(WNDCLASSEX); 
	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= (WNDPROC)WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, (LPCTSTR)IDI_CppSample);
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName	= (LPCSTR)IDC_CppSample;
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, (LPCTSTR)IDI_CppSample);
	
	// Выдача сообщения об отсутствии ключа.
	if(Main.status != HASP_STATUS_OK) MsgBox("Feature ID = 0", MB_SYSTEMMODAL | MB_ICONERROR, "Login error #%d", Main.status);
	
	return RegisterClassEx(&wcex);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура выполняет создание и отображение главного окна приложения.
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
	HWND hWnd;
	CHAR new_header[356], header[256];
	
	hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, 930, 606, NULL, NULL, hInstance, NULL);

	// Завершение приложения, если нет ключа. Ну, или, если какие-либо проблемы при вызове CreateWindow(...)
   if(!hWnd || Main.status) return FALSE;
	ShowWindow(hWnd, nCmdShow);

	// Вывод в заголовок окна текущего значения ImageBase
	GetWindowText(hWnd, header, sizeof(header));
	sprintf_s(new_header, sizeof(new_header), "%s [ current ImageBase = %08Xh ]", header, CurrentImageBase);
	SetWindowText(hWnd, new_header);

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

Factors F1 = {0x0000, 0x0080, 0xFF00, 0x00FF};	// Массив с коэффициентами, необходимыми для работы функции.

#define F1_Feature		1						// Номер фичи ключа, которую будет использовать функция.
#define F1_Ecc_Length	(sizeof(F1) * 2)		// Размер ECC для зашифрованного массива с коэффициентами.
#define Fn1_Ecc_Length	256						// Размер ECC для защищенного участка кода.

HaspSession Fn1  = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F1_Feature};

// Адресные поля дескрипторов инициализируем не просто каким-либо числом, а реальным адресом, чтобы
// компоновщик занес эти поля в список перемещаемых элементов.
CrcDsc F1_Crc  = {&AddrStub, &AddrStub};		// CRC-дескриптор массива F1.
CrcDsc Fn1_Crc = {&AddrStub, &AddrStub};		// CRC-дескриптор участка кода между метками l1 и l2.
EccDsc F1_Ecc  = {&AddrStub, &AddrStub};		// ECC-дескриптор массива F1.
EccDsc Fn1_Ecc = {&AddrStub, &AddrStub};		// ECC-дескриптор участка кода между метками l1 и l2.

KeyEncDataMrk F1_Mrk1 = {KeyEncDataSig, &F1, sizeof(F1), F1_Feature};				// Encrypt-маркер массива F1
CrcDataMrk	  F1_Mrk2 = {CrcDataSig, &F1_Crc, &F1, sizeof(F1), 2};					// CRC-маркер массива F1
EccDataMrk    F1_Mrk3 = {EccDataSig, &F1_Ecc, &F1, sizeof(F1), F1_Ecc_Length, 2};	// ECC-маркер массива F1

void Function1(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	Factors F;
	UCHAR vc[sizeof(vendor_code)];

	l1:	// Начало защищенного региона кода.

	// Копируем зашифрованные вендор-код и буфер с коэффициентами в локальные переменные.
	CopyMemory(vc, vendor_code, sizeof(vc));
	CopyMemory(&F, &F1, sizeof(F));

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

	// Расшифровываем локальную копию буфера с коэффициентами
	hasp_decrypt(Fn1.handle, &F, sizeof(F));

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
				z0 = ((rand() % (F.Max - F.Min) + F.Min) ^ (F.Xor & F.And)) & 0x0000FFFF;

				// "Редкое событие".

				if(z1 == z0 && z2 == z0) {
					// Проверка целостности регионов по всей цепочке дескрипторов.
					if(!CRCDataScan(CrcListEntry.EntryPoint)) {
						if(F1ErrCount < F1Trigger) SetTextColor(hDC, RGB(192, 0, 192));
							else SetTextColor(hDC, RGB(192, 0, 0));
						F1ErrCount++;
					} else SetTextColor(hDC, RGB(0, 0, 192));
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
	EnableMenuItem(hMainMenu, IDM_F1Start, MF_ENABLED);
	EnableMenuItem(hMainMenu, IDM_F1Stop, MF_GRAYED);
	Fn1.status = hasp_logout(Fn1.handle);
	ExitThread(0);

	l2:	// Конец защищенного региона кода.

	AsmCrcCodeMrk(Fn1_Crc, l1, l2, 3);							// CRC-маркер участка кода между метками l1 и l2.
	AsmEccCodeMrk(Fn1_Ecc, l1, l2, Fn1_Ecc_Length, 3);			// ECC-маркер участка кода между метками l1 и l2.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура генерирует псевдо-случайные числа в диапазоне [128; 255] с контролем ошибок.
//  Все входящие в диапазон значения выводятся зеленым цветом, все прочие - красным. Так же, 
//  в процедуре реализована реакция на "редкое событие" - монотонно возрастающая последовательность
//  из трёх чисел подряд, отличающиеся друг от друга на единицу, последнее из них выводится синим цветом.

#define F2_Feature 2									// Номер фичи ключа, которую будет использовать функция.

HaspSession Fn2 = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F2_Feature};

// Адресные поля дескрипторов инициализируем не просто каким-либо числом, а реальным адресом, чтобы
// компоновщик занес эти поля в список перемещаемых элементов.
KeyEncCodeDsc  Fn2_KeyEnc1 = {(PHaspSession)&AddrStub, &AddrStub};		// Encrypt-дескриптор участка кода между метками l1 и l2.
KeyEncCodeDsc  Fn2_KeyEnc2 = {(PHaspSession)&AddrStub, &AddrStub};		// Encrypt-дескриптор участка кода между метками l2 и l3.

void Function2(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z_min = 0x0080, z_max = 0x00FF, z_xor = 0xFF00, z_and = 0x00FF;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	UCHAR vc[sizeof(vendor_code)];
	
	RaiseExceptionForKeyDecrypt(Fn2_KeyEnc1, NULL);	
	l1:		// Начало 1-го региона.

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
		RaiseExceptionForKeyEncrypt(Fn2_KeyEnc1, offset l4);	// После обработки исключения передать управление на l4. 
	}
	
	RaiseExceptionForKeyDecrypt(Fn2_KeyEnc2, NULL);	
	l2:	// Конец 1-го и начало 2-го регионов.
	RaiseExceptionForKeyEncrypt(Fn2_KeyEnc1, NULL);

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

	RaiseExceptionForKeyEncrypt(Fn2_KeyEnc2, NULL);
	l3:		// Конец 2-го региона.

	Fn2.status = hasp_logout(Fn2.handle);
	ExitThread(0);

	l4:		// Выход при отсутствии лицензии на работу функции.
	ExitThread(1);

	AsmKeyEncCodeMrk(Fn2_KeyEnc1, l1, l2, Main);	// Encrypt-маркер участка кода между метками l1 и l2.
	AsmKeyEncCodeMrk(Fn2_KeyEnc2, l2, l3, Fn2);		// Encrypt-маркер участка кода между метками l2 и l3.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура выполняет фоновый опрос ключа с указанным интервалом. Строковые параметры,
//	позволяющие обнаружить процедуру через перекрестные ссылки (scope, format и vendorcode),
//  зашифрованы и расшифровываются непосредственно перед вызовом hasp_get_info(), после чего
//  снова зашифровываются.

void KeyBackgroundChk(PVOID hwnd) {
	HANDLE hMsg = INVALID_HANDLE_VALUE;
	DWORD hMsgState = NULL;
	PCHAR info = 0;
	hasp_status_t status;
	UCHAR vc[sizeof(vendor_code)];
	
	// Копируем зашифрованный вендор-код в локальную переменную.
	CopyMemory(vc, vendor_code, sizeof(vc));

	while(TRUE) {

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

		Sleep(CheckKeyTimeout);
	}
	ExitThread(0);
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
	DWORD hRSCState = 0;
	HANDLE hRSC = NULL;

	GetExitCodeThread(hRSC,&hRSCState);
	if(Noise != HaspKeyPresent) {		// Поток KeyBacgroundChk работает штатно. Рандомизируем таймаут реакции.
		ProtectTimeout = rand() % (MaxReactionTimeout - MinReactionTimeout) + MinReactionTimeout;
	} else {							// Поток KeyBacgroundChk не работает.
		if(ProtectTimeout) {			// Если таймаут не истек - уменьшаем его на единицу.
			ProtectTimeout -= 1;	
		} else {						// Таймаут истек - наступает реакция.
			// Вариант №1. Аварийное завершение приложения с разрушением стека.
			__asm ret 0x7FFF;
			// Вариант №2. Перезапуск потока KeyBacgroundChk.
//			hKeyBackgroundChk = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChk, 0, 0, NULL);
//			SetThreadPriority(hKeyBackgroundChk, THREAD_PRIORITY_LOWEST);
		}  
	}

	// Если счетчик достиг предельного значения, запускаем поток, выполняющий, при необходимости,
	// коррекцию кода/данных при помощи декодера Рида-Соломона.
	if(hRSCState == 0 && F1ErrCount > F1Trigger)
		hRSC = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RSCDataScan, (LPVOID)EccListEntry.EntryPoint, 0, NULL);

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
//  VEH-обработчик исключительной ситуации.
LONG WINAPI VEH_Handler(PEXCEPTION_POINTERS ExceptionInfo) {

	// Отладочная печать.
/*	MsgBox("VEH (all exceptions)", MB_OK, "Exception Code\t %.8X\nException Address\t %.8X\nInvalid Instruction\t %X", 
		    ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, 
			*(USHORT *)ExceptionInfo->ExceptionRecord->ExceptionAddress);
*/

	// Получаем доступ к структуре-описателю зашифрованного региона. Её адрес лежит в операнде инструкции,
	// следующей за двухбайтовой командой, вызвавшей исключительную ситуацию.
	PRaiseExcept   exception  = (PRaiseExcept)ExceptionInfo->ExceptionRecord->ExceptionAddress;
	PKeyEncCodeDsc descriptor = (PKeyEncCodeDsc)exception->DescriptorAddr;

	// Если есть активные аппаратные точки останова, делаем невозможным штатное завершение криптографических
	// операций над текущим регионом путем внесения искажений во входные данные процедур расшифрования/зашифрования,
	// а именно - "портим" значение длины текущего региона в его дескрипторе. Благодаря явно выраженному лавинному
	// эффекту AES, это приведет к неправильному криптографичекому преобразованию текущего региона.
//	descriptor->Length += HardwareBPFlag(ExceptionInfo->ContextRecord);

	switch(exception->InvalidOpCode) {
		
		// Расшифрование региона через ключ.
		case KeyDecInvalidOpCode: 
			// Коррекция точки входа.
			if(exception->SafeEIPAddr == NULL) ExceptionInfo->ContextRecord->Eip += sizeof(RaiseExcept);
				else ExceptionInfo->ContextRecord->Eip = exception->SafeEIPAddr;
			KeyDecWithFixUp(descriptor);
//			KeyDec(descriptor);
			break;

		// Зашифрование региона через ключ.
		case KeyEncInvalidOpCode: 
			// Коррекция точки входа.
			if(exception->SafeEIPAddr == NULL) ExceptionInfo->ContextRecord->Eip += sizeof(RaiseExcept); 
				else ExceptionInfo->ContextRecord->Eip = exception->SafeEIPAddr;
			KeyEncWithFixUp(descriptor);
//			KeyEnc(descriptor);
			break;

		// Не "наше" исключение, передаем управление следующему обработчику в цепочке. 
		default: 
			return EXCEPTION_CONTINUE_SEARCH;	
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Проверка наличия установленных аппаратных точек останова.
DWORD HardwareBPFlag(struct _CONTEXT *ContextRecord) {
	if(ContextRecord->Dr0 == 0 && ContextRecord->Dr1 == 0 && ContextRecord->Dr2 == 0 && ContextRecord->Dr3 == 0) return(0); 
	return(1);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Конверт для использования функции KeyEnc. В случае зашифрования нормально расшифрованного
// региона ничего специального делать не нужно. Если не установлен флаг ValidateFlag, установить его.
void __stdcall KeyEncWithFixUp(PKeyEncCodeDsc data) {
	if(data->ValidateFlag != TRUE) data->ValidateFlag = TRUE;
	KeyEnc(data);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Конверт для использования функции KeyDec в случае, если в зашифрованном регионе имеются
// перемещаемые элементы. В дескрипторе региона есть поле ValidateFlag, по умолчанию
// инициализированное значением FALSE. Это означает, что описываемый дескриптором регион
// ещё не проверялся на корректность относительно текущего значения ImageBase.
//
// Функция проверяет корректность региона, относительно текущего значения ImageBase. Если
// текущий ImageBase совпадает с предпочитаемым, то ничего делать не нужно - регион корректен.
// Если регион загружен по адресу, отличному от предпочитаемого ImageBase, то это означает, что
// системный загрузчик "испортил" регион, применив к перемещаемым элементам внутри него базовые
// поправки. Теперь регион невозможно корректно расшифровать обычным способом. Для того, чтобы
// обеспечить корректное расшифрование региона необходимо сделать следующее:
//
// 1. Определить количество перемещаемых элементов в регионе.
// 2. Расшифровать регион:
//    - Если перемещаемых элементов нет, то регион корректен, и его можно расшифровать обычным способом.
//    - Если в регионе есть перемещаемые элементы, то создается его копия, и перемещаемые элементы копии
//      возвращаются в исходное состояние, согласно предпочитаемому ImageBase. После этого копия региона
//      корректно расшифровывается обычным способом и настраивается на текущее значение ImageBase. Далее,
//      исходный регион замещается его расшифрованной и настроенной копией.
// 3. Установить флаг ValidateFlag в значение TRUE.
//
// Используемые глобальные переменные: CurrentImageBase, PEHeader (инициализируются в WinMain),
//                                     OrgPEValue (заполняется одной из вспомогательных утилит).
void __stdcall KeyDecWithFixUp(PKeyEncCodeDsc data) {
	DWORD	ImageBaseDelta, RelocsNum, i;
	PDWORD	Relocs;
	PBYTE	Buffer;
	KeyEncCodeDsc dataCopy;

	// Если регион уже проверен на корректность, расшифровываем его в обычном порядке.
	if(data->ValidateFlag == TRUE) {
		KeyDec(data);
		return;
	}

	// Вычисляем значение дельта-смещения.
	ImageBaseDelta = CurrentImageBase - OrgPEValue.ImageBase;

	// Проверяем, загружен ли образ по предпочитаемому ImageBase (в этом случае ImageBaseDelta == 0). Если да, то
	// устанавливаем ValidateFlag = TRUE и расшифровываем регион в обычном порядке - базовые поправки не требуются.
	if(ImageBaseDelta == 0) {
		KeyDec(data);
		data->ValidateFlag = TRUE;
		return;
	}

	// Образ загружен по ImageBase, отличному от предпочитаемого. 
	// Выделяем память под список адресов перемещаемых элементов.
	if((Relocs = (PDWORD)HeapAlloc(GetProcessHeap(), 0, data->Length)) == NULL) {
		MsgBox("KeyDecWithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Relocs!");	
		return;
	}

	// Заполняем список адресов перемещаемых элементов зашифрованного региона. Если список пуст, то ничего более
	// делать не нужно - регион не содержит перемещаемых элементов и его можно корректно расшифровать. Иначе -
	// делаем копию региона и настраиваем соответственно случаю загрузки по предпочитаемому ImageBase. Далее
	// расшифровываем её, настраиваем перемещаемые элементы соответственно текущему значению ImageBase и заменяем
	// исходный регион модифицированной таким образом копией.
	RelocsNum = SearchingRelocs(Relocs, data->Addr, data->Length);
	if(RelocsNum == 0) {

		// Регион не содержит перемещаемых элементов. Просто расшифровываем его.
		KeyDec(data);

	} else {

		// Выделяем память под копию зашифрованного региона.
		if((Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, data->Length)) == NULL) {
			HeapFree(GetProcessHeap(), 0, Relocs);
			MsgBox("KeyDecWithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Buffer!");	
			return;
		}

		// Копируем зашифрованный регион в буфер.
		CopyMemory(Buffer, data->Addr, data->Length);

		// Приводим копию региона в состояние, соответствующее загрузке по предпочитаемому ImageBase,
		// путём уменьшения каждого перемещаемого элемента на величину дельта-смещения. 
		for(i = 0; i < RelocsNum; i++) *(PDWORD)&Buffer[Relocs[i] - (DWORD)data->Addr] -= ImageBaseDelta;

		// Заполняем дескриптор для копии региона (необходимо для вызова KeyDec)
		dataCopy.Addr = Buffer;
		dataCopy.Length = data->Length;
		dataCopy.KeySessionAddr = data->KeySessionAddr;

		// Расшифровываем копию региона
		KeyDec(&dataCopy);

		// Приводим копию региона в состояние, соответствующее загрузке по текущему ImageBase,
		// путём увеличения каждого перемещаемого элемента на величину дельта-смещения. 
		for(i = 0; i < RelocsNum; i++) *(PDWORD)&Buffer[Relocs[i] - (DWORD)data->Addr] += ImageBaseDelta;

		// Заменяем исходный регион его расшифрованной и настроенной копией
		CopyMemory(data->Addr, Buffer, data->Length);

		HeapFree(GetProcessHeap(), 0, Buffer);

		MsgBox("Correcting FixUp and decrypting", MB_ICONINFORMATION, "Start Address\t%Xh\nData Length\t%d(%Xh)\n"
			"FixUp quantity\t%d", data->Addr, data->Length, data->Length, RelocsNum);

	}

	HeapFree(GetProcessHeap(), 0, Relocs);
	data->ValidateFlag = TRUE;
	return;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедуры, выполняющие динамическое расшифрование/зашифрование кода через ключ. Состояние
//  сессии с ключом контролируется, в случае ее разрушения из-за кратковременного отсоединения
//  ключа, производится восстановление сессии. 

void KeyEnc(PKeyEncCodeDsc data) {

	data->KeySessionAddr->status = hasp_encrypt(data->KeySessionAddr->handle, data->Addr, data->Length);
	// Проверяем, не разрушена ли сессия с ключом
	if(data->KeySessionAddr->status == HASP_BROKEN_SESSION || data->KeySessionAddr->status == HASP_INV_HND) {
		HaspReLogin(data->KeySessionAddr);
		data->KeySessionAddr->status = hasp_encrypt(data->KeySessionAddr->handle, data->Addr, data->Length);
	}
}

void KeyDec(PKeyEncCodeDsc data){

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
// Процедура выполняет обход всех участков кода/данных, защищенных контрольными суммами.
// Возвращает FALSE, если хотя бы один участок не прошел проверку.
BOOL CRCDataScan(PCrcDsc EntryPoint) {
	PCrcDsc  dscr;
	BOOL	 Res = TRUE;
	INT		 ImageBaseDelta = CurrentImageBase - OrgPEValue.ImageBase;

	// Признаком конца цепочки дескрипторов является значение NULL в поле NextDsc текущего дескриптора.
	// Однако, это поле является перемещаемым элементом, поэтому, при загрузке по базовому адресу, отличному
	// от предпочитаемого, его значение будет скорректировано на величину базовой поправки, т.е. в нем будет
	// находиться не NULL, а дельта между текущим и предпочитаемым значениями ImageBase. С учетом этого и 
	// построим условие выхода из цикла проверки цепочки дескрипторов.
	for(dscr = EntryPoint; (INT)dscr != ImageBaseDelta; dscr = (PCrcDsc)dscr->NextDsc) {
		if(!CheckCRC32WithFixUp(dscr)) Res = FALSE;
	}
	return Res;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Конверт для использования функции CheckCRC32 в случае, если в защищенном регионе имеются
// перемещаемые элементы. В дескрипторе региона используется поле ValidateFlag, по умолчанию
// инициализированное значением FALSE. Это означает, что регион, описываемый дескриптором,
// ещё не проверялся на корректность относительно текущего значения ImageBase.
//
// Функция проверяет корректность региона, описываемого дескриптором, относительно текущего значения
// ImageBase. Если текущий ImageBase совпадает с предпочитаемым, то ничего делать не нужно - регион
// корректен. Если регион загружен по отличному от предпочитаемого ImageBase, тогда его необходимо
// привести в соответствие с текущей базой. Для этого необходимо:
//
// 1. Сделать копию региона, найти в ней перемещаемые элементы и применить к ним базовые поправки
//    относительно предпочитаемого ImageBase, таким образом, приведя регион в состояние, соответствующее
//    загрузке по предпочитаемому ImageBase, для которого и вычислялась эталонная контрольная сумма.
// 2. Проверить контрольную сумму модифицированной копии региона. Если сумма совпала с эталонной, значит
//    регион не подвергался иным изменениям, кроме внесения базовых поправок, и в этом случае текущая 
//    контрольная сумма региона замещает эталонную. Установить в поле ValidateFlag значение TRUE.
// 3. Если сумма не совпала с эталонной, значит в регион были внесены несанкционированные изменения, и в
//    этом случае ничего более не делается, т.к. рассчитать новую эталонную контрольную сумму невозможно,
//    из-за того, что регион необратимо изменен по сравнению с исходным состоянием. Можно установить в
//    поле ValidateFlag значение TRUE, т.к. результат в этом случае будет точно такой же, как и при
//    соответствующей региону контрольной сумме, а скорость принятия решения увеличится. Однако, если 
//    этот же регион защищен кодом коррекции ошибок, то устанавливать флаг не следует. Как только регион
//    будет восстановлен декодером Рида-Соломона, можно будет рассчитать новую эталонную контрольную
//    сумму и уже тогда следует устанавливать этот флаг.
//
// Как и CheckCRC32, функция возвращает логическое значение: 
//    TRUE  в случае, если регион корректен.
//    FALSE в случае, если регион не удалось привести в соответствие с текущей базой (ошибка выделения
//    памяти, регион был несанкционированно изменен и т.д.).
//
// Используемые глобальные переменные: CurrentImageBase, PEHeader (инициализируются в WinMain),
//                                     OrgPEValue (заполняется одной из вспомогательных утилит).

BOOL CheckCRC32WithFixUp(PCrcDsc descriptor) {
	INT		ImageBaseDelta;
	DWORD   RelocsNum, i;
	PDWORD	Relocs;
	PBYTE	Buffer;
	CrcDsc	dscCopy;
	BOOL	Res;

	// Если регион уже протестирован на корректность, проверяем его в обычном порядке.
	if(descriptor->ValidateFlag == TRUE) return CheckCRC32(descriptor);

	// Вычисляем значение дельта-смещения.
	ImageBaseDelta = CurrentImageBase - OrgPEValue.ImageBase;

	// Проверяем, загружен ли образ по предпочитаемому ImageBase (в этом случае ImageBaseDelta == 0).
	// Если да, то устанавливаем поле ValidateFlag = TRUE и проверяем контрольную сумму в обычном порядке.
	if(ImageBaseDelta == 0) {
		Res = CheckCRC32(descriptor);
		descriptor->ValidateFlag = TRUE;
		return Res;
	}

	// Образ загружен по ImageBase, отличному от предпочитаемого. Проверяем регион.

	// Выделяем память под список адресов перемещаемых элементов.
	if((Relocs = (PDWORD)HeapAlloc(GetProcessHeap(), 0, descriptor->Length)) == NULL) { 
		MsgBox("CheckCRC32WithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Relocs!");	
		return FALSE;
	}

	// Заполняем список адресов перемещаемых элементов защищенного региона. Если список пуст, то ничего более
	// делать не нужно - регион не содержит перемещаемых элементов, эталонная контрольная сумма корректна и 
	// соответствует состоянию региона. Иначе - делаем копию региона, настраиваем её соответственно случаю
	// загрузки по предпочитаемому ImageBase и сверяем с эталонной контрольной суммой.
	RelocsNum = SearchingRelocs(Relocs, descriptor->Addr, descriptor->Length);
	if(RelocsNum == 0) {

		// Регион не содержит перемещаемых элементов. Ничего более делать не требуется.
		Res = CheckCRC32(descriptor);
		descriptor->ValidateFlag = TRUE;

	} else {

		// Выделяем память под копию защищенного региона.
		if((Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, descriptor->Length)) == NULL) {
			HeapFree(GetProcessHeap(), 0, Relocs);
			MsgBox("CheckCRC32WithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Buffer!");	
			return FALSE; 
		}

		// Копируем защищенный регион в буфер.
		CopyMemory(Buffer, descriptor->Addr, descriptor->Length);

		// Приводим копию региона в состояние, соответствующее загрузке по предпочитаемому ImageBase,
		// путём уменьшения каждого перемещаемого элемента на величину дельта-смещения. 
		for(i = 0; i < RelocsNum; i++) *(PDWORD)&Buffer[Relocs[i] - (DWORD)descriptor->Addr] -= ImageBaseDelta;

		// Заполняем дескриптор для копии региона (необходимо для вызова CheckCRC32)
		dscCopy.Addr   = Buffer;
		dscCopy.Length = descriptor->Length;
		dscCopy.OrgCrc = descriptor->OrgCrc;

		// Проверяем целостность копии региона, приведенной в соответствие предпочитаемому ImageBase.
		CheckCRC32(descriptor);
		if((Res = CheckCRC32(&dscCopy)) == TRUE) {

			// Копия региона корректна, заменяем эталонную контрольную сумму региона на текущую.
			DWORD OrgCRC = descriptor->OrgCrc;			// Сохраняем оригинальное значение для вывода диагностики.
			descriptor->OrgCrc = descriptor->CurrCrc;
			descriptor->ValidateFlag = TRUE;

			MsgBox("CRC32 recalculating", MB_ICONINFORMATION, "Region ID\t\t%04d\nStart Address\t%Xh\nData Length\t%d(%Xh)\n"
				"Old Original CRC\t%08Xh\nNew Original CRC\t%08Xh\nFixUp quantity\t%d", descriptor->Id, descriptor->Addr,
				descriptor->Length, descriptor->Length, OrgCRC, descriptor->OrgCrc, RelocsNum);

		} else {

			// Копия региона некорректна. Поскольку регион необратимо изменен, расчет нового значения 
			// контрольной суммы невозможен. Оставляем все как есть, ничего делать не нужно.
			
			MsgBox("CRC32 recalculating", MB_ICONWARNING, "Region ID\t\t%04d\nStart Address\t%Xh\nData Length\t%d(%Xh)\n"
				   "Old Original CRC\t%08Xh\nNew Original CRC\tCRC Error! Recalculation impossible!\nFixUp quantity\t%d", 
				    descriptor->Id, descriptor->Addr, descriptor->Length, descriptor->Length, descriptor->OrgCrc, RelocsNum);

		}
		HeapFree(GetProcessHeap(), 0, Buffer);
	}
	HeapFree(GetProcessHeap(), 0, Relocs);
	return Res;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура проверяет совпадение текущей и эталонной контрольных сумм для массива, адресуемого
// через дескриптор. Для расчета контрольных сумм используется одна из реализаций алгоритма CRC32.
// Полином, используемый для расчета контрольной суммы, замаскирован. Это не позволит обнаружить
// процедуру простым поиском полинома в исполняемом коде. 
BOOL CheckCRC32(PCrcDsc descriptor) {
    DWORD i, j, crc, crc_table[256], length = descriptor->Length; 
	PBYTE buffer = (PBYTE)descriptor->Addr;
	DWORD mask = 0xF5D92187, crc32poly = 0x1861A2A7;	// crc32poly ^ mask -> 0xEDB88320	
    
	for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) crc = crc & 1 ? (crc >> 1) ^ crc32poly ^ mask : crc >> 1;
        crc_table[i] = crc;
    }
	
    crc = 0xFFFFFFFFUL;
	while(length--) crc = crc_table[(crc ^ *buffer++) & 0xFF] ^ (crc >> 8);
	descriptor->CurrCrc = crc ^ 0xFFFFFFFFUL;
	if(descriptor->CurrCrc == descriptor->OrgCrc) return TRUE; 
	return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура выполняет обход всех участков кода/данных, защищенных кодом коррекции ошибок.
void RSCDataScan(PVOID EntryPoint) {
	PEccDsc  dscr;
	CHAR	 str[70], listing[1024] = "";
	INT		 ImageBaseDelta = CurrentImageBase - OrgPEValue.ImageBase;
	
	F1ErrCount = 0;

	// Признаком конца цепочки дескрипторов является значение NULL в поле NextDsc текущего дескриптора.
	// Однако, это поле является перемещаемым элементом, поэтому, при загрузке по базовому адресу, отличному
	// от предпочитаемого, его значение будет скорректировано на величину базовой поправки, т.е. в нем будет
	// находиться не NULL, а дельта между текущим и предпочитаемым значениями ImageBase. С учетом этого и 
	// построим условие выхода из цикла проверки цепочки дескрипторов.
	for(dscr = (PEccDsc)EntryPoint; (INT)dscr != ImageBaseDelta; dscr = (PEccDsc)dscr->NextDsc) {
		switch(RSCDataFixingWithFixUp(dscr)) {
		case 0: sprintf_s(str, sizeof(str), "Region #%02d --> No Errors.\n", dscr->Id);
			break;
		case 1: sprintf_s(str, sizeof(str), "Region #%02d --> Correction done. %u error(s) fixed.\n", dscr->Id, RSGetErrors()); 
			break;
		case 2: sprintf_s(str, sizeof(str), "Region #%02d --> Restoring is impossible. Errors is more than %d\n", dscr->Id, dscr->EccLength/2); 
			break;
		}
		strcat_s(listing, sizeof(listing), str);
	}
	RSLibClose();
	MessageBox(NULL, listing, "Reed-Solomon Codec", MB_SYSTEMMODAL | MB_ICONINFORMATION);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Конверт для использования функции RSCDataFixing в случае, если в защищенном регионе имеются
// перемещаемые элементы. В дескрипторе региона используется поле ValidateFlag, по умолчанию
// инициализированное значением FALSE. Это означает, что регион, описываемый дескриптором,
// ещё не проверялся на корректность относительно текущего значения ImageBase.
//
// Функция проверяет корректность региона, описываемого дескриптором, относительно текущего значения
// ImageBase. Если текущий ImageBase совпадает с предпочитаемым, то ничего делать не нужно - регион
// корректен. Если регион загружен по отличному от предпочитаемого ImageBase, тогда его необходимо
// привести в соответствие с текущей базой. Для этого необходимо:
//
// 1. Сделать копию региона, найти в ней перемещаемые элементы и применить к ним базовые поправки
//    относительно предпочитаемого ImageBase, таким образом приведя регион в состояние, соответствующее
//    загрузке по предпочитаемому ImageBase, для которого и вычислялся код коррекции ошибок.
// 2. Проверить целостность модифицированной копии региона. Если искажений не обнаружено, значит
//    регион не подвергался иным изменениям, кроме внесения базовых поправок, и в этом случае необходимо
//    расчитать новый код коррекции ошибок для защищенного региона. Установить в поле ValidateFlag
//    значение TRUE.
// 3. Если целостность копии региона нарушена, значит в регион были внесены несанкционированные изменения.
//	  Нужно восстановить копию региона в исходном виде, используя имеющийся код коррекции ошибок. Если
//    восстановление прошло успешно, нужно применить к восстановленной копии региона базовые поправки, 
//	  приводящие его в соответствие с текущим значением ImageBase. После этого необходимо расчитать по 
//	  копии новый код коррекции ошибок. Далее, восстановить регион, скопировав в него восстановленную и
//    настроенную копию. Установить в поле ValidateFlags значение TRUE.
// 4. Если целостность копии региона нарушена, и восстановить её в исходном виде не удается, то, в этом 
//    случае ничего более не делается. Рассчитать новый код коррекции ошибок не удастся, поскольку регион
//    необратимо изменен по сравнению с исходным состоянием, и корректирующей способности кода недостаточно 
//    для исправления ошибок. Можно установить в поле ValidateFlags значение TRUE, т.к. результат в этом
//    случае будет точно такой же, как и при соответствующем региону коде коррекции ошибок, а скорость
//    принятия решения увеличится.
//
// Как и RSCDataFixing, функция возвращает одно из значений: 
//    0 - регион корректен и не имел ошибок.
//    1 - регион корректен, имел ошибки, все они исправлены.
//    2 - регион не удалось привести в соответствие с текущей базой (ошибка выделения памяти, регион имеет 
//        слишком много ошибок, и т.д.).
//
// Используемые глобальные переменные: CurrentImageBase, PEHeader (инициализируются в WinMain),
//                                     OrgPEValue (заполняется одной из вспомогательных утилит).

DWORD RSCDataFixingWithFixUp(PEccDsc descriptor) {
	CHAR	OldEcc[128], NewEcc[128];
	INT		ImageBaseDelta;
	DWORD	RelocsNum, i;
	PDWORD	Relocs;
	PBYTE	Buffer;
	EccDsc  dscCopy;
	BOOL	Res;

	// Если регион уже протестирован на корректность, проверяем его в обычном порядке.
	if(descriptor->ValidateFlag == TRUE) return RSCDataFixing(descriptor);

	// Вычисляем значение дельта-смещения.
	ImageBaseDelta = CurrentImageBase - OrgPEValue.ImageBase;

	// Проверяем, загружен ли образ по предпочитаемому ImageBase (в этом случае ImageBaseDelta == 0).
	// Если да, то устанавливаем поле ValidateFlag = TRUE и проверяем контрольную сумму в обычном порядке.
	if(ImageBaseDelta == 0) {
		Res = RSCDataFixing(descriptor);
		descriptor->ValidateFlag = TRUE;
		return Res;
	}

	// Образ загружен по ImageBase, отличному от предпочитаемого.
	// Выделяем память под список адресов перемещаемых элементов. 
	if((Relocs = (PDWORD)HeapAlloc(GetProcessHeap(), 0, descriptor->Length)) == NULL) {
		MsgBox("RSCDataFixingWithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Relocs!");	
		return 2;
	}

	// Заполняем список адресов перемещаемых элементов защищенного региона. Если список пуст, то ничего более
	// делать не нужно - регион не содержит перемещаемых элементов, код коррекции ошибок не требует обновления
	// и соответствует состоянию региона. Иначе - делаем копию региона, настраиваем её соответственно случаю
	// загрузки по предпочитаемому ImageBase и проверяем целостность.
	RelocsNum = SearchingRelocs(Relocs, descriptor->Addr, descriptor->Length);
	if(RelocsNum == 0) {

		// Регион не содержит перемещаемых элементов. Ничего более делать не требуется.
		Res = RSCDataFixing(descriptor);

	} else {

		// Выделяем память под копию защищенного региона.
		if((Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, descriptor->Length)) == NULL) {
			HeapFree(GetProcessHeap(), 0, Relocs);
			MsgBox("RSCDataFixingWithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Buffer!");	
			return 2; 
		}

		// Копируем защищенный регион в буфер.
		CopyMemory(Buffer, descriptor->Addr, descriptor->Length);

		// Приводим копию региона в состояние, соответствующее загрузке по предпочитаемому ImageBase,
		// путём уменьшения каждого перемещаемого элемента на величину дельта-смещения. 
		for(i = 0; i < RelocsNum; i++) *(PDWORD)&Buffer[Relocs[i] - (DWORD)descriptor->Addr] -= ImageBaseDelta;

		// Заполняем дескриптор для копии региона (необходимо для вызова RSCDataFixing)
		dscCopy.Addr      = Buffer;
		dscCopy.Length    = descriptor->Length;
		dscCopy.EccLength = descriptor->EccLength;
		CopyMemory(dscCopy.Ecc, descriptor->Ecc, descriptor->EccLength);
		
		// Сохраняем начало оригинального ECC для вывода диагностики
		sprintf_s(OldEcc, "%02X %02X %02X %02X %02X %02X %02X ...", descriptor->Ecc[0], descriptor->Ecc[1],
			      descriptor->Ecc[2], descriptor->Ecc[3], descriptor->Ecc[4], descriptor->Ecc[5], descriptor->Ecc[6]);

		// Проверяем целостность копии региона, приведенной в соответствие предпочитаемому ImageBase.
		Res = RSCDataFixing(&dscCopy);
		if(Res == 0) {

			// Целостность не нарушена, значит регион не подвергался иным изменениям, кроме внесения базовых 
			// поправок. Расчитываем новый код коррекции ошибок для защищенного региона.

			RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
			RSCalcECC(descriptor->Addr, descriptor->Ecc);

		} else if(Res == 1) {

			// Целостность региона нарушена, однако, число несанкционированных изменений не превысило
			// корректирующей способности кода, и копия региона была приведена в исходное состояние.

			// Настраиваем восстановленную копию региона обратно на текущий ImageBase
			for(i = 0; i < RelocsNum; i++) *(PDWORD)&Buffer[Relocs[i] - (DWORD)descriptor->Addr] += ImageBaseDelta;

			// Расчитываем новый код коррекции ошибок для восстановленной копии региона.
			RSLibInit(dscCopy.Length, dscCopy.EccLength, NULL);
			RSCalcECC(dscCopy.Addr, dscCopy.Ecc);

			// Копируем восстановленный регион и новый код коррекции ошибок на штатные места.
			CopyMemory(descriptor->Addr, Buffer, descriptor->Length);
			CopyMemory(descriptor->Ecc, dscCopy.Ecc, descriptor->EccLength);

		} else if(Res == 2) {

			// Целостность региона нарушена, корректирующей способности кода недостаточно для  
			// восстановления. Поскольку регион необратимо изменен, расчет нового кода коррекции 
			// ошибок невозможен. Оставляем все как есть, ничего делать не нужно.

			MsgBox("ECC recalculating", MB_ICONWARNING, "Region ID\t\t%04d\nStart Address\t%Xh\nData Length\t%d(%Xh)\n"
				   "Old ECC\t\t%s\nNew ECC\t\tECC Error! Recalculation impossible!\nFixUp quantity\t%d", descriptor->Id,
				    descriptor->Addr, descriptor->Length, descriptor->Length, OldEcc, RelocsNum);
		}

		// Вывод диагностики
		if(Res == 0 || Res == 1) {
			sprintf_s(NewEcc, "%02X %02X %02X %02X %02X %02X %02X ...", descriptor->Ecc[0], descriptor->Ecc[1],
				    descriptor->Ecc[2], descriptor->Ecc[3], descriptor->Ecc[4], descriptor->Ecc[5], descriptor->Ecc[6]);
			MsgBox("ECC recalculating", MB_ICONINFORMATION, "Region ID\t\t%04d\nStart Address\t%Xh\nData Length\t%d(%Xh)\n"
				   "Old ECC\t\t%s\nNew ECC\t\t%s\nFixUp quantity\t%d", descriptor->Id, descriptor->Addr,
				    descriptor->Length, descriptor->Length, OldEcc, NewEcc, RelocsNum);
		}

		HeapFree(GetProcessHeap(), 0, Buffer);
	}
	HeapFree(GetProcessHeap(), 0, Relocs);
	descriptor->ValidateFlag = TRUE;
	return Res;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура выполняет проверку целостности и, в случае необходимости, если не превышена
// корректирующая способность ECC, восстановление кода/данных, защищенных этим ECC
DWORD RSCDataFixing(PEccDsc descriptor) {
	
	RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
	if(RSCheckData(descriptor->Addr, descriptor->Ecc)  == 0) return 0;	// нет ошибок
	if(RSRepairData(descriptor->Addr, descriptor->Ecc) == 1) return 1;	// ошибки есть, все исправлены
	return 2;															// ошибок слишком много, коррекция невозможна
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Функция возвращает количество перемещаемых элементов внутри указанного диапазона адресов. 
// Абсолютные адреса найденных перемещаемых элементов помещаются в массив Reloc. 
// 
// Используемые глобальные переменные: CurrentImageBase, PEHeader (инициализируются в WinMain).
DWORD SearchingRelocs(PDWORD Reloc, PBYTE Addr, DWORD Length) {
	DWORD	RegStartAddr = (DWORD)Addr, RegEndAddr = (DWORD)Addr + Length;
	DWORD	FixupIndex, FixupMaxIndex, PageStartAddr, FixupAddr;
	DWORD	BlockRVA, RelocDirSize, RelocDirEndAddr, RelocsNum = 0;
	PIMAGE_BASE_RELOCATION Block;

	// Секция перемещаемых элементов организована как последовательность блоков базовых поправок.
	// Каждый блок описывает перемещаемые элементы на странице размером в 4 Кб, и имеет заголовок,
	// содержащий RVA-адрес страницы в образе и длину блока, включая заголовок (+2 DWORD).

	// Из PE-заголовка получаем RVA-адрес первого блока и полный размер секции перемещаемых элементов.
	BlockRVA = PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	RelocDirSize = PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	// Будем искать блоки, описывающие страницы, в которые укладывается диапазон адресов защищенного региона.
	Block = (PIMAGE_BASE_RELOCATION)(CurrentImageBase + BlockRVA);		// Первый блок базовых поправок
	RelocDirEndAddr = CurrentImageBase + BlockRVA + RelocDirSize;		// Адрес конца последнего блока
	for(; (DWORD)Block < RelocDirEndAddr; Block = (PIMAGE_BASE_RELOCATION)((DWORD)Block + Block->SizeOfBlock)) {

		// Если страница, описываемая текущим блоком базовых поправок, еще не содержит адресов защищенного 
		// региона, пропускаем её. Если уже не содержит - завершаем цикл, т.к. все, что можно, уже найдено. 
		PageStartAddr = CurrentImageBase + Block->VirtualAddress;
		if(PageStartAddr < (RegStartAddr & 0xFFFFF000)) continue;
		if(PageStartAddr > (RegEndAddr & 0xFFFFF000)) break;

		// Будем искать внутри блока базовые поправки (fixup'ы) из диапазона адресов защищенного региона.
		FixupIndex = sizeof(IMAGE_BASE_RELOCATION)/sizeof(WORD);  // Текущй fixup - первый после заголовка блока
		FixupMaxIndex = Block->SizeOfBlock/sizeof(WORD);		  // Максимальный индекс для fixup'а в блоке
		for(; FixupIndex < FixupMaxIndex; FixupIndex++) {

			// Здесь пока будем хранить не адрес перемещаемого элемента, а сам fixup
			FixupAddr = *(PWORD)((DWORD)Block + FixupIndex * sizeof(WORD)); 

			// Вычисляем абсолютный адрес перемещаемого элемента, на который указывает базовая поправка. При этом 
			// обрабатываем только fixup'ы типа IMAGE_REL_BASED_HIGHLOW (тип хранится в старших четырех битах fixup'а) 
			if((FixupAddr & 0xF000) != (IMAGE_REL_BASED_HIGHLOW << 12)) continue;
			FixupAddr = PageStartAddr + (FixupAddr & 0x0FFF);

			// Если адрес перемещаемого элемента еще не попадает внутрь защищенного региона, пропускаем его. 
			// Если уже не попадает - завершаем цикл. Если попал - сохраняем адрес в массив.
			if(FixupAddr < RegStartAddr) continue;
			if(FixupAddr >= RegEndAddr) break;
			Reloc[RelocsNum++] = FixupAddr;
		}
	}
	return RelocsNum;	// Количество найденных перемещаемых элементов.
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
