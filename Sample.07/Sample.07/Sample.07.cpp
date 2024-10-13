//*****************************************************************************
// (v07) Восстановление измененных данных/кода защищенного приложения с
// использованием помехоустойчивого кодирования Рида-Соломона.
// Построение высокоэшелонированной защиты.
//
// Автор - Сергей Усков (a9wdk@yandex.ru, Telegram: @a9wdk)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "hasp_api.h"
#include "RSLib.h"			// Кодек Рида-Соломона.
#include "macros.h"			// Сигнатуры и структуры данных, используемые для передачи информации во внешнюю утилиту.
#include "enc_str.h"		// Данные, подлежащие зашифрованию при помощи внешней утилиты.

#define MAX_LOADSTRING 100

#define xGap 50				// Расстояние между соседними символами при выводе текста.
#define yGap 20				// Расстояние между соседними строками при выводе текста.

#define CheckKeyTimeout		500						// Интервал фонового опроса ключа (в миллисекундах).
#define CheckThreadTimeout	CheckKeyTimeout*2		// Интервал проверки состояния потока фонового опроса ключа
#define MinReactionTimeout	10						// Минимальная задержка (в сек.) до реакции на отсутствие потока.
#define MaxReactionTimeout	20						// Максимальная задержка (в сек.) до реакции на отсутствие потока.

#define F1Trigger	1		// Пороговое значение для Function1, включающее третий эшелон защиты.
#define F2Trigger	3		// Пороговое значение для Function2, включающее третий эшелон защиты.

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
// Глобальные переменные.
HINSTANCE hInst;							
HMENU hMainMenu;
TCHAR szTitle[MAX_LOADSTRING];				
TCHAR szWindowClass[MAX_LOADSTRING];		
TCHAR szText;

HANDLE hF1Thread, hF2Thread, hKeyBackgroundChk;		// Идентификаторы запущенных потоков
BOOL f1Terminate = TRUE, f2Terminate = TRUE;		// Признаки завершения потоков
BOOL HaspKeyPresent = FALSE;						// Флаг устанавливается потоком, выполняющим фоновый опрос ключа

HaspSession Main = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, HASP_DEFAULT_FID};

int	TimerID, ProtectTimeout = MaxReactionTimeout;

DWORD F1ErrCount = 0, F2ErrCount = 0;

CrcDscList CrcListEntry = {CrcDscListSig, NULL};		// точка входа в список CRC-дескрипторов
EccDscList EccListEntry = {EccDscListSig, NULL};		// точка входа в список ECC-дескрипторов

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
BOOL				CheckCRC32(PCrcDsc descriptor);
void				RSCDataScan(PVOID EntryPoint);
DWORD				RSCDataFixing(PEccDsc descriptor);
DWORD				MsgBox(PCHAR title, UINT style, PCHAR format, ...);

//////////////////////////////////////////////////////////////////////////////////////////////

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	MSG msg;
	HWND hWnd;
	HACCEL hAccelTable;
	UCHAR vc[sizeof(vendor_code)];
	
	// Сохраняем идентификатор приложения в глобальной переменной.
	hInst = hInstance;
	
	// Копируем зашифрованный вендор-код в локальную переменную.
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

Factors  F1 = {0x0000, 0x0080, 0xFF00, 0x00FF};	// Массив с коэффициентами, необходимыми для работы функции.

#define F1_Feature		1						// Номер фичи ключа, которую будет использовать функция.
#define F1_Ecc_Length	(sizeof(F1) * 2)		// Размер ECC для зашифрованного массива с коэффициентами.
#define Fn1_Ecc_Length	30						// Размер ECC для защищенного участка кода.

HaspSession Fn1  = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F1_Feature};

CrcDsc F1_Crc  = {(PBYTE)0x78563412};			// CRC-дескриптор массива F1.
EccDsc F1_Ecc  = {(PBYTE)0x78563412};			// ECC-дескриптор массива F1.
EccDsc Fn1_Ecc = {(PBYTE)0x78563412};			// ECC-дескриптор участка кода между метками l1 и l2.

KeyEncDataMrk F1_Mrk1 = {KeyEncDataSig, &F1, sizeof(F1), F1_Feature};				// Encrypt-маркер массива F1
CrcDataMrk	  F1_Mrk2 = {CrcDataSig, &F1_Crc, &F1, sizeof(F1), 0};					// CRC-маркер массива F1
EccDataMrk    F1_Mrk3 = {EccDataSig, &F1_Ecc, &F1, sizeof(F1), F1_Ecc_Length, 0};	// ECC-маркер массива F1

void Function1(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	Factors F;
	UCHAR vc[sizeof(vendor_code)];

	// Копируем зашифрованные вендор-код и буфер с коэффициентами в локальные переменные.
	CopyMemory(vc, vendor_code, sizeof(vc));
	CopyMemory(&F, &F1, sizeof(F));

	l1:	// Начало защищенного региона кода.

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
	
	l2:	// Конец защищенного региона кода.

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
					// Проверка целостности содержимого зашифрованного массива с коэффициентами.
					if(!CheckCRC32(&F1_Crc)) {
						if(F1ErrCount < F1Trigger) SetTextColor(hDC, RGB(192, 0, 192));
							else SetTextColor(hDC, RGB(192, 0, 0));
						F1ErrCount += 1;
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
	
	AsmEccCodeMrk(Fn1_Ecc, l1, l2, Fn1_Ecc_Length, 1);			// ECC-маркер участка кода между метками l1 и l2.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура генерирует псевдо-случайные числа в диапазоне [128; 255] с контролем ошибок.
//  Все входящие в диапазон значения выводятся зеленым цветом, все прочие - красным. Так же, 
//  в процедуре реализована реакция на "редкое событие" - монотонно возрастающая последовательность
//  из трёх чисел подряд, отличающиеся друг от друга на единицу, последнее из них выводится синим цветом.

Factors  F2 = {0x0080, 0x00FF, 0xFF00, 0x00FF};	// Массив с коэффициентами, необходимыми для работы функции.

#define F2_Feature		2						// Номер фичи ключа, которую будет использовать функция.
#define F2_Ecc_Length	(sizeof(F2) * 2)		// Размер ECC для зашифрованного массива с коэффициентами.
#define Fn2_Ecc_Length	30						// Размер ECC для защищенного участка кода.

HaspSession Fn2  = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F2_Feature};

CrcDsc Fn2_Crc = {(PBYTE)0x78563412};			// CRC-дескриптор участка кода между метками l1 и l2.
EccDsc Fn2_Ecc = {(PBYTE)0x78563412};			// ECC-дескриптор участка кода между метками l1 и l2.
EccDsc F2_Ecc  = {(PBYTE)0x78563412};			// ECC-дескриптор массива F2. 

KeyEncDataMrk F2_Mrk1 = {KeyEncDataSig, &F2, sizeof(F2), F2_Feature};			// Encrypt-маркер массива F2
EccDataMrk F2_Mrk2 = {EccDataSig, &F2_Ecc, &F2, sizeof(F2), F2_Ecc_Length, 2};	// ECC-маркер массива F2

void Function2(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	Factors F;
	UCHAR vc[sizeof(vendor_code)];
	
	// Копируем зашифрованные вендор-код и буфер с коэффициентами в локальные переменные.
	CopyMemory(vc, vendor_code, sizeof(vc));
	CopyMemory(&F, &F2, sizeof(F));

	l1:	// Начало защищенного региона кода.
	
	// Выполняем Login на Feature 2, если ошибка - выводим сообщение и завершаем работу функции. Перед 
	// вызовом Login производится расшифрование Vendor-кода, сразу после вызова - обратное зашифрование.
	Fn2.status = hasp_login(Fn2.feature, Dec(vc, sizeof(vc)), &Fn2.handle);
	Enc(vc, sizeof(vc));
	if(Fn2.status != HASP_STATUS_OK) {
		MsgBox("Feature ID = 2", MB_SYSTEMMODAL | MB_ICONERROR, "Login error #%d", Fn2.status);
		EnableMenuItem(hMainMenu, IDM_F2Start, MF_ENABLED);
		EnableMenuItem(hMainMenu, IDM_F2Stop, MF_GRAYED);
		ExitThread(1);
	}
	
	// Расшифровываем локальную копию буфера с коэффициентами
	hasp_decrypt(Fn2.handle, &F, sizeof(F));

	l2:	// Конец защищенного региона кода.

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
				z0 = ((rand() % (F.Max - F.Min) + F.Min) ^ (F.Xor & F.And)) & 0x0000FFFF;

				// "Редкое событие". 

				if(z1 == z0-1 && z2 == z1-1) {
					// Проверка целостности "помеченного" участка кода.
					if(!CheckCRC32(&Fn2_Crc)) {
						if(F2ErrCount < F2Trigger) SetTextColor(hDC, RGB(192, 0, 192));
							else SetTextColor(hDC, RGB(192, 0, 0));
						F2ErrCount += 1;
					} else SetTextColor(hDC, RGB(0, 0, 192));
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
	Fn2.status = hasp_logout(Fn2.handle);
	ExitThread(0);

	AsmCrcCodeMrk(Fn2_Crc, l1, l2, 1);						// CRC-маркер участка кода между метками l1 и l2.
	AsmEccCodeMrk(Fn2_Ecc, l1, l2, Fn2_Ecc_Length, 3);		// ECC-маркер участка кода между метками l1 и l2.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура выполняет фоновый опрос ключа с указанным интервалом. Строковые параметры,
//	позволяющие обнаружить процедуру через перекрестные ссылки (scope, format и vendorcode),
//  зашифрованы и расшифровываются непосредственно перед вызовом hasp_get_info(), после чего
//  снова зашифровываются.
void KeyBackgroundChk(PVOID hwnd) {
	HANDLE hMsg = INVALID_HANDLE_VALUE;
	DWORD hMsgState = NULL;
	char *info = 0;
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

	// Запускаем поток, выполняющий, при необходимости, коррекцию кода/данных при помощи декодера Рида-Соломона.
	if(hRSCState == 0) hRSC = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RSCDataScan, (LPVOID)EccListEntry.EntryPoint, 0, NULL);

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
// Процедура проверяет совпадение текущей и эталонной контрольных сумм для массива, адресуемого
// через дескриптор. Для расчета контрольных сумм используется одна из реализаций алгоритма CRC32.
BOOL CheckCRC32(PCrcDsc descriptor) {
	DWORD i, j, crc, crc_table[256], length = descriptor->Length; 
	PBYTE buffer = (PBYTE)descriptor->Addr;

	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 0; j < 8; j++) crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
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
	DWORD	 i;
	PEccDsc  dscr;
	CHAR	 str[70], listing[1024] = "";
	
	// Проверка состояний триггеров. Если хотя бы один достиг порогового уровня, начинаем восстановление кода/данных
	if((F1ErrCount > F1Trigger) || (F2ErrCount > F2Trigger)) {
		for(i = 0, dscr = (PEccDsc)EntryPoint; dscr != NULL; dscr = (PEccDsc)dscr->NextDsc, i++) {
			switch(RSCDataFixing(dscr)) {
			case 0: sprintf_s(str, sizeof(str), "Region #%04d --> No Errors.\n", dscr->Id);
				break;
			case 1: sprintf_s(str, sizeof(str), "Region #%04d --> Correction done. %u error(s) fixed.\n", dscr->Id, RSGetErrors()); 
				break;
			case 2: sprintf_s(str, sizeof(str), "Region #%04d --> Restoring is impossible. Errors is more than %d\n", dscr->Id, dscr->EccLength/2); 
				break;
			}
			strcat_s(listing, sizeof(listing), str);
		}
		RSLibClose();
		F1ErrCount = F2ErrCount = 0;	// Сброс триггеров.
		MsgBox("Reed-Solomon Codec", MB_SYSTEMMODAL | MB_ICONINFORMATION, listing);
	}
	ExitThread(0);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура выполняет проверку целостности и, в случае необходимости, если не превышена
// корректирующая способность ECC, восстановление кода/данных, защищенных этим ECC
DWORD RSCDataFixing(PEccDsc descriptor) {
	
	RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
	if(RSCheckData((PBYTE)descriptor->Addr, descriptor->Ecc)  == 0) return 0;	// нет ошибок
	if(RSRepairData((PBYTE)descriptor->Addr, descriptor->Ecc) == 1) return 1;	// ошибки есть, все исправлены
	return 2;																	// ошибок слишком много, коррекция невозможна
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
