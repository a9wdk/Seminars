//*****************************************************************************
// (v10) Защита кода методом каскадного динамического шифрования через
// обработчики исключительных ситуаций.
//
// Автор - Сергей Усков (Sergey.Uskov@safenet-inc.com, uskov@smtp.ru)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "hasp_api.h"
#include "macros.h"			// Сигнатуры и структуры данных, используемые для передачи информации во внешнюю утилиту.
#include "enc_str.h"		// Данные, подлежащие зашифрованию при помощи внешней утилиты.

#define MAX_LOADSTRING 100

#define xGap 50				// Расстояние между соседними символами при выводе текста.
#define yGap 20				// Расстояние между соседними строками при выводе текста.

#define CheckKeyTimeout		500						// Интервал фонового опроса ключа (в миллисекундах).
#define CheckThreadTimeout	CheckKeyTimeout*2		// Интервал проверки состояния потока фонового опроса ключа
#define MinReactionTimeout	10						// Минимальная задержка (в сек.) до реакции на отсутствие потока.
#define MaxReactionTimeout	20						// Максимальная задержка (в сек.) до реакции на отсутствие потока.

//////////////////////////////////////////////////////////////////////////////////////////////
// Обработчики исключительных ситуаций.

EXCEPTION_DISPOSITION __cdecl SEH_Handler(struct _EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame, 
                                          struct _CONTEXT *ContextRecord, void *DispatcherContext);

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

int	TimerID, ProtectTimeout = MaxReactionTimeout;

// Перед началом исполнения кода примера скрытно устанавливаем векторный обработчик исключительных ситуаций.
// Это будет выполнено как инициализация переменной hVEH_Handler, на этапе выполнения startup-кода примера.

PVOID  hVEH_Handler = AddVectoredExceptionHandler(0, VEH_Handler);	// Идентификатор VEH-обработчика

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
void				KeyEnc(PKeyEncCodeDsc data);
void				KeyDec(PKeyEncCodeDsc data);
void				HaspReLogin(PHaspSession session);
DWORD				MsgBox(PCHAR title, UINT style, PCHAR format, ...);

//////////////////////////////////////////////////////////////////////////////////////////////

HaspSession Main = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, HASP_DEFAULT_FID};

CstEncCodeDsc WM_CstEnc = {(PBYTE)0x78563412};		// Encrypt-дескриптор участка кода между метками l1 и l2.

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	MSG msg;
	HWND hWnd;
	HACCEL hAccelTable;
	UCHAR vc[sizeof(vendor_code)];

	// Сохраняем идентификатор приложения в глобальной переменной.
	hInst = hInstance;
	
	// Копируем зашифрованный вендор-код данные в локальную переменную.
	CopyMemory(vc, vendor_code, sizeof(vc));

	RaiseExceptionForCustomDecrypt(WM_CstEnc, NULL);	
	l1:			// Начало региона.

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
		RaiseExceptionForCustomEncrypt(WM_CstEnc, offset l3);	// После обработки исключения передать управление на l3.
	}
	
	// Регистрируем класс окна, создаем главное окно приложения и отображаем его.
	RegisterWindowClass(hInst);
	if (!InitInstance (hInst, nCmdShow)) RaiseExceptionForCustomEncrypt(WM_CstEnc, offset l4);

	// Запускаем поток, выполняющий фоновый опрос ключа и понижаем ему приоритет.
	hKeyBackgroundChk = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChk, 0, 0, NULL);
	SetThreadPriority(hKeyBackgroundChk, THREAD_PRIORITY_LOWEST);

	RaiseExceptionForCustomEncrypt(WM_CstEnc, NULL);	
	l2:			// Конец региона.

	// Запускаем цикл обработки сообщений.
	while (GetMessage(&msg, NULL, 0, 0)) {
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	Main.status = hasp_logout(Main.handle);
	return 0;

	l3:		// Выход - приложение уже запущено.
	MsgBox("WinMain", MB_SYSTEMMODAL | MB_ICONINFORMATION, "The application already started!");
	return -1;

	l4:
	return -2;

	AsmCstEncCodeMrk(WM_CstEnc, l1, l2);		// Encrypt-маркер участка кода между метками l1 и l2.
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

#define F1_Feature 1								// Номер фичи ключа, которую будет использовать функция.

HaspSession Fn1 = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F1_Feature};

KeyEncCodeDsc  Fn1_KeyEnc1 = {(PHaspSession)0x78563412};	// Encrypt-дескриптор участка кода между метками l1 и l2.
KeyEncCodeDsc  Fn1_KeyEnc2 = {(PHaspSession)0x78563412};	// Encrypt-дескриптор участка кода между метками l2 и l3.

void Function1(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z_min = 0x0000, z_max = 0x0080, z_xor = 0xFF00, z_and = 0x00FF;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	UCHAR vc[sizeof(vendor_code)];
	
	InstallHandler(SEH_Handler);
	
	RaiseExceptionForKeyDecrypt(Fn1_KeyEnc1, NULL);	
	l1:		// Начало 1-го региона.

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
		RaiseExceptionForKeyEncrypt(Fn1_KeyEnc1, offset l4);	// После обработки исключения передать управление на l4.
	}

	RaiseExceptionForKeyDecrypt(Fn1_KeyEnc2, NULL);	
	l2:	// Конец 1-го и начало 2-го регионов.
	RaiseExceptionForKeyEncrypt(Fn1_KeyEnc1, NULL);

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

	RaiseExceptionForKeyEncrypt(Fn1_KeyEnc2, NULL);
	l3:		// Конец 2-го региона.

	Fn1.status = hasp_logout(Fn1.handle);
	RemoveHandler;
	ExitThread(0);

	l4:		// Выход по ошибке при неудачном завершении hasp_login
	RemoveHandler;
	ExitThread(1);

	AsmKeyEncCodeMrk(Fn1_KeyEnc1, l1, l2, Main);		// Encrypt-маркер участка кода между метками l1 и l2.
	AsmKeyEncCodeMrk(Fn1_KeyEnc2, l2, l3, Fn1);			// Encrypt-маркер участка кода между метками l2 и l3.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура генерирует псевдо-случайные числа в диапазоне [128; 255] с контролем ошибок.
//  Все входящие в диапазон значения выводятся зеленым цветом, все прочие - красным. Так же, 
//  в процедуре реализована реакция на "редкое событие" - монотонно возрастающая последовательность
//  из трёх чисел подряд, отличающиеся друг от друга на единицу, последнее из них выводится синим цветом.

#define F2_Feature 2								// Номер фичи ключа, которую будет использовать функция.

HaspSession Fn2 = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F2_Feature};

KeyEncCodeDsc  Fn2_KeyEnc1 = {(PHaspSession)0x78563412};	// Encrypt-дескриптор участка кода между метками l1 и l2.
KeyEncCodeDsc  Fn2_KeyEnc2 = {(PHaspSession)0x78563412};	// Encrypt-дескриптор участка кода между метками l2 и l3.

void Function2(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z_min = 0x0080, z_max = 0x00FF, z_xor = 0xFF00, z_and = 0x00FF;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	UCHAR vc[sizeof(vendor_code)];
	
	InstallHandler(SEH_Handler);
	
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
	RemoveHandler;
	ExitThread(0);

	l4:		// Выход при отсутствии лицензии на работу функции.
	RemoveHandler;
	ExitThread(1);

	AsmKeyEncCodeMrk(Fn2_KeyEnc1, l1, l2, Main);	// Encrypt-маркер участка кода между метками l1 и l2.
	AsmKeyEncCodeMrk(Fn2_KeyEnc2, l2, l3, Fn2);		// Encrypt-маркер участка кода между метками l2 и l3.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура выполняет фоновый опрос ключа с указанным интервалом. Строковые параметры,
//	позволяющие обнаружить процедуру через перекрестные ссылки (scope, format и vendorcode),
//  зашифрованы и расшифровываются непосредственно перед вызовом hasp_get_info(), после чего
//  снова зашифровываются.

CstEncCodeDsc KBChk_CstEnc = {(PBYTE)0x78563412};		// Encrypt-дескриптор участка кода между метками l1 и l2.

void KeyBackgroundChk(PVOID hwnd) {
	HANDLE hMsg = INVALID_HANDLE_VALUE;
	DWORD hMsgState = NULL;
	char *info = 0;
	hasp_status_t status;
	UCHAR vc[sizeof(vendor_code)];
	
	// Копируем зашифрованный вендор-код в локальную переменную.
	CopyMemory(vc, vendor_code, sizeof(vc));

	while(TRUE) {
		RaiseExceptionForCustomDecrypt(KBChk_CstEnc, NULL);	
		l1:			// Начало региона.

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

		RaiseExceptionForCustomEncrypt(KBChk_CstEnc, NULL);	
		l2:			// Конец региона.

		Sleep(CheckKeyTimeout);
	}
	ExitThread(0);

	AsmCstEncCodeMrk(KBChk_CstEnc, l1, l2);		// Encrypt-маркер участка кода между метками l1 и l2.
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
//  Внутрипоточный SEH-обработчик исключительной ситуации.
EXCEPTION_DISPOSITION __cdecl SEH_Handler(struct _EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame,
                                          struct _CONTEXT *ContextRecord, void *DispatcherContext) {
	// Отладочная печать.
/*	MsgBox("SEH", MB_OK, "Exception Code\t %.8X\nException Address\t %.8X\nInvalid Instruction\t %X", 
		    ExceptionRecord->ExceptionCode, ExceptionRecord->ExceptionAddress, 
			*(USHORT *)ExceptionRecord->ExceptionAddress);
*/

	// Получаем доступ к структуре-описателю зашифрованного региона. Её адрес лежит в операнде инструкции,
	// следующей за двухбайтовой командой, вызвавшей исключительную ситуацию.
	PRaiseExcept   exception  = (PRaiseExcept)ExceptionRecord->ExceptionAddress;
	PKeyEncCodeDsc descriptor = (PKeyEncCodeDsc)exception->DescriptorAddr;
	
	// Если есть активные аппаратные точки останова, делаем невозможным штатное завершение криптографических
	// операций над текущим регионом путем внесения искажений во входные данные процедур расшифрования/зашифрования,
	// а именно - "портим" значение длины текущего региона в его дескрипторе. Благодаря явно выраженному лавинному
	// эффекту AES, это приведет к неправильному криптографичекому преобразованию текущего региона.
	descriptor->Length += HardwareBPFlag(ContextRecord);
	
	switch(exception->InvalidOpCode) {
		
		// Расшифрование региона через ключ.
		case KeyDecInvalidOpCode: 
			// Коррекция точки входа.
			if(exception->SafeEIPAddr == NULL) ContextRecord->Eip += sizeof(RaiseExcept);
				else ContextRecord->Eip = exception->SafeEIPAddr;
			KeyDec(descriptor);
			break;
			
		// Зашифрование региона через ключ.
		case KeyEncInvalidOpCode: 
			// Коррекция точки входа.
			if(exception->SafeEIPAddr == NULL) ContextRecord->Eip += sizeof(RaiseExcept); 
				else ContextRecord->Eip = exception->SafeEIPAddr;
			KeyEnc(descriptor);
			break;
			
		// Не "наше" исключение, передаем управление следующему обработчику в цепочке. 
		default: return ExceptionContinueSearch;	
	}
	return ExceptionContinueExecution;
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
	PCstEncCodeDsc descriptor = (PCstEncCodeDsc)exception->DescriptorAddr;

	switch(exception->InvalidOpCode) {
		
		// Расшифрование региона сторонним алгоритмом.
		case CstDecInvalidOpCode: 
			// Коррекция точки входа.
			if(exception->SafeEIPAddr == NULL) ExceptionInfo->ContextRecord->Eip += sizeof(RaiseExcept); 
				else ExceptionInfo->ContextRecord->Eip = exception->SafeEIPAddr;
			Dec(descriptor->Addr, descriptor->Length);
			break;
			
		// Зашифрование региона сторонним алгоритмом.
		case CstEncInvalidOpCode: 
			// Коррекция точки входа.
			if(exception->SafeEIPAddr == NULL) ExceptionInfo->ContextRecord->Eip += sizeof(RaiseExcept); 
				else ExceptionInfo->ContextRecord->Eip = exception->SafeEIPAddr;
			Enc(descriptor->Addr, descriptor->Length);
			break;

		// Не "наше" исключение, передаем управление следующему обработчику в цепочке. 
		default: 

			// Отладочная печать.
/*			MsgBox("VEH (others exceptions)", MB_OK, "Exception Code\t %.8X\nException Address\t %.8X\nInvalid Instruction\t %X", 
				    ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, 
					*(USHORT *)ExceptionInfo->ExceptionRecord->ExceptionAddress);
*/
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
//  Вызов MessageBox с форматным выводом строки.
DWORD MsgBox(PCHAR title, UINT style, PCHAR format, ...) {
	char buffer[1024];
	va_list arg_ptr;

	va_start(arg_ptr, format);
	vsprintf_s(buffer, sizeof(buffer), format, arg_ptr);
	va_end(arg_ptr);
	return MessageBox(NULL, buffer, title, style);
}
