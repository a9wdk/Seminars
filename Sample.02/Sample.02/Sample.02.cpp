//*****************************************************************************
// (v02) Простая защита + фоновый опрос ключа. 
//
// Автор - Сергей Усков (a9wdk@yandex.ru, Telegram: @a9wdk)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>
   
#include "resource.h"
#include "hasp_api.h"
#include "hasp_vcode.h"

#define MAX_LOADSTRING 100

#define xGap 50				// Расстояние между соседними символами при выводе текста.
#define yGap 20				// Расстояние между соседними строками при выводе текста.

#define CheckTimeout 500	// Интервал, с которым производится фоновый опрос ключа.

#define int3	__asm int 3		\
				__asm nop

//////////////////////////////////////////////////////////////////////////////////////////////
// Структура-описатель сессии с ключом.

struct HaspSession {
	hasp_handle_t	handle;		// Хендл текущей сессии с ключом.
	hasp_status_t	status;		// Код ошибки последней операции.
	hasp_feature_t	feature;	// Фича для текущей сессии.
};

//////////////////////////////////////////////////////////////////////////////////////////////
// Глобальные переменные.

HINSTANCE hInst;							
HMENU hMainMenu;
TCHAR szTitle[MAX_LOADSTRING];				
TCHAR szWindowClass[MAX_LOADSTRING];		

HANDLE hF1Thread, hF2Thread, hKeyBackgroundChk;		// Идентификаторы запущенных потоков
BOOL f1Terminate = TRUE, f2Terminate = TRUE;		// Признаки завершения потоков
BOOL HaspKeyPresent = FALSE;						// Флаг устанавливается потоком, выполняющим фоновый опрос ключа

HaspSession Main = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, HASP_DEFAULT_FID};

//////////////////////////////////////////////////////////////////////////////////////////////

ATOM				RegisterWindowClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
void				Function1(PVOID hwnd);
void				Function2(PVOID hwnd);
void				KeyBackgroundChk(PVOID hwnd);
void				KeyBackgroundChkMsg(PVOID err);
DWORD				MsgBox(PCHAR title, UINT style, PCHAR format, ...);

//////////////////////////////////////////////////////////////////////////////////////////////

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	MSG msg;
	HWND hWnd;
	HACCEL hAccelTable;

	// Сохраняем идентификатор приложения в глобальной переменной.
	hInst = hInstance;

	// Выполняем Login на Feature ID 0, проверка результата будет выполнена в InitInstance().
	Main.status = hasp_login(Main.feature, vendor_code, &Main.handle);

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
	hKeyBackgroundChk = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChk, (LPVOID)hWnd, 0, NULL);
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
	if(Main.status != HASP_STATUS_OK) 
		MsgBox("Feature ID = 0", MB_SYSTEMMODAL | MB_ICONERROR, "Login error #%d", Main.status);
	
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
			break;

		case WM_DESTROY:
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
void Function1(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z_min = 0x0000, z_max = 0x0080, z_xor = 0xFF00, z_and = 0x00FF;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];

	while(!f1Terminate) {
		hDC = GetDC((HWND)hwnd);
		GetWindowRect((HWND)hwnd, &rect);
		delay = 50;
		
		// Если нет ключа - никакой полезной работы не делаем.
		if(!HaspKeyPresent) { 
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
	ExitThread(0);
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура генерирует псевдо-случайные числа в диапазоне [128; 255] с контролем ошибок.
//  Все входящие в диапазон значения выводятся зеленым цветом, все прочие - красным. Так же, 
//  в процедуре реализована реакция на "редкое событие" - монотонно возрастающая последовательность
//  из трёх чисел подряд, отличающиеся друг от друга на единицу, последнее из них выводится синим цветом.
void Function2(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z_min = 0x0080, z_max = 0x00FF, z_xor = 0xFF00, z_and = 0x00FF;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	
	while(!f2Terminate) {
		hDC = GetDC((HWND)hwnd);
		GetWindowRect((HWND)hwnd, &rect);
		delay = 50;
		
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
	ExitThread(0);
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура выполняет фоновый опрос ключа с указанным интервалом.
void KeyBackgroundChk(PVOID hwnd) {
	HANDLE hMsg = INVALID_HANDLE_VALUE;
	DWORD hMsgState = 0;
	PCHAR info = NULL;
	hasp_status_t status;
	
	CCHAR *scope = 
		"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"
		"<haspscope>"
		"    <hasp type=\"HASP-HL\" />"
		"</haspscope>";
	
	CCHAR *format = 
		"<haspformat root=\"hasp_info\">"
		"    <feature>"
		"       <attribute name=\"id\" />"
		"       <attribute name=\"locked\" />"
		"       <attribute name=\"expired\" />"
		"       <attribute name=\"disabled\" />"
		"       <attribute name=\"usable\" />"
		"    </feature>"
		"</haspformat>";

	while(TRUE) {
		GetExitCodeThread(hMsg, &hMsgState);
		status = hasp_get_info(scope, format, vendor_code, &info);
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
		Sleep(CheckTimeout);
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
//  Вызов MessageBox с форматным выводом строки.
DWORD MsgBox(PCHAR title, UINT style, PCHAR format, ...) {
	char buffer[1024];
	va_list arg_ptr;
    
	va_start(arg_ptr, format);
	vsprintf_s(buffer, sizeof(buffer), format, arg_ptr);
    va_end(arg_ptr);
	return MessageBox(NULL, buffer, title, style);
}
