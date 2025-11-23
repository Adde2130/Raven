#include <Windows.h>
#include <stdio.h>
#include "raven.h"

void _draw_box(HDC, int, int, int, int);

// RED = 255 119 121

LRESULT CALLBACK _main_window_proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam;
        RECT rect;
        GetClientRect(hwnd, &rect);
        HBRUSH hBrush = CreateSolidBrush(RGB(46, 48, 61));
        FillRect(hdc, &rect, hBrush);
        DeleteObject(hBrush);
        return 1; 
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        const char* text = "Hello, World!";
        HFONT hFont = CreateFont(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET,
                                    OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                    DEFAULT_PITCH | FF_SWISS, "Courier new");

        SelectObject(hdc, hFont);
        SetTextColor(hdc, RGB(255, 255, 255));
        SetBkMode(hdc, TRANSPARENT); 

        TextOut(hdc, 10, 10, text, strlen(text));

        CreateSolidBrush(RGB(0, 0, 0));
        _draw_box(hdc, 10, 10, 50, 50);

        DeleteObject(hFont);
        EndPaint(hwnd, &ps);
        return 0;
    }

    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void _register_window_class(){
    WNDCLASS wc = { };
    wc.lpfnWndProc = _main_window_proc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "Main Window";
    RegisterClass(&wc);
}

void open_main_window() {
    _register_window_class();
    
    HWND hwnd = CreateWindowEx(
        0,
        "Main Window",
        "Raven",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, NULL, GetModuleHandle(NULL), NULL
    );

    if (hwnd == NULL) {
        return;
    }

    ShowWindow(hwnd, SW_SHOW);
}

void _draw_box(HDC hdc, int x, int y, int width, int height) {
    MoveToEx(hdc, x, y, NULL);
    LineTo(hdc, width, y);
    LineTo(hdc, x, height);

    MoveToEx(hdc, width, height, NULL);
    LineTo(hdc, width, y);
    LineTo(hdc, x, height);
}

void window_msg_loop() {
    MSG msg = {0};
    while( GetMessage(&msg, NULL, 0, 0) ){
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

DWORD WINAPI window_monitor_thread(){
    open_main_window();
    window_msg_loop();
    return 0;
}

uint8_t raven_listen(const char* function_name, int arg_count, ...) {
    va_list args;
    va_start(args, arg_count);
    if(arg_count % 2)
        return 1;

    char** param_values = malloc(arg_count * sizeof(char*));
    
    for(int i = 0; i < arg_count / 2; i++) {
        RavenType type = va_arg(args, RavenType);
        switch(type){
        case TYPE_BYTE: {
            uint8_t value = va_arg(args, uint8_t);
            param_values[i] = malloc(256);
            sprintf_s(param_values[i], 256, "");
        }
        case TYPE_STRING:
        case TYPE_INT16:
        case TYPE_INT32:
        case TYPE_INT64:
        case TYPE_POINTER:
        default:
            break;
        }
    }
}

