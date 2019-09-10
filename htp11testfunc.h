#ifndef HTP11TESTFUNC_H
#define HTP11TESTFUNC_H

#include <QString>
#ifdef Q_OS_WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "cryptoki.h"
#include "mainwindow.h"

class HTP11Testfunc
{
public:

    int g_nSkfInitFlag ;
    int g_nP11InitFlag ;

    CK_FUNCTION_LIST_PTR g_P11_FuncList ;
#ifdef Q_OS_WIN32
    HMODULE p11Module;
#else
    void* g_handle;
#endif
    HTP11Testfunc();
    int QtrToChar(QString srcstr, char *desstr);
    int Load_Pkcs11_Lib(const char *dllName);
    int load_p11(const char *dllName);
    void DeleteBlankPad(char *string);
#if 0
    int  Haitai_GenRSAKeyPair(CK_SESSION_HANDLE handle, unsigned long keyspec, char *pszContainer);
#endif
};

#endif // HTP11TESTFUNC_H
