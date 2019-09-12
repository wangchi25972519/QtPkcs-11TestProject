#include "htp11testfunc.h"
#include <QMessageBox>

HTP11Testfunc::HTP11Testfunc()
{
    g_nP11InitFlag = 0;
    g_nSkfInitFlag = 0;
}

int HTP11Testfunc::QtrToChar(QString srcstr, char *desstr)
{
    if(!desstr)
    {
        return -1;
    }

    QString  filename = srcstr;
    std::string str = filename.toStdString();
    const char* ch = str.c_str();
    strcpy(desstr, ch);

    return 0;
}

int HTP11Testfunc::Load_Pkcs11_Lib(const char *dllName)
{
    CK_RV(*dll_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
    char buffer[256] = {0};
    int rv = 0;

#ifdef Q_OS_WIN32
    p11Module = LoadLibraryA(dllName);
    if (!p11Module)
    {
        rv = GetLastError();
        sprintf(buffer, "LoadLibrary %s fail, rv = %d", dllName, rv);
        QMessageBox::information(NULL,"Warning", buffer, QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        return rv;
        //MessageBox(0, buffer, "Error", 0);
        //exit(1);
    }

    /*while(1);*/
    dll_get_function_list = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))GetProcAddress(p11Module, "C_GetFunctionList");
    if (dll_get_function_list)
        dll_get_function_list(&g_P11_FuncList);
    if (!g_P11_FuncList)
    {
        return -1;
    }
#else
    g_handle = dlopen(dllName, RTLD_LAZY);
    dll_get_function_list = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(g_handle, "C_GetFunctionList");
    if (dll_get_function_list)
        dll_get_function_list(&g_P11_FuncList);
    if(dll_get_function_list==NULL)
    {
        dlclose(g_handle);
        g_handle=NULL;
        return -1;
    }
#endif
    return 0;
}

int HTP11Testfunc::load_p11(const char *dllName)
{
    int rv = 0;

    if (g_nP11InitFlag)
    {
        return 0;
    }
    //Load_Pkcs11_Lib("C:\\Windows\\SysWOW64\\HtPkcs1120098.dll")
    rv = Load_Pkcs11_Lib(dllName);
    /*Load_Pkcs11_Lib("HtPkcs11.dll");*/

    g_nP11InitFlag = 1;
    return rv;
}

void HTP11Testfunc::DeleteBlankPad(char *string)
{
    char *p = strrchr(string, ' ');
    if (p)
    {
        while (*p == ' ')
        {
            *p = '\0';
            p--;
        }
    }
    return;
}
#if 0
int  HTP11Testfunc::Haitai_GenRSAKeyPair(CK_SESSION_HANDLE handle, unsigned long keyspec, char *pszContainer)
{
    CK_ULONG bits = 1024;
    CK_RV    Result = CKR_OK;
    CK_KEY_TYPE keytype = CKK_RSA;
    CK_BYTE truevalue = CK_TRUE;
    CK_BYTE falsevalue = CK_FALSE;

    int    dwRet = 0;

    CK_OBJECT_HANDLE PubHandle = 0;
    CK_OBJECT_HANDLE PriHandle = 0;
    unsigned char pubExponent[3] = {0x01, 0x00, 0x01};

    char szCertFileName[260] = {0};

    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0};

    char ckaid[256] = {0};

    CK_BYTE PubKey[256];
    CK_ULONG ulLen = 256;
    char szCertFile[2048] = {0};
    char szLocalPubFile[2048] = {0};

    CK_BYTE *pdata_1_value = NULL;
    CK_ULONG data_1_value_len = 10*1024;
    CK_BYTE data_2_value[10*1024] = {0};
    CK_ULONG data_2_value_len = 10*1024;

    CK_BYTE data_1_application[64] = {0};
    CK_BYTE data_1_object_id[64] = {0};

    CK_ATTRIBUTE pubAttrs[ 8 ] = {
        { CKA_TOKEN, &truevalue, sizeof(truevalue) },
        { CKA_PRIVATE, &falsevalue, sizeof(falsevalue) },
        { CKA_ENCRYPT, &truevalue, sizeof(truevalue) },
        { CKA_DECRYPT, &truevalue, sizeof(truevalue) },
        { CKA_PUBLIC_EXPONENT, &pubExponent, 3 },
        { CKA_MODULUS_BITS, &bits, sizeof(CK_ULONG) },
        /*{ CKA_LOCATION_ATTRIBUTES, &pubLoc, sizeof(pubLoc)}*/
        { CKA_LABEL, pszContainer, strlen(pszContainer) },
        { CKA_ID, ckaid, strlen(pszContainer)+2 }
    };
    CK_ATTRIBUTE privAttrs[ 7 ] = {
        { CKA_KEY_TYPE, &keytype, sizeof(keytype) },
        { CKA_TOKEN, &truevalue, sizeof(truevalue) },
        { CKA_PRIVATE, &truevalue, sizeof(truevalue) },
        { CKA_DECRYPT, &truevalue, sizeof(truevalue) },
        { CKA_ENCRYPT, &truevalue, sizeof(truevalue) },
        /*{ CKA_LOCATION_ATTRIBUTES, &priLoc, sizeof(priLoc)}*/
        { CKA_LABEL, pszContainer, strlen(pszContainer) },
        { CKA_ID, ckaid, strlen(pszContainer)+2 }
    };

    dwRet = (g_P11_FuncList->C_GenerateKeyPair)(handle, &mech, pubAttrs, 8, privAttrs, 7, &PubHandle, &PriHandle);
    if(dwRet)
    {
        //ui->textEdit->append(QString().sprintf("C_GenerateKeyPair ERR, dwRet = 0x%08x", dwRet));
        //goto ERR;
    }
}
#endif
