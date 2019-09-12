#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "htp11testfunc.h"
#include <QUuid>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_FullTestButton_clicked()
{
    int               dwRet = 0, i =0;
    char              dllpath[512] = {0};
    char              struserpin[512] = {0};
    char              buf[1024] = {0};

    CK_KEY_TYPE       keytype = CKK_RSA;
    CK_BYTE           truevalue = CK_TRUE;
    CK_BYTE           falsevalue = CK_FALSE;

    CK_ULONG          ulSlotCount = 0;
    CK_SLOT_ID_PTR    pSlotList;

    CK_TOKEN_INFO     tokenInfo = {0};

    HTP11Testfunc      p11func;
    CK_SESSION_HANDLE  TmpSession = NULL;

    QString filepath = ui->textEditPath->toPlainText();
    QString userpin  = ui->pintextEdit->toPlainText();

    //QTextCodec::setCodecForCStrings(QTextCodec::codecForName("UTF-8"));

    if(!filepath.length())
    {
        ui->textEdit->clear();
        ui->textEdit->setText("路径不能为空");
        return;
    }

    if(!userpin.length())
    {
        ui->textEdit->clear();
        ui->textEdit->setText("user pin不能为空");
        return;
    }

    dwRet = p11func.QtrToChar(filepath,dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("convert Char Err");
        return;
    }

    dwRet = p11func.QtrToChar(userpin,struserpin);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("convert Char Err");
        return;
    }

    qDebug() << dllpath;
    qDebug() << filepath;
    qDebug() << struserpin;

    dwRet = p11func.load_p11(dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("import dll err");
        return;
    }

    dwRet = (p11func.g_P11_FuncList->C_Initialize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Initialize ERR, dwRet = 0x%08x", dwRet));
        return;
    }

    ui->textEdit->append(QString().sprintf("C_Initialize sucessfully...\n"));

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, NULL_PTR, &ulSlotCount);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    if(!ulSlotCount)
    {
        ui->textEdit->append(QString().sprintf("NO Device"));
        goto ERR;
    }

    pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*ulSlotCount);

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, pSlotList, &ulSlotCount);
    if (dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    ui->textEdit->append(QString().sprintf("C_GetSlotList sucessfully...\n"));

    ui->textEdit->append(QString().sprintf("枚举到的设备个数为:%d", ulSlotCount));
    for(i = 0; i <ulSlotCount ;i++)
    {
        ui->textEdit->append(QString().sprintf("开始操作第 %d个设备...\n", i+1));

        dwRet = (p11func.g_P11_FuncList->C_GetTokenInfo)(pSlotList[i], &tokenInfo);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_GetTokenInfo ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_GetTokenInfo sucessfully...\n"));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.label, 32);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, label[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.model, 16);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, model[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.manufacturerID, 32);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, 厂商[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.serialNumber, 16);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, 设备序列号[%s]\n", i+1, buf));

        dwRet = (p11func.g_P11_FuncList->C_OpenSession)(pSlotList[i], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_OpenSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_OpenSession sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_Login)(TmpSession, CKU_USER, (CK_UTF8CHAR_PTR)struserpin, userpin.length());
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_Login ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_Login sucessfully...\n"));

        ui->textEdit->append(QString().sprintf("*********************************"));
        ui->textEdit->append(QString().sprintf("开始进行RSA相关测试"));
        ui->textEdit->append(QString().sprintf("*********************************\n"));

        QUuid id = QUuid::createUuid();
        QString strId = id.toString();

        unsigned char pubExponent[3] = {0x01, 0x00, 0x01};
        CK_ULONG      bits = 1024;

        char          pszContainer[1024] = {0};
        char          ckaid[256] = {0};

        CK_OBJECT_HANDLE PubHandle = 0;
        CK_OBJECT_HANDLE PriHandle = 0;

        p11func.QtrToChar(strId, pszContainer);

        sprintf(ckaid, "%s#1", pszContainer);

        CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0};

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

        dwRet = (p11func.g_P11_FuncList->C_GenerateKeyPair)(TmpSession, &mech, pubAttrs, 8, privAttrs, 7, &PubHandle, &PriHandle);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_GenerateKeyPair ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_GenerateKeyPair sucessfully...\n"));

        CK_MECHANISM mechanism ;
        mechanism.mechanism      = CKM_MD5;//
        mechanism.ulParameterLen = 0;
        mechanism.pParameter     = NULL;

        unsigned char szDigestData[1024] = {0};
        unsigned long pDigestLen = 1024;

        dwRet = (p11func.g_P11_FuncList->C_DigestInit)(TmpSession, &mechanism);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_DigestInit ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_DigestInit sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_DigestUpdate)(TmpSession, (CK_BYTE *)"ABCDEFG", 6);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_DigestUpdate ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_DigestUpdate sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_DigestFinal)(TmpSession, szDigestData, &pDigestLen);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_DigestFinal ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_DigestFinal sucessfully...\n"));
#if 0
        CK_OBJECT_CLASS objectclass = CKO_PRIVATE_KEY;
        CK_OBJECT_HANDLE prihandle[10];
        CK_ULONG ObjCount = 0;

        CK_ATTRIBUTE PriKeyAttr[] = {
            {CKA_CLASS, &objectclass, sizeof(objectclass)},
            {CKA_KEY_TYPE, &keytype, sizeof(keytype)},
            {CKA_TOKEN, &truevalue, sizeof (truevalue)},
            /*{CKA_LOCATION_ATTRIBUTES, &attrValue, sizeof(attrValue)}*/
        };

        dwRet = (p11func.g_P11_FuncList->C_FindObjectsInit)(TmpSession, PriKeyAttr, sizeof(PriKeyAttr)/sizeof(CK_ATTRIBUTE));
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsInit ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsInit sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_FindObjects)(TmpSession, prihandle, sizeof(PriHandle)/sizeof(CK_OBJECT_HANDLE), &ObjCount);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjects ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        if(!ObjCount)
        {
            ui->textEdit->append(QString().sprintf("No private Object..."));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjects sucessfully...\n"));
#endif
        mechanism.mechanism      = CKM_SHA1_RSA_PKCS;//
        mechanism.ulParameterLen = 0;
        mechanism.pParameter     = NULL;

        CK_BYTE pSignedData[1024] = {0};
        CK_ULONG pSignedLen = 1024;

        dwRet = (p11func.g_P11_FuncList->C_SignInit)(TmpSession, &mechanism, PriHandle);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_SignInit ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_SignInit sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_Sign)(TmpSession, (CK_BYTE *)"ABCDEFG", 6, pSignedData, &pSignedLen);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_Sign ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        dwRet = (p11func.g_P11_FuncList->C_VerifyInit)(TmpSession, &mechanism, PubHandle);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_VerifyInit ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_VerifyInit sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_Verify)(TmpSession, (CK_BYTE *)"ABCDEFG", 6, pSignedData, pSignedLen);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_Verify ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_Verify sucessfully...\n"));

        mechanism.mechanism      = CKM_RSA_PKCS;//
        mechanism.ulParameterLen = 0;
        mechanism.pParameter     = NULL;

        memset(pSignedData, 0x00, sizeof(pSignedData));
        pSignedLen = 1024;

        dwRet = (p11func.g_P11_FuncList->C_EncryptInit)(TmpSession, &mechanism, PubHandle);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_EncryptInit ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_EncryptInit sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_Encrypt)(TmpSession, (CK_BYTE *)"HaiTai123", 9, pSignedData, &pSignedLen);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_Encrypt ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_Encrypt sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_DecryptInit)(TmpSession, &mechanism, PriHandle);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_DecryptInit ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_DecryptInit sucessfully...\n"));

        CK_BYTE pSrcData[1024] = {0};
        CK_ULONG pSrcLen = 1024;

        dwRet = (p11func.g_P11_FuncList->C_Decrypt)(TmpSession, (CK_BYTE *)pSignedData, pSignedLen, pSrcData, &pSrcLen);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_Decrypt ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_Decrypt sucessfully.....\n"));

#if 0
        dwRet = (p11func.g_P11_FuncList->C_FindObjectsFinal)(TmpSession);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsFinal ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsFinal sucessfully...\n"));
#endif
        dwRet = (p11func.g_P11_FuncList->C_DestroyObject)(TmpSession, PriHandle);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_DestroyObject ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_DestroyObject sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_DestroyObject)(TmpSession, PubHandle);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_DestroyObject ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_DestroyObject sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_CloseSession)(TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_CloseSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }
        TmpSession = NULL;

        ui->textEdit->append(QString().sprintf("C_CloseSession sucessfully...\n"));
    }
ERR:
    if(TmpSession)
    {
        dwRet = (p11func.g_P11_FuncList->C_CloseSession)(TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_CloseSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_CloseSession sucessfully...\n"));
    }

    dwRet = (p11func.g_P11_FuncList->C_Finalize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Finalize ERR, dwRet = 0x%08x", dwRet));
    }

    ui->textEdit->append(QString().sprintf("C_Finalize sucessfully...\n"));
}

void MainWindow::on_pathchoiceButton_clicked()
{
    QFileInfo         fileinfo;
    QString           file_full = QFileDialog::getOpenFileName(this);

    if (!file_full.isEmpty())
    {
        fileinfo  = QFileInfo(file_full);
    }

    ui->textEditPath->clear();
    ui->textEditPath->setText(fileinfo.absoluteFilePath());

    //    dwRet = LoadDeviceFun(dllpath);
    //    if(dwRet)
    //    {
    //        ui->textEdit->clear();
    //        ui->textEdit->setText("import dll err");
    //    }

    //    ui->textEdit->append("1");
    //    ui->textEdit->append("2");

}

void MainWindow::on_filepushButton_clicked()
{
    int               dwRet = 0, i =0;
    char              dllpath[512] = {0};
    char              buf[1024] = {0};

    CK_OBJECT_CLASS   objClass = CKO_DATA;
    CK_OBJECT_HANDLE  hCKObj ;
    CK_ULONG          ObjCount = 0;

    CK_ULONG          ulSlotCount = 0;
    CK_SLOT_ID_PTR    pSlotList;

    CK_TOKEN_INFO     tokenInfo = {0};

    CK_BYTE           truevalue = CK_TRUE;

    CK_UTF8CHAR label[] = "testztc";
    CK_UTF8CHAR application[] = "An application";
    CK_BYTE data[] = "Sample data";


    HTP11Testfunc      p11func;
    CK_SESSION_HANDLE  TmpSession = NULL;

    QString filepath = ui->textEditPath->toPlainText();

    if(!filepath.length())
    {
        ui->textEdit->clear();
        ui->textEdit->setText("路径不能为空");
        return;
    }

    dwRet = p11func.QtrToChar(filepath,dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("convert Char Err");
        return;
    }

    qDebug() << dllpath;
    qDebug() << filepath;

    dwRet = p11func.load_p11(dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("import dll err");
        return;
    }

    dwRet = (p11func.g_P11_FuncList->C_Initialize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Initialize ERR, dwRet = 0x%08x", dwRet));
        //ui->textEdit->setText(QString().sprintf("C_Initialize ERR, dwRet = 0x%08x", dwRet));
        return;
    }

    ui->textEdit->append(QString().sprintf("C_Initialize sucessfully...\n"));

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, NULL_PTR, &ulSlotCount);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    if(!ulSlotCount)
    {
        ui->textEdit->append(QString().sprintf("NO Device"));
        goto ERR;
    }

    pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*ulSlotCount);

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, pSlotList, &ulSlotCount);
    if (dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    ui->textEdit->append(QString().sprintf("C_GetSlotList sucessfully...\n"));

    //QTextCodec::setCodecForCStrings(QTextCodec::codecForName("UTF-8"));

    ui->textEdit->append(QString().sprintf("枚举到的设备个数为:%d", ulSlotCount));
    for(i = 0; i <ulSlotCount ;i++)
    {
        ui->textEdit->append(QString().sprintf("开始操作第 %d个设备...\n", i+1));

        dwRet = (p11func.g_P11_FuncList->C_GetTokenInfo)(pSlotList[i], &tokenInfo);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_GetTokenInfo ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_GetTokenInfo sucessfully...\n"));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.label, 32);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, label[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.model, 16);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, model[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.manufacturerID, 32);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, 厂商[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.serialNumber, 16);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, 设备序列号[%s]\n", i+1, buf));

        dwRet = (p11func.g_P11_FuncList->C_OpenSession)(pSlotList[i], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_OpenSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_OpenSession sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_Login)(TmpSession, CKU_USER, (CK_UTF8CHAR_PTR)"111111", 6);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_Login ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }
        ui->textEdit->append(QString().sprintf("C_Login sucessfully...\n"));

        ui->textEdit->append(QString().sprintf("*********************************"));
        ui->textEdit->append(QString().sprintf("开始进行CKO_DATA对象CREATE,WRITE相关测试"));
        ui->textEdit->append(QString().sprintf("*********************************\n"));

        CK_ATTRIBUTE templateDataObject[] = {
            {CKA_CLASS, &objClass, sizeof(objClass)},
            {CKA_TOKEN, &truevalue, sizeof (truevalue)},
            {CKA_LABEL, label, sizeof(label)-1}
            /*{CKA_LOCATION_ATTRIBUTES, &attrValue, sizeof(attrValue)}*/
        };

        dwRet = (p11func.g_P11_FuncList->C_FindObjectsInit)(TmpSession, templateDataObject, sizeof(templateDataObject)/sizeof(CK_ATTRIBUTE));
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsInit ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsInit sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_FindObjects)(TmpSession, &hCKObj, sizeof(hCKObj)/sizeof(CK_OBJECT_HANDLE), &ObjCount);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjects ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        if(!ObjCount)
        {
            ui->textEdit->append(QString().sprintf("No CKO_DATA Object...\n"));
            //goto ERR;
        }
        else
        {
            dwRet = (p11func.g_P11_FuncList->C_DestroyObject)(TmpSession, hCKObj);
            if(dwRet)
            {
                ui->textEdit->append(QString().sprintf("C_DestroyObject ERR, dwRet = 0x%08x", dwRet));
                goto ERR;
            }

            ui->textEdit->append(QString().sprintf("C_DestroyObject sucessfully...\n"));
        }

        ui->textEdit->append(QString().sprintf("C_FindObjects sucessfully...\n"));

        CK_OBJECT_HANDLE hDataObject;

        CK_ATTRIBUTE templateDataObject1[] = {
            {CKA_CLASS, &objClass, sizeof(objClass)},
            {CKA_TOKEN, &truevalue, sizeof(truevalue)},
            {CKA_LABEL, label, sizeof(label)-1},
            {CKA_PRIVATE, &truevalue, sizeof(truevalue)},
            {CKA_APPLICATION, application, sizeof(application)-1},
            {CKA_VALUE, data, sizeof(data)}
        };

        dwRet = (p11func.g_P11_FuncList->C_CreateObject)(TmpSession, templateDataObject1, sizeof(templateDataObject1)/sizeof(CK_ATTRIBUTE), &hDataObject);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_CreateObject ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_CreateObject sucessfully...\n"));

        CK_ATTRIBUTE objValue[] ={
            {CKA_VALUE, data, sizeof(data)}
        };

        dwRet = (p11func.g_P11_FuncList->C_SetAttributeValue)(TmpSession, hDataObject, objValue, sizeof(objValue) / sizeof(CK_ATTRIBUTE));
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_SetAttributeValue ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_SetAttributeValue sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_FindObjectsFinal)(TmpSession);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsFinal ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsFinal sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_CloseSession)(TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_CloseSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }
        TmpSession = NULL;

        ui->textEdit->append(QString().sprintf("C_CloseSession sucessfully...\n"));
    }

ERR:
    dwRet = (p11func.g_P11_FuncList->C_Finalize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Finalize ERR, dwRet = 0x%08x", dwRet));
    }

    ui->textEdit->append(QString().sprintf("C_Finalize sucessfully...\n"));
}


void MainWindow::on_readfilepushButton_clicked()
{
    int               dwRet = 0, i =0;
    char              dllpath[512] = {0};
    char              buf[1024] = {0};

    CK_OBJECT_CLASS   objClass = CKO_DATA;
    CK_OBJECT_HANDLE  hCKObj ;
    CK_ULONG          ObjCount = 0;

    CK_ULONG          ulSlotCount = 0;
    CK_SLOT_ID_PTR    pSlotList;

    CK_TOKEN_INFO     tokenInfo = {0};

    CK_BYTE           truevalue = CK_TRUE;
    CK_BYTE           falsevalue = CK_FALSE;

    CK_UTF8CHAR label[] = "testztc";
    CK_UTF8CHAR application[] = "An application";
    CK_BYTE data[] = "Sample data";


    HTP11Testfunc      p11func;
    CK_SESSION_HANDLE  TmpSession = NULL;

    QString filepath = ui->textEditPath->toPlainText();

    if(!filepath.length())
    {
        ui->textEdit->clear();
        ui->textEdit->setText("路径不能为空");
        return;
    }

    dwRet = p11func.QtrToChar(filepath,dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("convert Char Err");
        return;
    }

    qDebug() << dllpath;
    qDebug() << filepath;

    dwRet = p11func.load_p11(dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("import dll err");
        return;
    }

    dwRet = (p11func.g_P11_FuncList->C_Initialize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Initialize ERR, dwRet = 0x%08x", dwRet));
        //ui->textEdit->setText(QString().sprintf("C_Initialize ERR, dwRet = 0x%08x", dwRet));
        return;
    }

    ui->textEdit->append(QString().sprintf("C_Initialize sucessfully...\n"));

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, NULL_PTR, &ulSlotCount);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    if(!ulSlotCount)
    {
        ui->textEdit->append(QString().sprintf("NO Device"));
        goto ERR;
    }

    pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*ulSlotCount);

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, pSlotList, &ulSlotCount);
    if (dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    ui->textEdit->append(QString().sprintf("C_GetSlotList sucessfully...\n"));

    //QTextCodec::setCodecForCStrings(QTextCodec::codecForName("UTF-8"));

    ui->textEdit->append(QString().sprintf("枚举到的设备个数为:%d", ulSlotCount));
    for(i = 0; i <ulSlotCount ;i++)
    {
        ui->textEdit->append(QString().sprintf("开始操作第 %d个设备...\n", i+1));

        dwRet = (p11func.g_P11_FuncList->C_GetTokenInfo)(pSlotList[i], &tokenInfo);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_GetTokenInfo ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_GetTokenInfo sucessfully...\n"));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.label, 32);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, label[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.model, 16);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, model[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.manufacturerID, 32);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, 厂商[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.serialNumber, 16);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, 设备序列号[%s]\n", i+1, buf));

        dwRet = (p11func.g_P11_FuncList->C_OpenSession)(pSlotList[i], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_OpenSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_OpenSession sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_Login)(TmpSession, CKU_USER, (CK_UTF8CHAR_PTR)"111111", 6);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_Login ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }
        ui->textEdit->append(QString().sprintf("C_Login sucessfully...\n"));

        ui->textEdit->append(QString().sprintf("*********************************"));
        ui->textEdit->append(QString().sprintf("开始进行CKO_DATA对象READ相关测试"));
        ui->textEdit->append(QString().sprintf("*********************************\n"));

        CK_ATTRIBUTE templateDataObject[] = {
            {CKA_CLASS, &objClass, sizeof(objClass)},
            {CKA_TOKEN, &truevalue, sizeof (truevalue)},
            {CKA_LABEL, label, sizeof(label)-1}
            /*{CKA_LOCATION_ATTRIBUTES, &attrValue, sizeof(attrValue)}*/
        };

        dwRet = (p11func.g_P11_FuncList->C_FindObjectsInit)(TmpSession, templateDataObject, sizeof(templateDataObject)/sizeof(CK_ATTRIBUTE));
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsInit ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsInit sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_FindObjects)(TmpSession, &hCKObj, sizeof(hCKObj)/sizeof(CK_OBJECT_HANDLE), &ObjCount);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjects ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        if(!ObjCount)
        {
            ui->textEdit->append(QString().sprintf("No CKO_DATA Object...\n"));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjects sucessfully...\n"));

        CK_ATTRIBUTE objValue1[] ={
            {CKA_VALUE, NULL, 0}
        };

        dwRet = (p11func.g_P11_FuncList->C_GetAttributeValue)(TmpSession, hCKObj, objValue1, sizeof(objValue1) / sizeof(CK_ATTRIBUTE));
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_GetAttributeValue ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_GetAttributeValue sucessfully...\n"));

        objValue1[0].pValue =(CK_BYTE_PTR)malloc(objValue1[0].ulValueLen);

        dwRet = (p11func.g_P11_FuncList->C_GetAttributeValue)(TmpSession, hCKObj, objValue1, sizeof(objValue1) / sizeof(CK_ATTRIBUTE));
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_GetAttributeValue ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_GetAttributeValue sucessfully...\n"));

        ui->textEdit->append(QString().sprintf("value = %s\n", objValue1[0].pValue));

        dwRet = (p11func.g_P11_FuncList->C_FindObjectsFinal)(TmpSession);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsFinal ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsFinal sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_CloseSession)(TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_CloseSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }
        TmpSession = NULL;

        ui->textEdit->append(QString().sprintf("C_CloseSession sucessfully...\n"));
    }

ERR:
    dwRet = (p11func.g_P11_FuncList->C_Finalize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Finalize ERR, dwRet = 0x%08x", dwRet));
    }

    ui->textEdit->append(QString().sprintf("C_Finalize sucessfully...\n"));
}

void MainWindow::on_objectpushButton_clicked()
{
    int               dwRet = 0, i =0;
    char              dllpath[512] = {0};
    char              buf[1024] = {0};

    CK_OBJECT_CLASS   objClass = CKO_DATA;
    CK_OBJECT_CLASS   priobjClass = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS   pubobjClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS   certobjClass = CKO_CERTIFICATE;
    CK_OBJECT_HANDLE  hCKObj[10];
    CK_ULONG          ObjCount = 0;

    CK_ULONG          ulSlotCount = 0;
    CK_SLOT_ID_PTR    pSlotList;

    CK_TOKEN_INFO     tokenInfo = {0};

    CK_BYTE           truevalue = CK_TRUE;

    char              struserpin[512] = {0};

//    CK_UTF8CHAR label[] = "testztc";
//    CK_UTF8CHAR application[] = "An application";
//    CK_BYTE data[] = "Sample data";

    HTP11Testfunc      p11func;
    CK_SESSION_HANDLE  TmpSession = NULL;

    QString filepath = ui->textEditPath->toPlainText();
    QString userpin  = ui->pintextEdit->toPlainText();

    if(!filepath.length())
    {
        ui->textEdit->clear();
        ui->textEdit->setText("路径不能为空");
        return;
    }

    if(!userpin.length())
    {
        ui->textEdit->clear();
        ui->textEdit->setText("路径不能为空");
        return;
    }

    dwRet = p11func.QtrToChar(filepath,dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("convert Char Err");
        return;
    }

    dwRet = p11func.QtrToChar(userpin,struserpin);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("convert Char Err");
        return;
    }

    qDebug() << dllpath;
    qDebug() << filepath;

    dwRet = p11func.load_p11(dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("import dll err");
        return;
    }

    dwRet = (p11func.g_P11_FuncList->C_Initialize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Initialize ERR, dwRet = 0x%08x", dwRet));
        //ui->textEdit->setText(QString().sprintf("C_Initialize ERR, dwRet = 0x%08x", dwRet));
        return;
    }

    ui->textEdit->append(QString().sprintf("C_Initialize sucessfully...\n"));

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, NULL_PTR, &ulSlotCount);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    if(!ulSlotCount)
    {
        ui->textEdit->append(QString().sprintf("NO Device"));
        goto ERR;
    }

    pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*ulSlotCount);

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, pSlotList, &ulSlotCount);
    if (dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    ui->textEdit->append(QString().sprintf("C_GetSlotList sucessfully...\n"));

    //QTextCodec::setCodecForCStrings(QTextCodec::codecForName("UTF-8"));

    ui->textEdit->append(QString().sprintf("枚举到的设备个数为:%d", ulSlotCount));
    for(i = 0; i <ulSlotCount ;i++)
    {
        ui->textEdit->append(QString().sprintf("开始操作第 %d个设备...\n", i+1));

        dwRet = (p11func.g_P11_FuncList->C_GetTokenInfo)(pSlotList[i], &tokenInfo);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_GetTokenInfo ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_GetTokenInfo sucessfully...\n"));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.label, 32);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, label[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.model, 16);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, model[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.manufacturerID, 32);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, 厂商[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.serialNumber, 16);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, 设备序列号[%s]\n", i+1, buf));

        dwRet = (p11func.g_P11_FuncList->C_OpenSession)(pSlotList[i], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_OpenSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_OpenSession sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_Login)(TmpSession, CKU_USER, (CK_UTF8CHAR_PTR)struserpin, userpin.length());
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_Login ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }
        ui->textEdit->append(QString().sprintf("C_Login sucessfully...\n"));

        ui->textEdit->append(QString().sprintf("*********************************"));
        ui->textEdit->append(QString().sprintf("开始进行枚举对象相关测试"));
        ui->textEdit->append(QString().sprintf("*********************************\n"));

        CK_ATTRIBUTE templateDataObject[] = {
            {CKA_CLASS, &objClass, sizeof(objClass)},
            {CKA_TOKEN, &truevalue, sizeof (truevalue)}
            /*{CKA_LOCATION_ATTRIBUTES, &attrValue, sizeof(attrValue)}*/
        };

        //hCKObj = NULL;

        dwRet = (p11func.g_P11_FuncList->C_FindObjectsInit)(TmpSession, templateDataObject, sizeof(templateDataObject)/sizeof(CK_ATTRIBUTE));
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsInit ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsInit sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_FindObjects)(TmpSession, hCKObj, 10, &ObjCount);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjects ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        if(!ObjCount)
        {
            ui->textEdit->append(QString().sprintf("No CKO_PRIVATE Object...\n"));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjects sucessfully...\n"));

        ui->textEdit->append(QString().sprintf("枚举CKO_DATA对象个数:%d\n", ObjCount));

        CK_ATTRIBUTE objValue1[] ={
            {CKA_LABEL, NULL, 0}
        };

        for(i = 0; i<ObjCount; i++)
        {
            dwRet = (p11func.g_P11_FuncList->C_GetAttributeValue)(TmpSession, hCKObj[i], objValue1, sizeof(objValue1) / sizeof(CK_ATTRIBUTE));
            if (dwRet)
            {
                ui->textEdit->append(QString().sprintf("C_GetAttributeValue ERR, dwRet = 0x%08x", dwRet));
                goto ERR;
            }

            ui->textEdit->append(QString().sprintf("C_GetAttributeValue sucessfully...\n"));

            objValue1[0].pValue =(CK_BYTE_PTR)malloc(objValue1[0].ulValueLen);
            //objValue2[1].pValue =(CK_BYTE_PTR)malloc(objValue2[1].ulValueLen);

            dwRet = (p11func.g_P11_FuncList->C_GetAttributeValue)(TmpSession, hCKObj[i], objValue1, sizeof(objValue1) / sizeof(CK_ATTRIBUTE));
            if (dwRet)
            {
                ui->textEdit->append(QString().sprintf("C_GetAttributeValue ERR, dwRet = 0x%08x\n", dwRet));
                goto ERR;
            }

            ui->textEdit->append(QString().sprintf("C_GetAttributeValue sucessfully...\n"));

            ui->textEdit->append(QString().sprintf("CKA_LABLE:%s\n", objValue1[0].pValue));
        }

        dwRet = (p11func.g_P11_FuncList->C_FindObjectsFinal)(TmpSession);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsFinal ERR, dwRet = 0x%08x\n", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsFinal sucessfully...\n"));

        CK_ATTRIBUTE templatePrivateObject[] = {
            {CKA_CLASS, &priobjClass, sizeof(priobjClass)},
            {CKA_TOKEN, &truevalue, sizeof (truevalue)}
            /*{CKA_LOCATION_ATTRIBUTES, &attrValue, sizeof(attrValue)}*/
        };

        //hCKObj = NULL;

        dwRet = (p11func.g_P11_FuncList->C_FindObjectsInit)(TmpSession, templatePrivateObject, sizeof(templatePrivateObject)/sizeof(CK_ATTRIBUTE));
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsInit ERR, dwRet = 0x%08x\n", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsInit sucessfully...\n"));

        ObjCount = 0;

        dwRet = (p11func.g_P11_FuncList->C_FindObjects)(TmpSession, hCKObj, 10, &ObjCount);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjects ERR, dwRet = 0x%08x\n", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjects sucessfully...\n"));

        if(!ObjCount)
        {
            ui->textEdit->append(QString().sprintf("No CKo_PRIVATE Object...\n"));
            goto ERR;
        }
        else
        {
            ui->textEdit->append(QString().sprintf("枚举CKO_PRIVATE对象个数:%d\n", ObjCount));

            CK_ATTRIBUTE objValue2[] ={
                {CKA_LABEL, NULL, 0},
                {CKA_ID, NULL, 0}
            };

            for(i = 0; i< ObjCount; i++)
            {

                dwRet = (p11func.g_P11_FuncList->C_GetAttributeValue)(TmpSession, hCKObj[i], objValue2, sizeof(objValue2) / sizeof(CK_ATTRIBUTE));
                if (dwRet)
                {
                    ui->textEdit->append(QString().sprintf("C_GetAttributeValue ERR, dwRet = 0x%08x\n", dwRet));
                    goto ERR;
                }

                ui->textEdit->append(QString().sprintf("C_GetAttributeValue sucessfully...\n"));

                objValue2[0].pValue =(CK_BYTE_PTR)malloc(objValue2[0].ulValueLen+1);
                objValue2[1].pValue =(CK_BYTE_PTR)malloc(objValue2[1].ulValueLen+1);

                memset(objValue2[0].pValue, 0x00, objValue2[0].ulValueLen+1);
                memset(objValue2[1].pValue, 0x00, objValue2[1].ulValueLen+1);

                dwRet = (p11func.g_P11_FuncList->C_GetAttributeValue)(TmpSession, hCKObj[i], objValue2, sizeof(objValue2) / sizeof(CK_ATTRIBUTE));
                if (dwRet)
                {
                    ui->textEdit->append(QString().sprintf("C_GetAttributeValue ERR, dwRet = 0x%08x\n", dwRet));
                    goto ERR;
                }

                ui->textEdit->append(QString().sprintf("C_GetAttributeValue sucessfully...\n"));

                ui->textEdit->append(QString().sprintf("CKA_LABLE:%s\n", objValue2[0].pValue));
                ui->textEdit->append(QString().sprintf("CKA_ID:%s\n", objValue2[1].pValue));
            }

            dwRet = (p11func.g_P11_FuncList->C_FindObjectsFinal)(TmpSession);
            if(dwRet)
            {
                ui->textEdit->append(QString().sprintf("C_FindObjectsFinal ERR, dwRet = 0x%08x\n", dwRet));
                goto ERR;
            }

            ui->textEdit->append(QString().sprintf("C_FindObjectsFinal sucessfully...\n"));
        }

        CK_ATTRIBUTE templatePublicObject[] = {
            {CKA_CLASS, &pubobjClass, sizeof(pubobjClass)},
            {CKA_TOKEN, &truevalue, sizeof (truevalue)}
            /*{CKA_LOCATION_ATTRIBUTES, &attrValue, sizeof(attrValue)}*/
        };

        //hCKObj = NULL;

        dwRet = (p11func.g_P11_FuncList->C_FindObjectsInit)(TmpSession, templatePublicObject, sizeof(templatePublicObject)/sizeof(CK_ATTRIBUTE));
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsInit ERR, dwRet = 0x%08x\n", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsInit sucessfully...\n"));

        ObjCount = 0;

        dwRet = (p11func.g_P11_FuncList->C_FindObjects)(TmpSession, hCKObj, 10, &ObjCount);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjects ERR, dwRet = 0x%08x\n", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjects sucessfully...\n"));

        if(!ObjCount)
        {
            ui->textEdit->append(QString().sprintf("No CKO_PUBLIC Object...\n"));
//            goto ERR;
        }
        else
        {
            ui->textEdit->append(QString().sprintf("枚举CKO_PUBLIC对象个数:%d\n", ObjCount));

            CK_ATTRIBUTE objValue3[] ={
                {CKA_LABEL, NULL, 0},
                {CKA_ID, NULL, 0}
            };

            for(i = 0; i < ObjCount; i++)
            {
                dwRet = (p11func.g_P11_FuncList->C_GetAttributeValue)(TmpSession, hCKObj[i], objValue3, sizeof(objValue3) / sizeof(CK_ATTRIBUTE));
                if (dwRet)
                {
                    ui->textEdit->append(QString().sprintf("C_GetAttributeValue ERR, dwRet = 0x%08x\n", dwRet));
                    goto ERR;
                }

                ui->textEdit->append(QString().sprintf("C_GetAttributeValue sucessfully...\n"));

                objValue3[0].pValue =(CK_BYTE_PTR)malloc(objValue3[0].ulValueLen+1);
                objValue3[1].pValue =(CK_BYTE_PTR)malloc(objValue3[1].ulValueLen+1);

                memset(objValue3[0].pValue, 0x00, objValue3[0].ulValueLen+1);
                memset(objValue3[1].pValue, 0x00, objValue3[1].ulValueLen+1);

                dwRet = (p11func.g_P11_FuncList->C_GetAttributeValue)(TmpSession, hCKObj[i], objValue3, sizeof(objValue3) / sizeof(CK_ATTRIBUTE));
                if (dwRet)
                {
                    ui->textEdit->append(QString().sprintf("C_GetAttributeValue ERR, dwRet = 0x%08x\n", dwRet));
                    goto ERR;
                }

                ui->textEdit->append(QString().sprintf("C_GetAttributeValue sucessfully...\n"));

                ui->textEdit->append(QString().sprintf("CKA_LABLE:%s\n", objValue3[0].pValue));
                ui->textEdit->append(QString().sprintf("CKA_ID:%s\n", objValue3[1].pValue));
            }

            dwRet = (p11func.g_P11_FuncList->C_FindObjectsFinal)(TmpSession);
            if(dwRet)
            {
                ui->textEdit->append(QString().sprintf("C_FindObjectsFinal ERR, dwRet = 0x%08x\n", dwRet));
                goto ERR;
            }

            ui->textEdit->append(QString().sprintf("C_FindObjectsFinal sucessfully...\n"));
        }
        CK_ATTRIBUTE templateCertObject[] = {
            {CKA_CLASS, &certobjClass, sizeof(certobjClass)},
            {CKA_TOKEN, &truevalue, sizeof (truevalue)}
            /*{CKA_LOCATION_ATTRIBUTES, &attrValue, sizeof(attrValue)}*/
        };

        //hCKObj = NULL;
        dwRet = (p11func.g_P11_FuncList->C_FindObjectsInit)(TmpSession, templateCertObject, sizeof(templateCertObject)/sizeof(CK_ATTRIBUTE));
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjectsInit ERR, dwRet = 0x%08x\n", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjectsInit sucessfully...\n"));

        ObjCount = 0;

        dwRet = (p11func.g_P11_FuncList->C_FindObjects)(TmpSession, hCKObj, 10, &ObjCount);
        if(dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_FindObjects ERR, dwRet = 0x%08x\n", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_FindObjects sucessfully...\n"));

        if(!ObjCount)
        {
            ui->textEdit->append(QString().sprintf("No CKo_CERTIFECATE Object...\n"));
            goto ERR;
        }
        else
        {
            ui->textEdit->append(QString().sprintf("枚举CKO_CERTIFECATE对象个数:%d\n", ObjCount));

            CK_ATTRIBUTE objValue4[] ={
                {CKA_LABEL, NULL, 0},
                {CKA_ID, NULL, 0}
            };

            for(i = 0; i< ObjCount; i++)
            {
                dwRet = (p11func.g_P11_FuncList->C_GetAttributeValue)(TmpSession, hCKObj[i], objValue4, sizeof(objValue4) / sizeof(CK_ATTRIBUTE));
                if (dwRet)
                {
                    ui->textEdit->append(QString().sprintf("C_GetAttributeValue ERR, dwRet = 0x%08x\n", dwRet));
                    goto ERR;
                }

                ui->textEdit->append(QString().sprintf("C_GetAttributeValue sucessfully...\n"));

                objValue4[0].pValue =(CK_BYTE_PTR)malloc(objValue4[0].ulValueLen+1);
                objValue4[1].pValue =(CK_BYTE_PTR)malloc(objValue4[1].ulValueLen+1);

                memset(objValue4[0].pValue, 0x00, objValue4[0].ulValueLen+1);
                memset(objValue4[1].pValue, 0x00, objValue4[1].ulValueLen+1);

                dwRet = (p11func.g_P11_FuncList->C_GetAttributeValue)(TmpSession, hCKObj[i], objValue4, sizeof(objValue4) / sizeof(CK_ATTRIBUTE));
                if (dwRet)
                {
                    ui->textEdit->append(QString().sprintf("C_GetAttributeValue ERR, dwRet = 0x%08x\n", dwRet));
                    goto ERR;
                }

                ui->textEdit->append(QString().sprintf("C_GetAttributeValue sucessfully...\n"));

                ui->textEdit->append(QString().sprintf("CKA_LABLE:%s\n", objValue4[0].pValue));
                ui->textEdit->append(QString().sprintf("CKA_ID:%s\n", objValue4[1].pValue));
            }

            dwRet = (p11func.g_P11_FuncList->C_FindObjectsFinal)(TmpSession);
            if(dwRet)
            {
                ui->textEdit->append(QString().sprintf("C_FindObjectsFinal ERR, dwRet = 0x%08x\n", dwRet));
                goto ERR;
            }

            ui->textEdit->append(QString().sprintf("C_FindObjectsFinal sucessfully...\n"));
        }

        dwRet = (p11func.g_P11_FuncList->C_CloseSession)(TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_CloseSession ERR, dwRet = 0x%08x\n", dwRet));
            goto ERR;
        }
        TmpSession = NULL;

        ui->textEdit->append(QString().sprintf("C_CloseSession sucessfully...\n"));
    }

ERR:
    if(TmpSession)
    {
        dwRet = (p11func.g_P11_FuncList->C_CloseSession)(TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_CloseSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_CloseSession sucessfully...\n"));
    }

    dwRet = (p11func.g_P11_FuncList->C_Finalize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Finalize ERR, dwRet = 0x%08x\n", dwRet));
    }

    ui->textEdit->append(QString().sprintf("C_Finalize sucessfully...\n"));
}

void MainWindow::on_sympushButton_clicked()
{

}

void MainWindow::on_initpushButton_clicked()
{
    int               dwRet = 0, i =0;
    char              dllpath[512] = {0};

    CK_ULONG          ulSlotCount = 0;
    CK_SLOT_ID_PTR    pSlotList;

    HTP11Testfunc      p11func;

    char              szpLabel[256] = "HaiTaiWuDi";
    char              struserpin[512] = {0};

    QString userpin  = ui->pintextEdit->toPlainText();

    QString filepath = ui->textEditPath->toPlainText();

    if(!filepath.length())
    {
        ui->textEdit->clear();
        ui->textEdit->setText("路径不能为空");
        return;
    }

    dwRet = p11func.QtrToChar(filepath,dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("convert Char Err");
        return;
    }

    qDebug() << dllpath;
    qDebug() << filepath;

    dwRet = p11func.load_p11(dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("import dll err");
        return;
    }

    if(!userpin.length())
    {
        ui->textEdit->clear();
        ui->textEdit->setText("路径不能为空");
        return;
    }

    dwRet = p11func.QtrToChar(userpin,struserpin);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("convert Char Err");
        return;
    }

    dwRet = (p11func.g_P11_FuncList->C_Initialize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Initialize ERR, dwRet = 0x%08x", dwRet));
        return;
    }

    ui->textEdit->append(QString().sprintf("C_Initialize sucessfully...\n"));

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, NULL_PTR, &ulSlotCount);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    if(!ulSlotCount)
    {
        ui->textEdit->append(QString().sprintf("NO Device"));
        goto ERR;
    }

    pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*ulSlotCount);

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, pSlotList, &ulSlotCount);
    if (dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    ui->textEdit->append(QString().sprintf("C_GetSlotList sucessfully...\n"));

    //QTextCodec::setCodecForCStrings(QTextCodec::codecForName("UTF-8"));

    ui->textEdit->append(QString().sprintf("枚举到的设备个数为:%d", ulSlotCount));

    for(i = 0; i <ulSlotCount ;i++)
    {
        ui->textEdit->append(QString().sprintf("开始初始化第 %d个设备...\n", i+1));

        dwRet = (p11func.g_P11_FuncList->C_InitToken)(pSlotList[i], (CK_UTF8CHAR_PTR)struserpin, userpin.length(), (CK_UTF8CHAR_PTR)szpLabel);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_InitToken ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_InitToken sucessfully...\n"));
    }

ERR:
    dwRet = (p11func.g_P11_FuncList->C_Finalize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Finalize ERR, dwRet = 0x%08x", dwRet));
    }

    ui->textEdit->append(QString().sprintf("C_Finalize sucessfully...\n"));
}

void MainWindow::on_changepin_clicked()
{
    int               dwRet = 0, i =0;
    char              dllpath[512] = {0};
    char              buf[1024] = {0};

    CK_ULONG          ulSlotCount = 0;
    CK_SLOT_ID_PTR    pSlotList;

    CK_TOKEN_INFO     tokenInfo = {0};

    HTP11Testfunc      p11func;
    CK_SESSION_HANDLE  TmpSession = NULL;

    char              struserpin[512] = {0};
    char              strAdminPin[512] = {0};

    QString filepath = ui->textEditPath->toPlainText();
    QString userpin  = ui->pintextEdit->toPlainText();
    QString AdminPin  = ui->admintextEdit->toPlainText();

    if(!filepath.length())
    {
        ui->textEdit->clear();
        ui->textEdit->setText("路径不能为空");
        return;
    }

    if(!userpin.length())
    {
        ui->textEdit->clear();
        ui->textEdit->setText("路径不能为空");
        return;
    }

    dwRet = p11func.QtrToChar(filepath,dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("convert Char Err");
        return;
    }

    dwRet = p11func.QtrToChar(userpin,struserpin);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("convert Char Err");
        return;
    }

    qDebug() << dllpath;
    qDebug() << filepath;

    dwRet = p11func.load_p11(dllpath);
    if(dwRet)
    {
        ui->textEdit->clear();
        ui->textEdit->setText("import dll err");
        return;
    }

    dwRet = (p11func.g_P11_FuncList->C_Initialize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Initialize ERR, dwRet = 0x%08x", dwRet));
        return;
    }

    ui->textEdit->append(QString().sprintf("C_Initialize sucessfully...\n"));

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, NULL_PTR, &ulSlotCount);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    if(!ulSlotCount)
    {
        ui->textEdit->append(QString().sprintf("NO Device"));
        goto ERR;
    }

    pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*ulSlotCount);

    dwRet = (p11func.g_P11_FuncList->C_GetSlotList)(TRUE, pSlotList, &ulSlotCount);
    if (dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_GetSlotList ERR, dwRet = 0x%08x", dwRet));
        goto ERR;
    }

    ui->textEdit->append(QString().sprintf("C_GetSlotList sucessfully...\n"));

    //QTextCodec::setCodecForCStrings(QTextCodec::codecForName("UTF-8"));

    ui->textEdit->append(QString().sprintf("枚举到的设备个数为:%d", ulSlotCount));

    for(i = 0; i <ulSlotCount ;i++)
    {
        ui->textEdit->append(QString().sprintf("开始操作第 %d个设备...\n", i+1));

        dwRet = (p11func.g_P11_FuncList->C_GetTokenInfo)(pSlotList[i], &tokenInfo);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_GetTokenInfo ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_GetTokenInfo sucessfully...\n"));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.label, 32);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, label[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.model, 16);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, model[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.manufacturerID, 32);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, 厂商[%s]", i+1, buf));

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, tokenInfo.serialNumber, 16);
        p11func.DeleteBlankPad(buf);
        ui->textEdit->append(QString().sprintf("第 %d个设备, 设备序列号[%s]\n", i+1, buf));

        dwRet = (p11func.g_P11_FuncList->C_OpenSession)(pSlotList[i], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_OpenSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_OpenSession sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_SetPIN)(TmpSession, (CK_UTF8CHAR_PTR)struserpin, userpin.length(), (CK_UTF8CHAR_PTR)"22222222", 8);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_SetPIN ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_SetPIN sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_SetPIN)(TmpSession, (CK_UTF8CHAR_PTR)"22222222", 8, (CK_UTF8CHAR_PTR)struserpin, userpin.length());
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_SetPIN ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_SetPIN sucessfully...\n"));

        dwRet = (p11func.g_P11_FuncList->C_Login)(TmpSession, CKU_USER, (CK_UTF8CHAR_PTR)struserpin, userpin.length());
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_Login ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }
        ui->textEdit->append(QString().sprintf("C_Login User sucessfully...\n"));

        if(AdminPin.length())
        {

            dwRet = p11func.QtrToChar(AdminPin,strAdminPin);
            if(dwRet)
            {
                ui->textEdit->clear();
                ui->textEdit->setText("convert Char Err");
                return;
            }

            dwRet = (p11func.g_P11_FuncList->C_Login)(TmpSession, CKU_SO, (CK_UTF8CHAR_PTR)strAdminPin, AdminPin.length());
            if (dwRet)
            {
                ui->textEdit->append(QString().sprintf("C_Login ERR, dwRet = 0x%08x", dwRet));
                goto ERR;
            }
            ui->textEdit->append(QString().sprintf("C_Login Admin sucessfully...\n"));
        }

        dwRet = (p11func.g_P11_FuncList->C_CloseSession)(TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_CloseSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        TmpSession = NULL;

        ui->textEdit->append(QString().sprintf("C_CloseSession sucessfully...\n"));
    }

ERR:
    if(TmpSession)
    {
        dwRet = (p11func.g_P11_FuncList->C_CloseSession)(TmpSession);
        if (dwRet)
        {
            ui->textEdit->append(QString().sprintf("C_CloseSession ERR, dwRet = 0x%08x", dwRet));
            goto ERR;
        }

        ui->textEdit->append(QString().sprintf("C_CloseSession sucessfully...\n"));
    }

    dwRet = (p11func.g_P11_FuncList->C_Finalize)(NULL);
    if(dwRet)
    {
        ui->textEdit->append(QString().sprintf("C_Finalize ERR, dwRet = 0x%08x", dwRet));
    }

    ui->textEdit->append(QString().sprintf("C_Finalize sucessfully...\n"));

}
