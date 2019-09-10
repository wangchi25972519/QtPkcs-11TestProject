#-------------------------------------------------
#
# Project created by QtCreator 2019-06-06T09:57:33
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = HTP11Test
TEMPLATE = app

win32 {
    DEFINES += CK_Win32
}

unix {
    DEFINES += CK_GENERIC
}

QMAKE_CFLAGS += -Wattributes
SOURCES += main.cpp\
        mainwindow.cpp \
    htp11testfunc.cpp

HEADERS  += mainwindow.h \
    htp11testfunc.h

FORMS    += mainwindow.ui
