#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QTextCodec>
#include <QDebug>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_FullTestButton_clicked();

    void on_pathchoiceButton_clicked();

    void on_filepushButton_clicked();

    void on_readfilepushButton_clicked();

    void on_objectpushButton_clicked();

    void on_sympushButton_clicked();

    void on_initpushButton_clicked();

    void on_changepin_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
