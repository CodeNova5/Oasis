#include "webuiwindow.h"

#include "webuipage.h"

WebUiWindow::WebUiWindow(const QString &pageDir, const QString &pageFile,
                         const QString &displayName, ServiceHost *services,
                         QWidget *parent)
    : QMainWindow(parent)
{
    // No menu bar, tool bar, dock or status bar: the page owns the whole window.
    setCentralWidget(new WebUiPage(pageDir, pageFile, displayName, services, this));
}
