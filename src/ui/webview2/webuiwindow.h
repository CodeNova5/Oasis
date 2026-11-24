#pragma once

#include <QMainWindow>

/**
 * The application window for the web UI.
 *
 * It hosts one WebUiPage edge to edge and draws no Qt chrome: no sidebar, no
 * header, no status bar. Everything the user sees is the Preact + HTM bundle.
 */
class WebUiWindow final : public QMainWindow
{
public:
    // pageDir is relative to the executable directory, e.g. "web/ui/dist".
    // pageFile is the page inside that folder, e.g. "index.html".
    explicit WebUiWindow(const QString &pageDir, const QString &pageFile,
                         const QString &displayName, QWidget *parent = nullptr);
};
