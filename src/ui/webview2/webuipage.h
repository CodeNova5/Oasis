#pragma once

#include <QWidget>
#include <QLibrary>
#include <QPointer>
#include <QString>

#include <string>

#include <windows.h>
#include <WebView2.h>

class QLabel;

/**
 * Hosts one bundled Preact + HTM page inside the Qt shell through WebView2.
 *
 * The page is built by the frontend project under web/ui and copied next to
 * the executable, so the frontend stays fully isolated from the native
 * widgets: this class only supplies a native window, a profile folder and the
 * URL to navigate to.
 */
class WebUiPage final : public QWidget
{
public:
    // pageDir is relative to the executable directory ("web/ui/dist") and
    // pageFile is the page inside it ("index.html", "datasaver.html").
    // displayName is only used in fallback messages.
    explicit WebUiPage(const QString &pageDir, const QString &pageFile,
                       const QString &displayName, QWidget *parent = nullptr);
    ~WebUiPage() override;

protected:
    void resizeEvent(QResizeEvent *event) override;

public:
    // Called by the asynchronous WebView2 completion handlers.
    void onEnvironmentCreated(HRESULT errorCode, ICoreWebView2Environment *environment);
    void onControllerCreated(HRESULT errorCode, ICoreWebView2Controller *controller);

private:
    void initialize();
    void showFailure(const QString &message);
    void resizeController();

    using CreateEnvironmentFunction = HRESULT (STDAPICALLTYPE *)(
        PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions *,
        ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *);

    QString m_displayName;
    QString m_pagePath;
    QLibrary m_loader;
    QLabel *m_status = nullptr;
    ICoreWebView2Environment *m_environment = nullptr;
    ICoreWebView2Controller *m_controller = nullptr;
    ICoreWebView2 *m_webView = nullptr;
    std::wstring m_userDataFolder;
};
