#pragma once

#include <QWidget>
#include <QLibrary>
#include <QPointer>

#include <string>

#include <windows.h>
#include <WebView2.h>

class QLabel;

class DataSaverWebPage final : public QWidget
{
public:
    explicit DataSaverWebPage(QWidget *parent = nullptr);
    ~DataSaverWebPage() override;

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

    QLibrary m_loader;
    QLabel *m_status = nullptr;
    ICoreWebView2Environment *m_environment = nullptr;
    ICoreWebView2Controller *m_controller = nullptr;
    ICoreWebView2 *m_webView = nullptr;
    std::wstring m_userDataFolder;
};