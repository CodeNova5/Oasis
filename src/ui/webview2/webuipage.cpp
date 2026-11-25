#include "webuipage.h"

#include "webuibridge.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QLabel>
#include <QResizeEvent>
#include <QStandardPaths>
#include <QUrl>
#include <QVBoxLayout>

namespace {

class WebView2EnvironmentHandler final
    : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler
{
public:
    explicit WebView2EnvironmentHandler(WebUiPage *page) : m_page(page) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **object) override
    {
        if (!object)
            return E_POINTER;
        *object = nullptr;
        if (riid == IID_IUnknown || riid == IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler) {
            *object = static_cast<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return ++m_references; }

    ULONG STDMETHODCALLTYPE Release() override
    {
        const ULONG references = --m_references;
        if (references == 0)
            delete this;
        return references;
    }

    HRESULT STDMETHODCALLTYPE Invoke(HRESULT errorCode,
                                     ICoreWebView2Environment *result) override
    {
        if (m_page)
            m_page->onEnvironmentCreated(errorCode, result);
        return S_OK;
    }

private:
    ULONG m_references = 1;
    QPointer<WebUiPage> m_page;
};

class WebView2ControllerHandler final
    : public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler
{
public:
    explicit WebView2ControllerHandler(WebUiPage *page) : m_page(page) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **object) override
    {
        if (!object)
            return E_POINTER;
        *object = nullptr;
        if (riid == IID_IUnknown || riid == IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler) {
            *object = static_cast<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return ++m_references; }

    ULONG STDMETHODCALLTYPE Release() override
    {
        const ULONG references = --m_references;
        if (references == 0)
            delete this;
        return references;
    }

    HRESULT STDMETHODCALLTYPE Invoke(HRESULT errorCode,
                                     ICoreWebView2Controller *result) override
    {
        if (m_page)
            m_page->onControllerCreated(errorCode, result);
        return S_OK;
    }

private:
    ULONG m_references = 1;
    QPointer<WebUiPage> m_page;
};

QString errorText(HRESULT errorCode)
{
    return QStringLiteral("0x%1").arg(static_cast<quint32>(errorCode), 8, 16, QLatin1Char('0'));
}

} // namespace

WebUiPage::WebUiPage(const QString &pageDir, const QString &pageFile,
                     const QString &displayName, ServiceHost *services,
                     QWidget *parent)
    : QWidget(parent)
    , m_displayName(displayName)
    , m_services(services)
    , m_pagePath(QCoreApplication::applicationDirPath() + QLatin1Char('/')
                 + pageDir + QLatin1Char('/') + pageFile)
    , m_loader(QStringLiteral("WebView2Loader"))
{
    setAttribute(Qt::WA_NativeWindow);
    setMinimumSize(720, 480);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(24, 24, 24, 24);

    m_status = new QLabel(QStringLiteral("Starting %1...").arg(m_displayName), this);
    m_status->setAlignment(Qt::AlignCenter);
    m_status->setWordWrap(true);
    m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_status->setStyleSheet(QStringLiteral("color: #8d9996; background: #111416;"));
    layout->addWidget(m_status);

    initialize();
}

WebUiPage::~WebUiPage()
{
    // The bridge holds a WebMessageReceived registration on the WebView2
    // object, so it has to go before the interfaces are released.
    delete m_bridge;
    m_bridge = nullptr;

    if (m_webView)
        m_webView->Release();
    if (m_controller)
        m_controller->Release();
    if (m_environment)
        m_environment->Release();
    m_loader.unload();
}

void WebUiPage::initialize()
{
    const QString profileFolder = QDir::toNativeSeparators(
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
        + QStringLiteral("/Oasis/WebView2"));
    if (!QDir().mkpath(profileFolder)) {
        showFailure(QStringLiteral("WebView2 profile directory could not be created.\n"
                                   "Expected: %1")
                        .arg(profileFolder));
        return;
    }
    m_userDataFolder = profileFolder.toStdWString();

    if (!m_loader.load()) {
        showFailure(QStringLiteral("WebView2Loader.dll could not be loaded.\n"
                                   "Expected next to Oasis.exe: %1")
                        .arg(QCoreApplication::applicationDirPath() + QStringLiteral("/WebView2Loader.dll"))
                    + QStringLiteral("\nThe DLL must match the executable architecture (x64 for this build)."));
        return;
    }

    auto createEnvironment = reinterpret_cast<CreateEnvironmentFunction>(
        m_loader.resolve("CreateCoreWebView2EnvironmentWithOptions"));
    if (!createEnvironment) {
        showFailure(QStringLiteral("WebView2 environment factory is unavailable.\n"
                                   "WebView2Loader.dll does not export the expected entry point; "
                                   "replace it with the loader from the WebView2 SDK."));
        return;
    }

    auto *handler = new WebView2EnvironmentHandler(this);
    const HRESULT result = createEnvironment(nullptr, m_userDataFolder.c_str(), nullptr, handler);
    handler->Release();
    if (FAILED(result))
        showFailure(QStringLiteral("WebView2 environment creation failed (%1).").arg(errorText(result)));
}

void WebUiPage::onEnvironmentCreated(HRESULT errorCode,
                                     ICoreWebView2Environment *environment)
{
    if (FAILED(errorCode) || !environment) {
        showFailure(QStringLiteral("WebView2 runtime is unavailable (%1).\n"
                                   "Install the Microsoft Edge WebView2 Evergreen Runtime.")
                        .arg(errorText(errorCode)));
        return;
    }

    m_environment = environment;
    m_environment->AddRef();

    auto *handler = new WebView2ControllerHandler(this);
    const HWND hostWindow = reinterpret_cast<HWND>(static_cast<quintptr>(winId()));
    const HRESULT result = m_environment->CreateCoreWebView2Controller(hostWindow, handler);
    handler->Release();
    if (FAILED(result))
        showFailure(QStringLiteral("WebView2 controller creation failed (%1).").arg(errorText(result)));
}

void WebUiPage::onControllerCreated(HRESULT errorCode,
                                    ICoreWebView2Controller *controller)
{
    if (FAILED(errorCode) || !controller) {
        showFailure(QStringLiteral("WebView2 controller is unavailable (%1).").arg(errorText(errorCode)));
        return;
    }

    m_controller = controller;
    m_controller->AddRef();
    m_controller->put_IsVisible(TRUE);
    resizeController();

    if (FAILED(m_controller->get_CoreWebView2(&m_webView)) || !m_webView) {
        showFailure(QStringLiteral("WebView2 content surface could not be created."));
        return;
    }

    if (!QFileInfo::exists(m_pagePath)) {
        showFailure(QStringLiteral("%1 assets were not found.\n"
                                   "Expected: %2\n"
                                   "Run `npm run build` in the page's web/ project, then relink the application.")
                        .arg(m_displayName, m_pagePath));
        return;
    }

    // Register the message handler before the first navigation, so a page that
    // asks for status as soon as it loads is never missed.
    m_bridge = new WebUiBridge(m_webView, m_services, this);

    m_status->hide();
    m_webView->Navigate(QUrl::fromLocalFile(m_pagePath).toString().toStdWString().c_str());
}

void WebUiPage::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    resizeController();
}

void WebUiPage::resizeController()
{
    if (!m_controller)
        return;

    const RECT bounds = {0, 0, width(), height()};
    m_controller->put_Bounds(bounds);
}

void WebUiPage::showFailure(const QString &message)
{
    // The WebView2 content surface is a native child window drawn above Qt
    // widgets, so it has to be hidden for the fallback text to be readable.
    if (m_controller)
        m_controller->put_IsVisible(FALSE);

    if (m_status) {
        m_status->setText(message
            + QStringLiteral("\n\nSee docs/WEBVIEW2_RUNTIME_SETUP.md for setup details."));
        m_status->show();
        m_status->raise();
    }
}
