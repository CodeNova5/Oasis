/**
 * @file    webuibridge.cpp
 * @author  Oasis
 */

#include "webuibridge.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QStringList>

#include <string>

#include "core/servicehost.h"
#include "core/version.h"
#include "network/auditeventstore.h"
#include "network/networkmonitor.h"
#include "network/networkwidget.h"

namespace {

// WebView2 keeps the handler alive for as long as it is registered, so the
// QPointer is what protects against the page being destroyed first.
class WebMessageHandler final : public ICoreWebView2WebMessageReceivedEventHandler
{
public:
    explicit WebMessageHandler(WebUiBridge *bridge) : m_bridge(bridge) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **object) override
    {
        if (!object)
            return E_POINTER;
        *object = nullptr;
        if (riid == IID_IUnknown
            || riid == IID_ICoreWebView2WebMessageReceivedEventHandler) {
            *object = static_cast<ICoreWebView2WebMessageReceivedEventHandler *>(this);
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

    HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2 *,
                                     ICoreWebView2WebMessageReceivedEventArgs *args) override
    {
        if (!args)
            return E_POINTER;

        LPWSTR raw = nullptr;
        if (FAILED(args->get_WebMessageAsJson(&raw)) || !raw)
            return S_OK;

        const QString json = QString::fromWCharArray(raw);
        CoTaskMemFree(raw);

        if (m_bridge)
            m_bridge->handleMessageJson(json);
        return S_OK;
    }

private:
    ULONG m_references = 1;
    QPointer<WebUiBridge> m_bridge;
};

QJsonObject errorReply(const QJsonValue &id, const QString &code, const QString &message)
{
    QJsonObject error;
    error.insert(QStringLiteral("code"), code);
    error.insert(QStringLiteral("message"), message);

    QJsonObject reply;
    reply.insert(QStringLiteral("id"), id);
    reply.insert(QStringLiteral("ok"), false);
    reply.insert(QStringLiteral("error"), error);
    return reply;
}

QJsonObject okReply(const QJsonValue &id, const QJsonObject &result)
{
    QJsonObject reply;
    reply.insert(QStringLiteral("id"), id);
    reply.insert(QStringLiteral("ok"), true);
    reply.insert(QStringLiteral("result"), result);
    return reply;
}

// The legacy control has three states; the automation PRD only has Off and
// Enforce. Reporting the raw value keeps the bridge honest instead of hiding
// the intermediate state.
QString dataSaverModeLabel(int mode)
{
    switch (mode) {
    case 0: return QStringLiteral("off");
    case 1: return QStringLiteral("monitor");
    case 2: return QStringLiteral("enforce");
    default: return QStringLiteral("unknown");
    }
}

QJsonObject appStatus(ServiceHost *services)
{
    QJsonObject capture;
    capture.insert(QStringLiteral("running"), services && services->isCapturing());
    capture.insert(QStringLiteral("adapter"),
                   services ? services->activeAdapterDescription() : QString());

    QJsonObject notifications;
    if (services) {
        const NotificationSettings settings = services->notificationSettings();
        notifications.insert(QStringLiteral("cooldownMs"), settings.cooldownMs);
        notifications.insert(QStringLiteral("windowMs"), settings.windowMs);
        notifications.insert(QStringLiteral("maxDeliveriesPerWindow"),
                             settings.maxDeliveriesPerWindow);
    }

    QJsonObject result;
    result.insert(QStringLiteral("schemaVersion"), 1);
    result.insert(QStringLiteral("name"), QStringLiteral(APP_NAME));
    result.insert(QStringLiteral("version"), QStringLiteral(APP_VERSION_STR));
    result.insert(QStringLiteral("servicesAvailable"), services != nullptr);
    result.insert(QStringLiteral("servicesStarted"), services && services->isStarted());
    result.insert(QStringLiteral("capture"), capture);
    result.insert(QStringLiteral("notifications"), notifications);
    return result;
}

QJsonObject dataSaverStatus(ServiceHost *services)
{
    NetworkWidget *network = services ? services->network() : nullptr;
    const int mode = network ? network->dataSaverMode() : 0;

    QJsonObject modeObject;
    modeObject.insert(QStringLiteral("value"), mode);
    modeObject.insert(QStringLiteral("label"), dataSaverModeLabel(mode));

    QJsonArray throttled;
    if (network) {
        const QStringList paths = network->throttledPaths();
        for (const QString &path : paths)
            throttled.append(path);
    }

    AuditEventStore *audit = services ? services->auditStore() : nullptr;

    QJsonObject capture;
    capture.insert(QStringLiteral("running"), network && network->isCapturing());
    capture.insert(QStringLiteral("adapter"),
                   network ? network->activeAdapterDescription() : QString());

    QJsonObject result;
    result.insert(QStringLiteral("schemaVersion"), 1);
    result.insert(QStringLiteral("servicesAvailable"), services != nullptr);
    result.insert(QStringLiteral("mode"), modeObject);
    result.insert(QStringLiteral("enforcing"), mode == 2);
    result.insert(QStringLiteral("throttledExecutables"), throttled);
    result.insert(QStringLiteral("auditEvents"), audit ? audit->count() : 0);
    result.insert(QStringLiteral("capture"), capture);
    return result;
}

} // namespace

WebUiBridge::WebUiBridge(ICoreWebView2 *webView, ServiceHost *services, QObject *parent)
    : QObject(parent)
    , m_webView(webView)
    , m_services(services)
{
    if (!m_webView)
        return;

    auto *handler = new WebMessageHandler(this);
    if (SUCCEEDED(m_webView->add_WebMessageReceived(handler, &m_messageToken))) {
        m_handlerRegistered = true;
    } else {
        m_handlerRegistered = false;
    }
    handler->Release();
}

WebUiBridge::~WebUiBridge()
{
    if (m_webView && m_handlerRegistered) {
        m_webView->remove_WebMessageReceived(m_messageToken);
        m_handlerRegistered = false;
    }
    m_webView = nullptr;
}

void WebUiBridge::handleMessageJson(const QString &json)
{
    // Refuse before parsing: a page cannot make the native side allocate an
    // unbounded document.
    if (json.size() > kMaxRequestBytes) {
        postToPage(errorReply(QJsonValue::Null, QStringLiteral("message_too_large"),
                              QStringLiteral("The request exceeded %1 characters.")
                                  .arg(kMaxRequestBytes)));
        return;
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(json.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        postToPage(errorReply(QJsonValue::Null, QStringLiteral("invalid_json"),
                              QStringLiteral("A request must be a single JSON object.")));
        return;
    }

    postToPage(dispatch(document.object(), m_services));
}

void WebUiBridge::postToPage(const QJsonObject &message)
{
    if (!m_webView)
        return;

    const std::wstring payload =
        QString::fromUtf8(QJsonDocument(message).toJson(QJsonDocument::Compact)).toStdWString();
    m_webView->PostWebMessageAsJson(payload.c_str());
}

QJsonObject WebUiBridge::dispatch(const QJsonObject &request, ServiceHost *services)
{
    const QJsonValue id = request.value(QStringLiteral("id"));
    const QJsonValue methodValue = request.value(QStringLiteral("method"));
    if (!methodValue.isString() || methodValue.toString().isEmpty())
        return errorReply(id, QStringLiteral("invalid_request"),
                          QStringLiteral("A request needs a string \"method\"."));

    const QJsonValue paramsValue = request.value(QStringLiteral("params"));
    if (!paramsValue.isUndefined() && !paramsValue.isNull() && !paramsValue.isObject())
        return errorReply(id, QStringLiteral("invalid_request"),
                          QStringLiteral("\"params\" must be an object when present."));

    const QString method = methodValue.toString();
    if (method == QStringLiteral("app.status"))
        return okReply(id, appStatus(services));
    if (method == QStringLiteral("datasaver.status"))
        return okReply(id, dataSaverStatus(services));

    return errorReply(id, QStringLiteral("unknown_method"),
                      QStringLiteral("No bridge method named \"%1\".").arg(method));
}
