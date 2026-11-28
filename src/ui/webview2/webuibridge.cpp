/**
 * @file    webuibridge.cpp
 * @author  Oasis
 */

#include "webuibridge.h"

#include <QBuffer>
#include <QHash>
#include <QIcon>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPair>
#include <QPixmap>
#include <QPointer>
#include <QSet>
#include <QStringList>
#include <QTime>

#include <string>

#include "core/servicehost.h"
#include "core/version.h"
#include "network/auditeventstore.h"
#include "network/datasavernotification.h"
#include "network/datasavermode.h"
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

// The automation contract exposes only Off and Enforce. An invalid stored mode
// has already failed closed to Off by the time the bridge reads it, so a
// "monitor" label can no longer be produced.
QString dataSaverModeLabel(DataSaverMode::Mode mode)
{
    return DataSaverMode::token(mode);
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

// Process icons are the executable's own 32 px shell image. They change only
// when Windows re-resolves the file, so the encoded data URI is cached by
// executable name instead of being re-encoded on every one-second beat.
QString overviewIcon(const TopConsumers::Consumer &consumer)
{
    if (consumer.icon.isNull())
        return QString();

    static QHash<QString, QPair<qint64, QString>> cache;
    const QString key = consumer.name.trimmed().isEmpty()
        ? QStringLiteral("pid:%1").arg(consumer.pid)
        : consumer.name.trimmed().toLower();
    const qint64 cacheKey = consumer.icon.cacheKey();
    const auto found = cache.constFind(key);
    if (found != cache.constEnd() && found->first == cacheKey)
        return found->second;

    const QPixmap pixmap = consumer.icon.pixmap(32, 32);
    if (pixmap.isNull())
        return QString();

    QByteArray png;
    QBuffer buffer(&png);
    if (!buffer.open(QIODevice::WriteOnly)
        || !pixmap.toImage().save(&buffer, "PNG")) {
        return QString();
    }
    buffer.close();

    if (cache.size() >= 256)
        cache.clear();
    const QString uri = QStringLiteral("data:image/png;base64,")
        + QString::fromLatin1(png.toBase64());
    cache.insert(key, qMakePair(cacheKey, uri));
    return uri;
}

QJsonObject overviewProcess(const TopConsumers::Consumer &consumer, const QString &name)
{
    QJsonObject row;
    row.insert(QStringLiteral("id"),
               QStringLiteral("%1-%2").arg(consumer.name).arg(consumer.pid));
    row.insert(QStringLiteral("name"), name);
    row.insert(QStringLiteral("pid"), static_cast<int>(consumer.pid));
    // Only advertise an icon that is already resolved; the page fetches the
    // pixels separately so the once-a-second status stays small.
    if (!consumer.icon.isNull() && !consumer.name.trimmed().isEmpty())
        row.insert(QStringLiteral("iconKey"), consumer.name);
    row.insert(QStringLiteral("downBps"),
               QJsonValue(static_cast<qint64>(consumer.rxBytesPerSecond)));
    row.insert(QStringLiteral("upBps"),
               QJsonValue(static_cast<qint64>(consumer.txBytesPerSecond)));
    row.insert(QStringLiteral("totalBytes"),
               QJsonValue(static_cast<qint64>(consumer.totalBytes())));
    return row;
}

// Fetches one executable's icon by the key advertised in overview.status.
// Names are matched case-insensitively because the row carries the model's
// spelling while the page echoes the key back verbatim.
QJsonObject overviewIconReply(ServiceHost *services, const QString &name)
{
    QJsonObject result;
    NetworkWidget *network = services ? services->network() : nullptr;
    if (!network)
        return result;

    const TopConsumers::Summary summary = network->dashboardSummary();
    for (const TopConsumers::Consumer &consumer : summary.consumers) {
        if (consumer.icon.isNull()
            || consumer.name.compare(name, Qt::CaseInsensitive) != 0) {
            continue;
        }

        const QString icon = overviewIcon(consumer);
        if (!icon.isEmpty()) {
            result.insert(QStringLiteral("icon"), icon);
            break;
        }
    }
    return result;
}

// The Overview page renders the same once-a-second beat the native dashboard
// already builds. Consumers are grouped under their real parent PID so the
// table can show one application row with its children nested underneath; a
// process whose parent is not consuming on this beat becomes a root row.
QJsonObject overviewStatus(ServiceHost *services)
{
    NetworkWidget *network = services ? services->network() : nullptr;
    const TopConsumers::Summary summary =
        network ? network->dashboardSummary() : TopConsumers::Summary();

    QJsonObject summaryObject;
    summaryObject.insert(QStringLiteral("totalBytes"),
                         QJsonValue(static_cast<qint64>(summary.totalRxBytes + summary.totalTxBytes)));
    summaryObject.insert(QStringLiteral("uploadBytes"),
                         QJsonValue(static_cast<qint64>(summary.totalTxBytes)));
    summaryObject.insert(QStringLiteral("downloadBytes"),
                         QJsonValue(static_cast<qint64>(summary.totalRxBytes)));

    QJsonObject realtime;
    realtime.insert(QStringLiteral("timestamp"),
                    QTime::currentTime().toString(QStringLiteral("HH:mm:ss")));
    realtime.insert(QStringLiteral("downBps"),
                    QJsonValue(static_cast<qint64>(summary.totalRxBytesPerSecond)));
    realtime.insert(QStringLiteral("upBps"),
                    QJsonValue(static_cast<qint64>(summary.totalTxBytesPerSecond)));

    // Only real rows with a name are shown; the model can carry an empty
    // placeholder row before the first process is resolved.
    QList<const TopConsumers::Consumer *> consumers;
    consumers.reserve(summary.consumers.size());
    for (const TopConsumers::Consumer &consumer : summary.consumers) {
        if (consumer.name.trimmed().isEmpty() && consumer.pid == 0)
            continue;
        consumers.append(&consumer);
    }

    QHash<quint32, int> byPid;
    for (int index = 0; index < consumers.size(); ++index) {
        const quint32 pid = consumers.at(index)->pid;
        if (pid != 0 && !byPid.contains(pid))
            byPid.insert(pid, index);
    }

    // Resolve each row to the topmost ancestor that is also present. The table
    // renders one level of children, so deeper descendants are flattened under
    // that ancestor rather than dropped. A parent that has no traffic yet is
    // not in the consumer list, which makes the row a root until it appears.
    QList<int> roots;
    QHash<int, QList<int>> children;
    for (int index = 0; index < consumers.size(); ++index) {
        int root = index;
        QSet<int> visited;
        visited.insert(index);
        bool cycle = false;
        quint32 parent = consumers.at(index)->parentPid;

        while (parent != 0) {
            const auto found = byPid.constFind(parent);
            if (found == byPid.constEnd())
                break;

            const int parentIndex = found.value();
            if (visited.contains(parentIndex)) {
                cycle = true;
                break;
            }
            visited.insert(parentIndex);
            root = parentIndex;
            parent = consumers.at(parentIndex)->parentPid;
        }

        // A recycled PID can produce a cycle; show that row as its own root
        // rather than nesting it under something indefinite.
        if (cycle)
            root = index;

        if (root == index)
            roots.append(index);
        else
            children[root].append(index);
    }

    QJsonArray processes;
    for (int rootIndex : roots) {
        const TopConsumers::Consumer &lead = *consumers.at(rootIndex);
        const QString displayName = lead.identity.trimmed().isEmpty()
            ? lead.name : lead.identity.trimmed();
        QJsonObject parent = overviewProcess(lead, displayName);

        QJsonArray subprocesses;
        for (int childIndex : children.value(rootIndex)) {
            const TopConsumers::Consumer &child = *consumers.at(childIndex);
            subprocesses.append(overviewProcess(child, child.name));
        }
        parent.insert(QStringLiteral("subprocesses"), subprocesses);
        processes.append(parent);
    }

    QJsonObject result;
    result.insert(QStringLiteral("schemaVersion"), 1);
    result.insert(QStringLiteral("summary"), summaryObject);
    result.insert(QStringLiteral("realtime"), realtime);
    result.insert(QStringLiteral("processes"), processes);
    return result;
}

QJsonObject dataSaverStatus(ServiceHost *services)
{
    NetworkWidget *network = services ? services->network() : nullptr;
    const DataSaverMode::Mode mode = network ? network->dataSaverMode()
                                             : DataSaverMode::Mode::Off;
    const bool enforcing = mode == DataSaverMode::Mode::Enforce;

    QJsonObject modeObject;
    // `token` is canonical; `value` is the deprecated legacy encoding and never
    // reports the old Monitor state.
    modeObject.insert(QStringLiteral("token"), DataSaverMode::token(mode));
    modeObject.insert(QStringLiteral("value"), enforcing ? 2 : 0);
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
    result.insert(QStringLiteral("enforcing"), enforcing);
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

    // DS-011: a delivered notice is pushed, not polled, so the page can show the
    // actionable card immediately. The connection is owned by the bridge, so a
    // page teardown stops the pushes without the host having to know about it.
    if (m_services) {
        connect(m_services, &ServiceHost::notificationPosted, this,
                [this](const AppNotification &notification, int suppressedCount) {
                    postToPage(WebUiBridge::noticeEvent(notification, suppressedCount));
                });

        // A tray action applies the same reversal the page offers, so the page
        // is told to retire that card instead of showing it again.
        if (NetworkWidget *network = m_services->network()) {
            connect(network, &NetworkWidget::dataSaverNoticeResolved, this,
                    [this](const QString &notificationKey, const QString &actionToken) {
                        QJsonObject payload;
                        payload.insert(QStringLiteral("key"), notificationKey);
                        payload.insert(QStringLiteral("action"), actionToken);
                        QJsonObject message;
                        message.insert(QStringLiteral("event"), noticeResolvedEventName());
                        message.insert(QStringLiteral("payload"), payload);
                        postToPage(message);
                    });
        }
    }

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

QString WebUiBridge::noticeEventName()
{
    return QStringLiteral("datasaver.notice");
}

QString WebUiBridge::noticeResolvedEventName()
{
    return QStringLiteral("datasaver.notice.resolved");
}

QJsonObject WebUiBridge::noticeEvent(const AppNotification &notification, int suppressedCount)
{
    QJsonObject message;
    message.insert(QStringLiteral("event"), noticeEventName());
    message.insert(QStringLiteral("payload"),
                   DataSaverNotifications::eventPayload(notification, suppressedCount));
    return message;
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
    if (method == QStringLiteral("overview.status"))
        return okReply(id, overviewStatus(services));
    if (method == QStringLiteral("overview.icon")) {
        const QString name = paramsValue.toObject()
                                 .value(QStringLiteral("name"))
                                 .toString()
                                 .trimmed();
        if (name.isEmpty()) {
            return errorReply(id, QStringLiteral("invalid_params"),
                              QStringLiteral("overview.icon needs a non-empty \"name\"."));
        }
        return okReply(id, overviewIconReply(services, name));
    }

    if (method == QStringLiteral("datasaver.notice.action")) {
        const QJsonObject noticeParams = paramsValue.toObject();
        const QString key = noticeParams.value(QStringLiteral("key"))
                                .toString()
                                .trimmed();
        const QString action = noticeParams.value(QStringLiteral("action"))
                                   .toString()
                                   .trimmed();
        if (key.isEmpty() || action.isEmpty()) {
            return errorReply(id, QStringLiteral("invalid_params"),
                              QStringLiteral("A notice action needs a non-empty \"key\" "
                                             "and \"action\"."));
        }

        NetworkWidget *network = services ? services->network() : nullptr;
        if (!network) {
            return errorReply(id, QStringLiteral("services_unavailable"),
                              QStringLiteral("The Data Saver services are not running."));
        }

        // Inspect answers with the retained evidence; it changes nothing.
        if (action == DataSaverNotifications::inspectActionToken()) {
            DataSaverNotifications::DecisionNotice evidence;
            if (!network->noticeEvidence(key, &evidence)) {
                return errorReply(id, QStringLiteral("notice_unavailable"),
                                  QStringLiteral("That notice is no longer available."));
            }
            QJsonObject result;
            result.insert(QStringLiteral("action"), action);
            result.insert(QStringLiteral("notice"),
                          DataSaverNotifications::evidenceSummary(evidence));
            return okReply(id, result);
        }

        const bool confirmed = noticeParams.value(QStringLiteral("confirmed")).toBool(false);
        QString error;
        bool applied = false;
        if (action == DataSaverNotifications::allowOnceActionToken()) {
            applied = network->allowOnceForNotice(key, &error);
        } else if (action == DataSaverNotifications::alwaysAllowActionToken()) {
            applied = network->alwaysAllowForNotice(key, confirmed, &error);
        } else {
            return errorReply(id, QStringLiteral("unsupported_action"),
                              QStringLiteral("\"%1\" is not an action this build offers.")
                                  .arg(action));
        }
        if (!applied) {
            return errorReply(id, QStringLiteral("notice_action_failed"),
                              error.isEmpty()
                                  ? QStringLiteral("The action could not be applied.")
                                  : error);
        }

        QJsonObject result;
        result.insert(QStringLiteral("action"), action);
        result.insert(QStringLiteral("message"),
                      action == DataSaverNotifications::allowOnceActionToken()
                          ? QStringLiteral("Allowed once. The control is paused for this flow "
                                           "for one hour.")
                          : QStringLiteral("Always allowed. A pinned rule now covers this "
                                           "application."));
        return okReply(id, result);
    }

    return errorReply(id, QStringLiteral("unknown_method"),
                      QStringLiteral("No bridge method named \"%1\".").arg(method));
}
