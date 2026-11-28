/**
 * @file    webuibridge.h
 * @author  Oasis
 * @brief   JSON message bridge between the Preact UI and the Qt services.
 *
 * WebView2 gives the page `window.chrome.webview.postMessage()`, which is a
 * complete transport without the Qt WebChannel module (not part of this Qt
 * kit). This class only translates messages; it never exposes arbitrary Qt
 * objects, so a page cannot call a method that was not deliberately added to
 * the dispatcher.
 *
 * Protocol, request (JS -> native):
 *   { "id": 1, "method": "app.status", "params": {} }
 * Reply (native -> JS), posted to the same page:
 *   { "id": 1, "ok": true,  "result": { ... } }
 *   { "id": 1, "ok": false, "error": { "code": "...", "message": "..." } }
 *
 * `id` is echoed verbatim so number and string ids both work. The dispatcher
 * is a pure function of the request and the service host, so it can be tested
 * without a WebView2 instance.
 */
#pragma once

#include <QJsonObject>
#include <QJsonValue>
#include <QObject>
#include <QPointer>

#include <WebView2.h>

#include "network/notificationcoordinator.h"

class ServiceHost;

class WebUiBridge final : public QObject
{
    Q_OBJECT
public:
    // Registers the WebMessageReceived handler on webView. The handler is
    // removed again before the WebView2 interfaces are released.
    WebUiBridge(ICoreWebView2 *webView, ServiceHost *services, QObject *parent = nullptr);
    ~WebUiBridge() override;

    // Largest request accepted from the page. A message beyond this is refused
    // instead of parsed; nothing the UI sends should come close.
    static constexpr int kMaxRequestBytes = 64 * 1024;

    // Request dispatcher. `services` may be null (no backend yet), in which
    // case status methods report the services as unavailable instead of
    // failing.
    static QJsonObject dispatch(const QJsonObject &request, ServiceHost *services);

    // Sends one raw JSON object to the page. Exposed so a later layer can push
    // events through the same channel.
    void postToPage(const QJsonObject &message);

    // Event name a delivered notification is pushed under, e.g.
    // "datasaver.notice". The page binds buttons from `payload.actions`, so it
    // never has to parse the message copy.
    static QString noticeEventName();
    // Event name pushed when a notice action was applied, so the page can retire
    // the card the tray just acted on (and the reverse).
    static QString noticeResolvedEventName();
    // Full event message: { "event": <name>, "payload": <eventPayload> }.
    static QJsonObject noticeEvent(const AppNotification &notification,
                                   int suppressedCount);

    // Entry point for the WebView2 completion handler.
    void handleMessageJson(const QString &json);

private:

    ICoreWebView2 *m_webView = nullptr;
    ServiceHost *m_services = nullptr;
    EventRegistrationToken m_messageToken{};
    bool m_handlerRegistered = false;
};
