/**
 * @file    openaiadapter.cpp
 * @brief   Opt-in OpenAI-compatible provider adapter (NG-045).
 * @author  Ali Sakkaf
 */
#include "openaiadapter.h"

#include <QEventLoop>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>

namespace {

const int kMaxResponseBytes = 64 * 1024;

/// Explanation text from either a plain string or the content-part array shape.
QString explanationFrom(const QJsonValue &content)
{
    if (content.isString()) return content.toString();

    QString text;
    if (content.isArray()) {
        const QJsonArray parts = content.toArray();
        for (const QJsonValue &part : parts) {
            if (!part.isObject()) continue;
            const QJsonValue partText = part.toObject().value(QStringLiteral("text"));
            if (partText.isString()) text += partText.toString();
        }
    }
    return text;
}

} // namespace

QString OpenAiCompatibleProvider::apiKeyEnvironmentVariable()
{
    return QStringLiteral("NETGUARD_AI_API_KEY");
}

QString OpenAiCompatibleProvider::systemPrompt()
{
    return QStringLiteral(
        "You explain network activity for a Windows bandwidth manager. "
        "The user message is a JSON metadata record about one local observation. "
        "It contains no packet payload, no full file paths, and destinations are "
        "already masked. Reply with two to four short plain-text sentences: what "
        "the activity most likely is, why, and how the user can reverse any "
        "suggested action. Do not invent hosts, addresses, rules, or evidence that "
        "the record does not contain. Do not propose, format, or claim to apply a "
        "policy; the application decides enforcement and always asks the user "
        "first.");
}

int OpenAiCompatibleProvider::maxResponseBytes()
{
    return kMaxResponseBytes;
}

QString OpenAiCompatibleProvider::name() const
{
    return QStringLiteral("OpenAI-compatible provider");
}

AiProviderResponse OpenAiCompatibleProvider::explain(
    const AiContextPayload &payload, const AiProviderSettings &settings)
{
    AiProviderResponse result;

    const QString endpointProblem = settings.endpointProblem();
    if (!endpointProblem.isEmpty()) {
        result.failure = AiFailure::UnsupportedEndpoint;
        result.detail = endpointProblem;
        return result;
    }

    const QByteArray variable = apiKeyEnvironmentVariable().toUtf8();
    const QByteArray apiKey = qgetenv(variable.constData());
    if (apiKey.isEmpty()) {
        result.failure = AiFailure::NotConfigured;
        result.detail = QStringLiteral("Set %1 to the provider's API key.")
                            .arg(apiKeyEnvironmentVariable());
        return result;
    }

    QJsonObject systemMessage;
    systemMessage[QStringLiteral("role")] = QStringLiteral("system");
    systemMessage[QStringLiteral("content")] = systemPrompt();

    // The context document is the entire user message: nothing else about the
    // machine is disclosed.
    QJsonObject userMessage;
    userMessage[QStringLiteral("role")] = QStringLiteral("user");
    userMessage[QStringLiteral("content")] = payload.json;

    QJsonArray messages;
    messages.append(systemMessage);
    messages.append(userMessage);

    QJsonObject body;
    body[QStringLiteral("model")] = settings.model.trimmed();
    body[QStringLiteral("messages")] = messages;

    QNetworkRequest request(QUrl(settings.endpoint.trimmed()));
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QStringLiteral("application/json"));
    request.setHeader(QNetworkRequest::UserAgentHeader,
                      QStringLiteral("UltimateNetGuard"));
    request.setRawHeader("Accept", "application/json");
    request.setRawHeader("Authorization", "Bearer " + apiKey);

    QNetworkAccessManager manager;
    QNetworkReply *reply =
        manager.post(request, QJsonDocument(body).toJson(QJsonDocument::Compact));

    QEventLoop loop;
    QTimer deadline;
    deadline.setSingleShot(true);
    bool timedOut = false;
    QObject::connect(&deadline, &QTimer::timeout, &loop, [&]() {
        timedOut = true;
        loop.quit();
    });
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    deadline.start(settings.timeoutSeconds * 1000);
    loop.exec();
    deadline.stop();

    if (timedOut) {
        reply->abort();
        result.failure = AiFailure::Timeout;
        result.detail = QStringLiteral("No answer within %1 s.")
                            .arg(settings.timeoutSeconds);
        return result;
    }

    if (reply->error() != QNetworkReply::NoError) {
        result.httpStatus =
            reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        result.failure = result.httpStatus > 0 ? AiFailure::HttpError
                                               : AiFailure::Network;
        result.detail = reply->errorString();
        return result;
    }

    const QByteArray data = reply->readAll();
    if (data.size() > kMaxResponseBytes) {
        result.failure = AiFailure::MalformedResponse;
        result.detail = QStringLiteral("The answer exceeded the size limit.");
        return result;
    }

    const QJsonDocument document = QJsonDocument::fromJson(data);
    if (!document.isObject()) {
        result.failure = AiFailure::MalformedResponse;
        return result;
    }

    const QJsonObject root = document.object();
    const QJsonArray choices = root.value(QStringLiteral("choices")).toArray();
    if (choices.isEmpty() || !choices.first().isObject()) {
        result.failure = AiFailure::MalformedResponse;
        return result;
    }

    const QJsonObject message =
        choices.first().toObject().value(QStringLiteral("message")).toObject();
    const QString text =
        explanationFrom(message.value(QStringLiteral("content")));
    if (text.trimmed().isEmpty()) {
        result.failure = AiFailure::EmptyResponse;
        return result;
    }

    result.ok = true;
    result.text = text;
    result.model = root.value(QStringLiteral("model")).toString();
    if (result.model.isEmpty()) result.model = settings.model.trimmed();
    result.httpStatus = 200;
    return result;
}
