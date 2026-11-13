/**
 * @file    aiprovider.cpp
 * @brief   Optional AI provider interface (NG-045).
 * @author  Oasis
 */
#include "aiprovider.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>

namespace {

const QString kSettingsGroup = QStringLiteral("Oasis/AiProvider");
const QString kSettingsKey = QStringLiteral("settings");

int clampedTimeout(int seconds)
{
    return qBound(AiProviderSettings::kMinTimeoutSeconds, seconds,
                  AiProviderSettings::kMaxTimeoutSeconds);
}

int clampedResponseCharacters(int characters)
{
    return qBound(AiProviderSettings::kMinResponseCharacters, characters,
                  AiProviderSettings::kMaxResponseCharacters);
}

bool isLoopbackHost(const QString &host)
{
    const QString normalized = host.trimmed().toLower();
    return normalized == QStringLiteral("localhost")
        || normalized == QStringLiteral("127.0.0.1")
        || normalized == QStringLiteral("::1")
        || normalized == QStringLiteral("[::1]");
}

/// Explanation text: printable, newlines preserved, tabs flattened, bounded.
QString sanitizedExplanation(const QString &text, int limit)
{
    QString cleaned;
    cleaned.reserve(text.size());
    for (const QChar c : text) {
        if (c == QLatin1Char('\r')) continue;
        if (c == QLatin1Char('\n')) {
            cleaned.append(QLatin1Char('\n'));
        } else if (c == QLatin1Char('\t')) {
            cleaned.append(QLatin1Char(' '));
        } else if (c.isPrint()) {
            cleaned.append(c);
        }
    }
    cleaned = cleaned.trimmed();
    if (limit > 3 && cleaned.size() > limit)
        cleaned = cleaned.left(limit - 3) + QStringLiteral("...");
    return cleaned;
}

} // namespace

// ─── Settings ──────────────────────────────────────────────────────────────

bool AiProviderSettings::isUsable() const
{
    return enabled && !model.trimmed().isEmpty() && endpointProblem().isEmpty();
}

QString AiProviderSettings::endpointProblem() const
{
    const QString trimmed = endpoint.trimmed();
    if (trimmed.isEmpty()) return QStringLiteral("No AI endpoint is configured.");

    const QUrl url(trimmed);
    if (!url.isValid() || url.host().isEmpty())
        return QStringLiteral("The AI endpoint is not a valid URL.");

    const QString scheme = url.scheme().toLower();
    if (scheme == QStringLiteral("https")) return QString();
    if (scheme == QStringLiteral("http") && isLoopbackHost(url.host()))
        return QString();
    if (scheme == QStringLiteral("http"))
        return QStringLiteral(
            "The endpoint must use HTTPS; plain HTTP is only allowed on this machine.");
    return QStringLiteral("The AI endpoint must use HTTPS.");
}

QString aiFailureToken(AiFailure failure)
{
    switch (failure) {
    case AiFailure::Disabled:            return QStringLiteral("disabled");
    case AiFailure::NotConfigured:       return QStringLiteral("not-configured");
    case AiFailure::UnsupportedEndpoint: return QStringLiteral("unsupported-endpoint");
    case AiFailure::NoProvider:          return QStringLiteral("no-provider");
    case AiFailure::Timeout:             return QStringLiteral("timeout");
    case AiFailure::Network:             return QStringLiteral("network");
    case AiFailure::HttpError:           return QStringLiteral("http-error");
    case AiFailure::MalformedResponse:   return QStringLiteral("malformed-response");
    case AiFailure::EmptyResponse:       return QStringLiteral("empty-response");
    case AiFailure::None:                break;
    }
    return QStringLiteral("none");
}

QString aiFailureMessage(AiFailure failure)
{
    switch (failure) {
    case AiFailure::Disabled:
        return QStringLiteral("AI assistance is turned off.");
    case AiFailure::NotConfigured:
        return QStringLiteral("No AI endpoint, model, or API key is configured.");
    case AiFailure::UnsupportedEndpoint:
        return QStringLiteral("The AI endpoint was refused: it must use HTTPS.");
    case AiFailure::NoProvider:
        return QStringLiteral("No AI provider is installed.");
    case AiFailure::Timeout:
        return QStringLiteral("The AI provider did not answer in time.");
    case AiFailure::Network:
        return QStringLiteral("The AI provider could not be reached.");
    case AiFailure::HttpError:
        return QStringLiteral("The AI provider returned an error.");
    case AiFailure::MalformedResponse:
        return QStringLiteral("The AI provider returned an unreadable answer.");
    case AiFailure::EmptyResponse:
        return QStringLiteral("The AI provider returned an empty explanation.");
    case AiFailure::None:
        break;
    }
    return QStringLiteral("The AI provider did not answer.");
}

// ─── Settings store ────────────────────────────────────────────────────────

QString AiProviderSettingsStore::settingsGroup()
{
    return kSettingsGroup;
}

QString AiProviderSettingsStore::settingsKey()
{
    return kSettingsKey;
}

AiProviderSettings AiProviderSettingsStore::load() const
{
    QSettings settings;
    return load(settings);
}

AiProviderSettings AiProviderSettingsStore::load(QSettings &settings) const
{
    settings.beginGroup(kSettingsGroup);
    const QString stored = settings.value(kSettingsKey).toString();
    settings.endGroup();
    return fromJson(stored);
}

bool AiProviderSettingsStore::save(const AiProviderSettings &settings) const
{
    QSettings store;
    return save(settings, store);
}

bool AiProviderSettingsStore::save(const AiProviderSettings &settings,
                                   QSettings &store) const
{
    store.beginGroup(kSettingsGroup);
    store.setValue(kSettingsKey, toJson(settings));
    store.endGroup();
    store.sync();
    return store.status() == QSettings::NoError;
}

void AiProviderSettingsStore::reset() const
{
    QSettings settings;
    reset(settings);
}

void AiProviderSettingsStore::reset(QSettings &settings) const
{
    settings.beginGroup(kSettingsGroup);
    settings.remove(QString());
    settings.endGroup();
    settings.sync();
}

QString AiProviderSettingsStore::toJson(const AiProviderSettings &settings)
{
    QJsonObject root;
    root[QStringLiteral("schemaVersion")] = kSchemaVersion;
    root[QStringLiteral("enabled")] = settings.enabled;
    root[QStringLiteral("endpoint")] = settings.endpoint.trimmed();
    root[QStringLiteral("model")] = settings.model.trimmed();
    root[QStringLiteral("timeoutSeconds")] = clampedTimeout(settings.timeoutSeconds);
    root[QStringLiteral("responseCharacterLimit")] =
        clampedResponseCharacters(settings.responseCharacterLimit);
    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Compact));
}

AiProviderSettings AiProviderSettingsStore::fromJson(const QString &json, bool *ok)
{
    AiProviderSettings settings;   // disabled defaults
    if (ok) *ok = false;

    const QJsonDocument document = QJsonDocument::fromJson(json.toUtf8());
    if (!document.isObject()) return settings;
    const QJsonObject root = document.object();

    // A newer schema may give a field a new meaning, so it is rejected as a
    // whole and the disabled defaults apply.
    const int schemaVersion =
        root.value(QStringLiteral("schemaVersion")).toInt(kSchemaVersion);
    if (schemaVersion > kSchemaVersion) return settings;

    settings.enabled = root.value(QStringLiteral("enabled")).toBool(false);
    settings.endpoint =
        root.value(QStringLiteral("endpoint")).toString().trimmed();
    settings.model = root.value(QStringLiteral("model")).toString().trimmed();
    settings.timeoutSeconds = clampedTimeout(
        root.value(QStringLiteral("timeoutSeconds"))
            .toInt(AiProviderSettings::kDefaultTimeoutSeconds));
    settings.responseCharacterLimit = clampedResponseCharacters(
        root.value(QStringLiteral("responseCharacterLimit"))
            .toInt(AiProviderSettings::kDefaultResponseCharacters));

    if (ok) *ok = true;
    return settings;
}

// ─── Result ────────────────────────────────────────────────────────────────

QString aiAssistStatusToken(AiAssistStatus status)
{
    switch (status) {
    case AiAssistStatus::Disabled:    return QStringLiteral("disabled");
    case AiAssistStatus::Unavailable: return QStringLiteral("unavailable");
    case AiAssistStatus::Failed:      return QStringLiteral("failed");
    case AiAssistStatus::Explained:   return QStringLiteral("explained");
    }
    return QStringLiteral("disabled");
}

QString AiAssistResult::summary() const
{
    switch (status) {
    case AiAssistStatus::Explained: {
        QString from = explanation.providerName;
        if (!explanation.model.isEmpty()) {
            from += QStringLiteral(" (%1)").arg(explanation.model);
        }
        return QStringLiteral("AI explanation from %1.").arg(from);
    }
    case AiAssistStatus::Disabled:
        return QStringLiteral("AI assistance is off; showing the local recommendation.");
    case AiAssistStatus::Unavailable:
    case AiAssistStatus::Failed:
        break;
    }
    return QStringLiteral("Showing the local recommendation: %1").arg(detail);
}

// ─── Assistant ─────────────────────────────────────────────────────────────

AiAssistant::AiAssistant()
    : m_settings(AiProviderSettingsStore().load())
{
}

AiAssistant::AiAssistant(const AiProviderSettings &settings)
    : m_settings(settings)
{
}

bool AiAssistant::saveSettings() const
{
    return AiProviderSettingsStore().save(m_settings);
}

void AiAssistant::resetSettings()
{
    AiProviderSettingsStore().reset();
    m_settings = AiProviderSettings();
}

AiAssistResult AiAssistant::explain(const AiContext &context,
                                    const Recommendation &local) const
{
    AiAssistResult result;
    // The local advice is the answer unless a provider adds an explanation to
    // it; this copy is never handed back to the provider.
    result.localRecommendation = local;

    if (!m_settings.enabled) {
        result.status = AiAssistStatus::Disabled;
        result.detail = aiFailureMessage(AiFailure::Disabled);
        return result;
    }

    const QString endpointProblem = m_settings.endpointProblem();
    if (!endpointProblem.isEmpty()) {
        result.status = AiAssistStatus::Unavailable;
        result.detail = endpointProblem;
        return result;
    }

    if (m_settings.model.trimmed().isEmpty()) {
        result.status = AiAssistStatus::Unavailable;
        result.detail = aiFailureMessage(AiFailure::NotConfigured);
        return result;
    }

    if (!m_provider) {
        result.status = AiAssistStatus::Unavailable;
        result.detail = aiFailureMessage(AiFailure::NoProvider);
        return result;
    }

    // Only the bounded, redacted document is ever handed to an adapter.
    const AiContextPayload payload = context.boundedJson();
    const AiProviderResponse response = m_provider->explain(payload, m_settings);

    if (!response.ok) {
        result.status = AiAssistStatus::Failed;
        result.detail = response.detail.isEmpty()
            ? aiFailureMessage(response.failure)
            : aiFailureMessage(response.failure) + QLatin1Char(' ') + response.detail;
        return result;
    }

    const QString text = sanitizedExplanation(
        response.text, m_settings.responseCharacterLimit);
    if (text.isEmpty()) {
        result.status = AiAssistStatus::Failed;
        result.detail = aiFailureMessage(AiFailure::EmptyResponse);
        return result;
    }

    result.status = AiAssistStatus::Explained;
    result.explanation.text = text;
    result.explanation.model =
        response.model.isEmpty() ? m_settings.model : response.model;
    result.explanation.providerName = m_provider->name();
    result.explanation.fromProvider = true;
    return result;
}
