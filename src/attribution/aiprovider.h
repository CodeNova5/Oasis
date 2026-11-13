/**
 * @file    aiprovider.h
 * @brief   Optional AI provider interface (NG-045): an opt-in adapter that may
 *          explain an NG-044 context, with the local recommendation as the
 *          always-available fallback.
 * @author  Oasis
 *
 * AI is off unless the user turns it on and configures an endpoint and model.
 * The provider only ever receives the bounded, redacted `AiContext` document;
 * it cannot name a policy, choose a scope, or change enforcement. A response is
 * a block of explanation text and nothing else, so there is no code path from
 * provider output to a `NetworkPolicy`.
 *
 * Every failure — disabled, unconfigured, missing adapter, timeout, network or
 * HTTP error, malformed or empty response — returns the unchanged local
 * recommendation with a short reason, so a broken or slow provider degrades to
 * the deterministic behaviour instead of hiding it.
 */
#pragma once

#include <QString>
#include <QUrl>

#include "attribution/aicontext.h"
#include "attribution/recommendationengine.h"

class QSettings;

struct AiProviderSettings
{
    static constexpr int kMinTimeoutSeconds = 5;
    static constexpr int kMaxTimeoutSeconds = 60;
    static constexpr int kDefaultTimeoutSeconds = 20;
    static constexpr int kMinResponseCharacters = 200;
    static constexpr int kMaxResponseCharacters = 4000;
    static constexpr int kDefaultResponseCharacters = 1200;

    /// Off until the user explicitly opts in.
    bool enabled = false;
    /// Full chat-completions URL supplied by the user; no vendor is assumed.
    QString endpoint;
    QString model;
    int timeoutSeconds = kDefaultTimeoutSeconds;
    /// Hard cap on the explanation the app will display or keep.
    int responseCharacterLimit = kDefaultResponseCharacters;

    /// True only when AI is enabled and both the endpoint and the model are
    /// configured and acceptable.
    bool isUsable() const;

    /// Empty when the endpoint is acceptable. Plain HTTP is only allowed on the
    /// local machine, so a context can never be posted in the clear to a remote
    /// host.
    QString endpointProblem() const;
};

enum class AiFailure
{
    None,
    Disabled,           // the user has not opted in
    NotConfigured,      // enabled, but no endpoint/model or no API key
    UnsupportedEndpoint,// not HTTPS (or plain HTTP off the local machine)
    NoProvider,         // no adapter is installed
    Timeout,
    Network,
    HttpError,
    MalformedResponse,
    EmptyResponse
};

QString aiFailureToken(AiFailure failure);
QString aiFailureMessage(AiFailure failure);

/**
 * Persisted opt-in settings.
 *
 * The payload is a versioned JSON object (`schemaVersion` = 1) under one
 * QSettings key. A malformed or newer document, and a disabled-by-default
 * missing one, loads as the disabled defaults rather than half-applying a
 * configuration this build does not understand. No credential is stored here:
 * the adapter reads its key from the environment.
 */
class AiProviderSettingsStore
{
public:
    static constexpr int kSchemaVersion = 1;

    static QString settingsGroup();
    static QString settingsKey();

    AiProviderSettings load() const;
    AiProviderSettings load(QSettings &settings) const;

    bool save(const AiProviderSettings &settings) const;
    bool save(const AiProviderSettings &settings, QSettings &settingsStore) const;

    void reset() const;
    void reset(QSettings &settings) const;

    static QString toJson(const AiProviderSettings &settings);
    static AiProviderSettings fromJson(const QString &json, bool *ok = nullptr);
};

/// What one adapter returned. `text` is explanation only; there is deliberately
/// no policy, scope, rate, or enforcement field.
struct AiProviderResponse
{
    bool ok = false;
    AiFailure failure = AiFailure::None;
    QString text;
    QString model;
    /// Short diagnostic for the UI. Never contains the API key or the payload.
    QString detail;
    int httpStatus = 0;
};

class AiProvider
{
public:
    virtual ~AiProvider() = default;

    virtual QString name() const = 0;

    /**
     * Send `payload.json` (and nothing else) to the configured endpoint.
     *
     * Implementations must be side-effect free with respect to policy: they may
     * not create, change, or apply a `NetworkPolicy`, and they may not persist
     * the context. This call may block on the network, so a UI caller runs it
     * off the GUI thread.
     */
    virtual AiProviderResponse explain(const AiContextPayload &payload,
                                       const AiProviderSettings &settings) = 0;
};

/// The provider's contribution. Explanation text only; `fromProvider` is false
/// for the local-only result.
struct AiExplanation
{
    QString text;
    QString model;
    QString providerName;
    bool fromProvider = false;

    bool isEmpty() const { return text.trimmed().isEmpty(); }
};

enum class AiAssistStatus
{
    Disabled,    // the user has not opted in
    Unavailable, // enabled but not configured, or no adapter installed
    Failed,      // the provider was tried and did not produce an explanation
    Explained    // the provider produced bounded explanation text
};

QString aiAssistStatusToken(AiAssistStatus status);

/**
 * One answer to "explain this activity". `localRecommendation` is the caller's
 * input, copied unchanged; the provider cannot alter it, and `enforcesAnything()`
 * is always false.
 */
struct AiAssistResult
{
    AiAssistStatus status = AiAssistStatus::Disabled;
    AiExplanation explanation;
    Recommendation localRecommendation;
    QString detail;

    bool usedProvider() const { return status == AiAssistStatus::Explained; }
    bool degraded() const { return status != AiAssistStatus::Explained; }
    /// AI output is advice text only. Present so a caller cannot mistake it for
    /// an enforceable decision.
    bool enforcesAnything() const { return false; }
    QString summary() const;
};

/**
 * Opt-in coordinator. It owns no provider (the caller decides which adapter to
 * install and how long it lives) and applies no policy.
 */
class AiAssistant
{
public:
    /// Loads the persisted settings; with none stored, AI stays disabled.
    AiAssistant();
    explicit AiAssistant(const AiProviderSettings &settings);

    void setProvider(AiProvider *provider) { m_provider = provider; }
    AiProvider *provider() const { return m_provider; }

    void setSettings(const AiProviderSettings &settings) { m_settings = settings; }
    const AiProviderSettings &settings() const { return m_settings; }

    /// Persist the current settings. Returns false on a settings-backend error.
    bool saveSettings() const;
    void resetSettings();

    /**
     * Ask the provider to explain `context`, falling back to `local` on every
     * failure. `context` is bounded and redacted before the provider sees it;
     * the explanation is sanitised and capped at the configured character limit.
     */
    AiAssistResult explain(const AiContext &context,
                           const Recommendation &local) const;

private:
    AiProviderSettings m_settings;
    AiProvider *m_provider = nullptr;
};
