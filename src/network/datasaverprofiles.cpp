/**
 * @file    datasaverprofiles.cpp
 * @brief   Local signatures and profile rules for Data Saver (DS-006).
 * @author  Oasis
 */
#include "datasaverprofiles.h"

#include <QSet>

using Action = NetworkPolicy::Action;

namespace {

double confidenceValue(ApplicationIdentity::Confidence confidence)
{
    switch (confidence) {
    case ApplicationIdentity::Confidence::Confirmed: return 0.95;
    case ApplicationIdentity::Confidence::StrongInference: return 0.80;
    case ApplicationIdentity::Confidence::WeakInference: return 0.60;
    case ApplicationIdentity::Confidence::Unknown: break;
    }
    return 0.30;
}

ProfileForeground foregroundFor(const FlowObservation &observation)
{
    switch (observation.process.foregroundState) {
    case FlowForegroundState::ForegroundActive:
        if (observation.process.interactionState == FlowInteractionState::Interactive)
            return ProfileForeground::Active;
        if (observation.process.interactionState == FlowInteractionState::Idle)
            return ProfileForeground::Idle;
        // Visible but without interaction evidence is not proof of idle, and it
        // is never inferred from a window title or a transfer rate.
        return ProfileForeground::Unknown;
    case FlowForegroundState::ForegroundIdle:
        return ProfileForeground::Idle;
    case FlowForegroundState::Background:
        return ProfileForeground::Background;
    case FlowForegroundState::Unknown:
        break;
    }
    return ProfileForeground::Unknown;
}

bool foregroundMatches(ProfileForeground rule, ProfileForeground actual)
{
    switch (rule) {
    case ProfileForeground::Any: return true;
    case ProfileForeground::Foreground:
        return actual == ProfileForeground::Active || actual == ProfileForeground::Idle;
    case ProfileForeground::Active: return actual == ProfileForeground::Active;
    case ProfileForeground::Idle: return actual == ProfileForeground::Idle;
    case ProfileForeground::Background: return actual == ProfileForeground::Background;
    case ProfileForeground::Unknown: return actual == ProfileForeground::Unknown;
    }
    return false;
}

bool validScope(const QString &scope)
{
    return scope == QStringLiteral("flow") || scope == QStringLiteral("domain")
           || scope == QStringLiteral("executable") || scope == QStringLiteral("group");
}

bool validateProfileRules(const QList<ProfileRule> &rules, QString *error)
{
    QSet<QString> ids;
    for (const ProfileRule &rule : rules) {
        if (rule.id.trimmed().isEmpty() || rule.detectorTag.trimmed().isEmpty()) {
            if (error) *error = QStringLiteral("a profile rule needs an id and a detector tag");
            return false;
        }
        if (ids.contains(rule.id)) {
            if (error) *error = QStringLiteral("duplicate profile rule id");
            return false;
        }
        ids.insert(rule.id);

        switch (rule.action) {
        case Action::Allow:
        case Action::Notify:
        case Action::Throttle:
        case Action::Block:
            break;
        case Action::Ask:
        case Action::Schedule:
        case Action::NoAction:
            if (error) *error = QStringLiteral("unsupported profile action");
            return false;
        }
        if (!validScope(rule.scope)) {
            if (error) *error = QStringLiteral("invalid profile scope");
            return false;
        }
        if (rule.action == Action::Throttle && rule.rateBitsPerSecond == 0) {
            if (error) *error = QStringLiteral("a throttling profile rule needs a positive rate");
            return false;
        }
        if (rule.minimumConfidence < 0.0 || rule.minimumConfidence > 1.0) {
            if (error) *error = QStringLiteral("invalid profile confidence floor");
            return false;
        }
    }
    return true;
}

QString profileRuleId(const QString &tag, ProfileForeground foreground)
{
    return QStringLiteral("profile_%1_%2").arg(tag, profileForegroundToken(foreground));
}

ProfileRule makeRule(const QString &tag, ProfileForeground foreground,
                     SignatureClassification classification, Action action,
                     bool continueAfterNotify = false, quint64 rate = 0,
                     bool advisoryOnly = false)
{
    ProfileRule rule;
    rule.id = profileRuleId(tag, foreground);
    rule.detectorTag = tag;
    rule.foreground = foreground;
    rule.classification = classification;
    rule.action = action;
    rule.continueAfterNotify = continueAfterNotify;
    rule.scope = QStringLiteral("executable");
    rule.rateBitsPerSecond = rate;
    rule.advisoryOnly = advisoryOnly;
    return rule;
}

void mergeTag(QStringList *tags, const QString &tag)
{
    if (tags && !tag.isEmpty() && !tags->contains(tag))
        tags->append(tag);
}

} // namespace

QString signatureClassificationToken(SignatureClassification classification)
{
    switch (classification) {
    case SignatureClassification::AppUpdate: return QStringLiteral("app_update");
    case SignatureClassification::ExtensionUpdate: return QStringLiteral("extension_update");
    case SignatureClassification::PackageInstall: return QStringLiteral("package_install");
    case SignatureClassification::AiInference: return QStringLiteral("ai_inference");
    case SignatureClassification::MediaStream: return QStringLiteral("media_stream");
    case SignatureClassification::Telemetry: return QStringLiteral("telemetry");
    case SignatureClassification::PolicyAction: return QStringLiteral("policy_action");
    case SignatureClassification::Unknown: break;
    }
    return QStringLiteral("unknown");
}

bool signatureClassificationFromToken(const QString &text,
                                      SignatureClassification *classification)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("app_update")) { if (classification) *classification = SignatureClassification::AppUpdate; return true; }
    if (token == QStringLiteral("extension_update")) { if (classification) *classification = SignatureClassification::ExtensionUpdate; return true; }
    if (token == QStringLiteral("package_install")) { if (classification) *classification = SignatureClassification::PackageInstall; return true; }
    if (token == QStringLiteral("ai_inference")) { if (classification) *classification = SignatureClassification::AiInference; return true; }
    if (token == QStringLiteral("media_stream")) { if (classification) *classification = SignatureClassification::MediaStream; return true; }
    if (token == QStringLiteral("telemetry")) { if (classification) *classification = SignatureClassification::Telemetry; return true; }
    if (token == QStringLiteral("policy_action")) { if (classification) *classification = SignatureClassification::PolicyAction; return true; }
    if (token == QStringLiteral("unknown")) { if (classification) *classification = SignatureClassification::Unknown; return true; }
    return false;
}

QString profileForegroundToken(ProfileForeground foreground)
{
    switch (foreground) {
    case ProfileForeground::Any: return QStringLiteral("any");
    case ProfileForeground::Foreground: return QStringLiteral("foreground");
    case ProfileForeground::Active: return QStringLiteral("active");
    case ProfileForeground::Idle: return QStringLiteral("idle");
    case ProfileForeground::Background: return QStringLiteral("background");
    case ProfileForeground::Unknown: return QStringLiteral("unknown");
    }
    return QStringLiteral("unknown");
}

bool profileForegroundFromToken(const QString &text, ProfileForeground *foreground)
{
    const QString token = text.trimmed().toLower();
    if (token == QStringLiteral("any")) { if (foreground) *foreground = ProfileForeground::Any; return true; }
    if (token == QStringLiteral("foreground")) { if (foreground) *foreground = ProfileForeground::Foreground; return true; }
    if (token == QStringLiteral("active")) { if (foreground) *foreground = ProfileForeground::Active; return true; }
    if (token == QStringLiteral("idle")) { if (foreground) *foreground = ProfileForeground::Idle; return true; }
    if (token == QStringLiteral("background")) { if (foreground) *foreground = ProfileForeground::Background; return true; }
    if (token == QStringLiteral("unknown")) { if (foreground) *foreground = ProfileForeground::Unknown; return true; }
    return false;
}

QList<ProfileRule> defaultProfileRules()
{
    QList<ProfileRule> rules;

    // Safety rules come first so they win over any general tag rule.
    rules << makeRule(QStringLiteral("protected_signature"), ProfileForeground::Any,
                      SignatureClassification::Unknown, Action::Allow, false, 0, true);
    rules << makeRule(QStringLiteral("latency_sensitive_signature"), ProfileForeground::Any,
                      SignatureClassification::Unknown, Action::Notify, true, 0, true);

    // Interactive package installs are allowed; background installs notify.
    rules << makeRule(QStringLiteral("package_install_signature"), ProfileForeground::Active,
                      SignatureClassification::PackageInstall, Action::Allow, false, 0, true);
    rules << makeRule(QStringLiteral("package_install_signature"), ProfileForeground::Idle,
                      SignatureClassification::PackageInstall, Action::Notify, true, 0, true);
    rules << makeRule(QStringLiteral("package_install_signature"), ProfileForeground::Background,
                      SignatureClassification::PackageInstall, Action::Notify, true, 0, true);

    // Known background updaters may use the canonical gentle throttle.
    const quint64 gentleRate = 409600;
    rules << makeRule(QStringLiteral("windows_update_signature"), ProfileForeground::Background,
                      SignatureClassification::AppUpdate, Action::Throttle, false, gentleRate);
    rules << makeRule(QStringLiteral("browser_update_signature"), ProfileForeground::Background,
                      SignatureClassification::AppUpdate, Action::Throttle, false, gentleRate);
    rules << makeRule(QStringLiteral("extension_update_signature"), ProfileForeground::Background,
                      SignatureClassification::ExtensionUpdate, Action::Throttle, false, gentleRate);
    rules << makeRule(QStringLiteral("app_update_signature"), ProfileForeground::Background,
                      SignatureClassification::AppUpdate, Action::Throttle, false, gentleRate);

    // A foreground updater is never throttled; it continues after a notice.
    rules << makeRule(QStringLiteral("windows_update_signature"), ProfileForeground::Foreground,
                      SignatureClassification::AppUpdate, Action::Notify, true, 0, true);
    rules << makeRule(QStringLiteral("browser_update_signature"), ProfileForeground::Foreground,
                      SignatureClassification::AppUpdate, Action::Notify, true, 0, true);
    rules << makeRule(QStringLiteral("extension_update_signature"), ProfileForeground::Foreground,
                      SignatureClassification::ExtensionUpdate, Action::Notify, true, 0, true);
    rules << makeRule(QStringLiteral("app_update_signature"), ProfileForeground::Foreground,
                      SignatureClassification::AppUpdate, Action::Notify, true, 0, true);

    rules << makeRule(QStringLiteral("media_stream_signature"), ProfileForeground::Foreground,
                      SignatureClassification::MediaStream, Action::Allow, false, 0, true);
    rules << makeRule(QStringLiteral("media_stream_signature"), ProfileForeground::Background,
                      SignatureClassification::MediaStream, Action::Notify, true, 0, true);

    rules << makeRule(QStringLiteral("background_transfer_signature"),
                      ProfileForeground::Background, SignatureClassification::Unknown,
                      Action::Notify, true, 0, true);
    rules << makeRule(QStringLiteral("interactive_application_signature"),
                      ProfileForeground::Foreground, SignatureClassification::Unknown,
                      Action::Notify, true, 0, true);
    rules << makeRule(QStringLiteral("security_application_signature"),
                      ProfileForeground::Background, SignatureClassification::Unknown,
                      Action::Notify, true, 0, true);
    rules << makeRule(QStringLiteral("foreground_download_signature"),
                      ProfileForeground::Foreground, SignatureClassification::Unknown,
                      Action::Notify, true, 0, true);

    rules << makeRule(QStringLiteral("unknown_signature"), ProfileForeground::Background,
                      SignatureClassification::Unknown, Action::Notify, true, 0, true);
    rules << makeRule(QStringLiteral("unknown_signature"), ProfileForeground::Unknown,
                      SignatureClassification::Unknown, Action::Notify, true, 0, true);
    rules << makeRule(QStringLiteral("unknown_signature"), ProfileForeground::Any,
                      SignatureClassification::Unknown, Action::Notify, true, 0, true);
    return rules;
}

LocalSignatureEngine::LocalSignatureEngine()
    : m_classifier()
    , m_profileRules(defaultProfileRules())
{
}

LocalSignatureEngine::LocalSignatureEngine(const EndpointCatalog &catalog,
                                           const QList<ProfileRule> &profileRules)
    : m_classifier(catalog)
    , m_profileRules(validateProfileRules(profileRules, nullptr) ? profileRules
                                                                 : defaultProfileRules())
{
}

bool LocalSignatureEngine::setProfileRules(const QList<ProfileRule> &profileRules,
                                           QString *error)
{
    if (!validateProfileRules(profileRules, error))
        return false;
    m_profileRules = profileRules;
    return true;
}

SignatureResult LocalSignatureEngine::classify(const LocalSignatureInput &input) const
{
    SignatureResult result;
    result.foreground = foregroundFor(input.observation);

    ActivityQuery query = input.activity;
    if (query.executableName.isEmpty())
        query.executableName = input.observation.process.exeName;
    if (query.executablePath.isEmpty())
        query.executablePath = input.observation.process.exePath;
    if (query.identityId.isEmpty())
        query.identityId = input.observation.process.identityId;
    if (query.domain.isEmpty())
        query.domain = input.observation.flow.domain;
    query.service = query.service
                    || input.observation.process.role == FlowProcessRole::Service;
    query.foreground = result.foreground == ProfileForeground::Active
                       || result.foreground == ProfileForeground::Idle;
    query.bytesPerSecond = input.observation.metrics.rateRxBitsPerSecond / 8ULL;

    const ActivityClassification classification = m_classifier.classify(query);
    result.confidence = confidenceValue(classification.assessment.confidence);

    for (const CatalogMatch &match : classification.matchedRules) {
        if (!match.ruleId.isEmpty())
            result.matchedSignatureIds.append(match.ruleId);
        if (!match.explanation.isEmpty())
            result.evidence.append(match.explanation);
    }
    for (const QString &evidence : classification.evidence)
        result.evidence.append(evidence);

    switch (classification.category) {
    case CatalogCategory::WindowsUpdate:
        result.classification = SignatureClassification::AppUpdate;
        mergeTag(&result.detectorTags, QStringLiteral("windows_update_signature"));
        mergeTag(&result.detectorTags, QStringLiteral("app_update_signature"));
        break;
    case CatalogCategory::BrowserUpdate:
        result.classification = SignatureClassification::AppUpdate;
        mergeTag(&result.detectorTags, QStringLiteral("browser_update_signature"));
        mergeTag(&result.detectorTags, QStringLiteral("app_update_signature"));
        for (const CatalogMatch &match : classification.matchedRules) {
            if (match.explanation.contains(QStringLiteral("extension"), Qt::CaseInsensitive)) {
                result.classification = SignatureClassification::ExtensionUpdate;
                mergeTag(&result.detectorTags, QStringLiteral("extension_update_signature"));
                break;
            }
        }
        break;
    case CatalogCategory::BackgroundTransfer:
        result.classification = SignatureClassification::AppUpdate;
        mergeTag(&result.detectorTags, QStringLiteral("background_transfer_signature"));
        mergeTag(&result.detectorTags, QStringLiteral("app_update_signature"));
        break;
    case CatalogCategory::CloudSync:
        mergeTag(&result.detectorTags, QStringLiteral("cloud_sync_signature"));
        mergeTag(&result.detectorTags, QStringLiteral("background_transfer_signature"));
        break;
    case CatalogCategory::PackageManager:
        result.classification = SignatureClassification::PackageInstall;
        mergeTag(&result.detectorTags, QStringLiteral("package_install_signature"));
        break;
    case CatalogCategory::Media:
        result.classification = SignatureClassification::MediaStream;
        mergeTag(&result.detectorTags, QStringLiteral("media_stream_signature"));
        break;
    case CatalogCategory::Browser:
    case CatalogCategory::GameLauncher:
    case CatalogCategory::DeveloperTool:
    case CatalogCategory::Communication:
    case CatalogCategory::RemoteAccess:
        mergeTag(&result.detectorTags, QStringLiteral("interactive_application_signature"));
        break;
    case CatalogCategory::Security:
        mergeTag(&result.detectorTags, QStringLiteral("security_application_signature"));
        break;
    case CatalogCategory::ForegroundDownload:
        mergeTag(&result.detectorTags, QStringLiteral("foreground_download_signature"));
        break;
    case CatalogCategory::Unknown:
        break;
    }

    // Reuse the shipped BandwidthGuard rules for protected services and for the
    // updater/interactive split the product already knows.
    ClassificationEvidence evidence;
    evidence.pid = input.observation.process.pid;
    evidence.processName = query.executableName;
    evidence.executablePath = query.executablePath;
    evidence.identityId = query.identityId;
    evidence.displayName = query.displayName;
    evidence.publisher = query.publisher;
    evidence.signerStatus = query.publisherVerified
                                ? ApplicationIdentity::SignerStatus::Signed
                                : ApplicationIdentity::SignerStatus::Unknown;
    evidence.isService = query.service
                         || input.observation.process.role == FlowProcessRole::Service;
    const ProcessClassification process = BandwidthGuard::classifyWithEvidence(evidence);
    const bool protectedExecutable = input.protectedExecutable
                                     || process.category == ProcessCategory::Protected;
    const double processConfidence = confidenceValue(process.confidence);
    if (processConfidence > result.confidence)
        result.confidence = processConfidence;
    for (const QString &line : process.evidence)
        result.evidence.append(line);

    if (protectedExecutable) {
        mergeTag(&result.detectorTags, QStringLiteral("protected_signature"));
        result.matchedSignatureIds.append(QStringLiteral("bandwidth:protected"));
    } else if (classification.category == CatalogCategory::Unknown) {
        if (process.category == ProcessCategory::AutoCandidate) {
            result.classification = SignatureClassification::AppUpdate;
            mergeTag(&result.detectorTags, QStringLiteral("app_update_signature"));
            result.matchedSignatureIds.append(QStringLiteral("bandwidth:auto-candidate"));
        } else if (process.category == ProcessCategory::AskFirst) {
            mergeTag(&result.detectorTags, QStringLiteral("interactive_application_signature"));
            result.matchedSignatureIds.append(QStringLiteral("bandwidth:ask-first"));
        }
    }

    const bool latencySensitive = input.latencySensitive
                                  || input.observation.uxSignals.latencySensitive;
    if (latencySensitive) {
        mergeTag(&result.detectorTags, QStringLiteral("latency_sensitive_signature"));
        result.evidence.append(QStringLiteral("The activity is marked latency-sensitive."));
    }
    for (const QString &tag : input.observation.uxSignals.detectorTags)
        mergeTag(&result.detectorTags, tag);

    if (result.detectorTags.isEmpty())
        mergeTag(&result.detectorTags, QStringLiteral("unknown_signature"));
    if (result.classification == SignatureClassification::Unknown
        && result.matchedSignatureIds.isEmpty()) {
        mergeTag(&result.detectorTags, QStringLiteral("unknown_signature"));
    }

    result.matched = !result.matchedSignatureIds.isEmpty()
                     || result.classification != SignatureClassification::Unknown;

    const ProfileRule *selected = nullptr;
    for (const ProfileRule &rule : m_profileRules) {
        if (!result.detectorTags.contains(rule.detectorTag)) continue;
        if (!foregroundMatches(rule.foreground, result.foreground)) continue;
        if (result.confidence + 1e-9 < rule.minimumConfidence) continue;
        selected = &rule;
        break;
    }

    if (selected) {
        result.profileRuleId = selected->id;
        result.action = selected->action;
        result.continueAfterNotify = selected->continueAfterNotify;
        result.scope = selected->scope;
        result.rateBitsPerSecond = selected->rateBitsPerSecond;
        result.advisoryOnly = selected->advisoryOnly;
    } else {
        result.action = Action::Notify;
        result.continueAfterNotify = true;
        result.scope = QStringLiteral("executable");
        result.advisoryOnly = true;
    }

    QStringList guards;
    auto downgrade = [&](const QString &reason) {
        if (result.action != Action::Throttle && result.action != Action::Block)
            return;
        result.action = Action::Notify;
        result.continueAfterNotify = true;
        result.rateBitsPerSecond = 0;
        result.advisoryOnly = true;
        guards.append(reason);
    };

    if (protectedExecutable) {
        if (result.action != Action::Allow) {
            result.action = Action::Allow;
            result.continueAfterNotify = false;
            result.rateBitsPerSecond = 0;
            result.advisoryOnly = true;
            guards.append(QStringLiteral("protected executable"));
        }
    }
    if (latencySensitive)
        downgrade(QStringLiteral("latency-sensitive activity"));
    if (result.classification == SignatureClassification::PackageInstall
        || input.interactivePackageInstall) {
        downgrade(QStringLiteral("package install"));
    }
    if (result.foreground == ProfileForeground::Active)
        downgrade(QStringLiteral("foreground-active application"));
    if (result.classification == SignatureClassification::Unknown)
        downgrade(QStringLiteral("unknown activity"));

    if (result.action == Action::Block) {
        const bool weakDomain =
            input.observation.flow.domain.isEmpty()
            || input.observation.flow.domainConfidence == FlowDomainConfidence::WeakInference
            || input.observation.flow.domainConfidence == FlowDomainConfidence::Unknown;
        const bool shared = input.observation.flow.shared
                            || input.observation.flow.multiplexed;
        if (result.confidence < 0.85 || result.scope != QStringLiteral("executable")
            || weakDomain || shared) {
            result.action = Action::Notify;
            result.continueAfterNotify = true;
            result.scope = QStringLiteral("executable");
            result.rateBitsPerSecond = 0;
            result.advisoryOnly = true;
            guards.append(QStringLiteral("block guard"));
        }
    }

    if (result.action == Action::Throttle && result.rateBitsPerSecond == 0)
        result.rateBitsPerSecond = 409600;
    else if (result.action != Action::Throttle)
        result.rateBitsPerSecond = 0;
    if (result.action != Action::Notify)
        result.continueAfterNotify = false;
    if (result.action == Action::Allow || result.action == Action::Notify)
        result.advisoryOnly = true;

    QStringList reason;
    if (!result.matchedSignatureIds.isEmpty())
        reason << QStringLiteral("signatures: %1").arg(result.matchedSignatureIds.join(QStringLiteral(", ")));
    else
        reason << QStringLiteral("no local signature matched");
    if (!result.profileRuleId.isEmpty())
        reason << QStringLiteral("profile rule: %1").arg(result.profileRuleId);
    else
        reason << QStringLiteral("conservative default");
    reason << QStringLiteral("foreground: %1").arg(profileForegroundToken(result.foreground));
    if (!guards.isEmpty())
        reason << QStringLiteral("guards: %1").arg(guards.join(QStringLiteral(", ")));
    result.reason = reason.join(QStringLiteral("; "));

    return result;
}
