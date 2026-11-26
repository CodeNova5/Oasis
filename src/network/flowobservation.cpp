/**
 * @file    flowobservation.cpp
 * @brief   Canonical Data Saver `FlowObservation` v1 and bounded aggregation.
 * @author  Oasis
 */
#include "flowobservation.h"

#include <QAbstractSocket>
#include <QCryptographicHash>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonValue>
#include <QRegularExpression>
#include <QUrl>

#include <limits>

namespace {

using Role = FlowProcessRole;
using Foreground = FlowForegroundState;
using Interaction = FlowInteractionState;
using DomainSource = FlowDomainSource;
using DomainConfidence = FlowDomainConfidence;

QString roleToken(Role role)
{
    switch (role) {
    case Role::Main: return QStringLiteral("main");
    case Role::Child: return QStringLiteral("child");
    case Role::Service: return QStringLiteral("service");
    case Role::Unknown: break;
    }
    return QStringLiteral("unknown");
}

bool roleFromToken(const QString &text, Role *role)
{
    if (text.compare(QStringLiteral("main"), Qt::CaseInsensitive) == 0) { if (role) *role = Role::Main; return true; }
    if (text.compare(QStringLiteral("child"), Qt::CaseInsensitive) == 0) { if (role) *role = Role::Child; return true; }
    if (text.compare(QStringLiteral("service"), Qt::CaseInsensitive) == 0) { if (role) *role = Role::Service; return true; }
    if (text.compare(QStringLiteral("unknown"), Qt::CaseInsensitive) == 0) { if (role) *role = Role::Unknown; return true; }
    return false;
}

QString foregroundToken(Foreground state)
{
    switch (state) {
    case Foreground::ForegroundActive: return QStringLiteral("foreground_active");
    case Foreground::ForegroundIdle: return QStringLiteral("foreground_idle");
    case Foreground::Background: return QStringLiteral("background");
    case Foreground::Unknown: break;
    }
    return QStringLiteral("unknown");
}

bool foregroundFromToken(const QString &text, Foreground *state)
{
    if (text.compare(QStringLiteral("foreground_active"), Qt::CaseInsensitive) == 0) { if (state) *state = Foreground::ForegroundActive; return true; }
    if (text.compare(QStringLiteral("foreground_idle"), Qt::CaseInsensitive) == 0) { if (state) *state = Foreground::ForegroundIdle; return true; }
    if (text.compare(QStringLiteral("background"), Qt::CaseInsensitive) == 0) { if (state) *state = Foreground::Background; return true; }
    if (text.compare(QStringLiteral("unknown"), Qt::CaseInsensitive) == 0) { if (state) *state = Foreground::Unknown; return true; }
    return false;
}

QString interactionToken(Interaction state)
{
    switch (state) {
    case Interaction::Interactive: return QStringLiteral("interactive");
    case Interaction::Idle: return QStringLiteral("idle");
    case Interaction::Unknown: break;
    }
    return QStringLiteral("unknown");
}

bool interactionFromToken(const QString &text, Interaction *state)
{
    if (text.compare(QStringLiteral("interactive"), Qt::CaseInsensitive) == 0) { if (state) *state = Interaction::Interactive; return true; }
    if (text.compare(QStringLiteral("idle"), Qt::CaseInsensitive) == 0) { if (state) *state = Interaction::Idle; return true; }
    if (text.compare(QStringLiteral("unknown"), Qt::CaseInsensitive) == 0) { if (state) *state = Interaction::Unknown; return true; }
    return false;
}

QString domainSourceToken(DomainSource source)
{
    switch (source) {
    case DomainSource::Dns: return QStringLiteral("dns");
    case DomainSource::Sni: return QStringLiteral("sni");
    case DomainSource::EchOuter: return QStringLiteral("ech_outer");
    case DomainSource::None: break;
    }
    return QStringLiteral("none");
}

bool domainSourceFromToken(const QString &text, DomainSource *source)
{
    if (text.compare(QStringLiteral("dns"), Qt::CaseInsensitive) == 0) { if (source) *source = DomainSource::Dns; return true; }
    if (text.compare(QStringLiteral("sni"), Qt::CaseInsensitive) == 0) { if (source) *source = DomainSource::Sni; return true; }
    if (text.compare(QStringLiteral("ech_outer"), Qt::CaseInsensitive) == 0) { if (source) *source = DomainSource::EchOuter; return true; }
    if (text.compare(QStringLiteral("none"), Qt::CaseInsensitive) == 0) { if (source) *source = DomainSource::None; return true; }
    return false;
}

QString domainConfidenceToken(DomainConfidence confidence)
{
    switch (confidence) {
    case DomainConfidence::Confirmed: return QStringLiteral("confirmed");
    case DomainConfidence::StrongInference: return QStringLiteral("strong_inference");
    case DomainConfidence::WeakInference: return QStringLiteral("weak_inference");
    case DomainConfidence::Unknown: break;
    }
    return QStringLiteral("unknown");
}

bool domainConfidenceFromToken(const QString &text, DomainConfidence *confidence)
{
    if (text.compare(QStringLiteral("confirmed"), Qt::CaseInsensitive) == 0) { if (confidence) *confidence = DomainConfidence::Confirmed; return true; }
    if (text.compare(QStringLiteral("strong_inference"), Qt::CaseInsensitive) == 0) { if (confidence) *confidence = DomainConfidence::StrongInference; return true; }
    if (text.compare(QStringLiteral("weak_inference"), Qt::CaseInsensitive) == 0) { if (confidence) *confidence = DomainConfidence::WeakInference; return true; }
    if (text.compare(QStringLiteral("unknown"), Qt::CaseInsensitive) == 0) { if (confidence) *confidence = DomainConfidence::Unknown; return true; }
    return false;
}

int confidenceRank(DomainConfidence confidence)
{
    switch (confidence) {
    case DomainConfidence::Confirmed: return 3;
    case DomainConfidence::StrongInference: return 2;
    case DomainConfidence::WeakInference: return 1;
    case DomainConfidence::Unknown: break;
    }
    return 0;
}

bool fail(QString *error, const QString &message)
{
    if (error) *error = message;
    return false;
}

bool readRequiredString(const QJsonObject &object, const QString &key, QString *value,
                        QString *error)
{
    const QJsonValue raw = object.value(key);
    if (!raw.isString() || raw.toString().isEmpty())
        return fail(error, QStringLiteral("missing or invalid \"%1\"").arg(key));
    if (value) *value = raw.toString();
    return true;
}

bool readOptionalString(const QJsonObject &object, const QString &key, QString *value)
{
    const QJsonValue raw = object.value(key);
    if (!raw.isString()) return false;
    if (value) *value = raw.toString();
    return true;
}

bool readRequiredBool(const QJsonObject &object, const QString &key, bool *value,
                      QString *error)
{
    const QJsonValue raw = object.value(key);
    if (!raw.isBool())
        return fail(error, QStringLiteral("missing or invalid \"%1\"").arg(key));
    if (value) *value = raw.toBool();
    return true;
}

bool readRequiredNonNegative(const QJsonObject &object, const QString &key, qint64 *value,
                             QString *error)
{
    const QJsonValue raw = object.value(key);
    if (!raw.isDouble())
        return fail(error, QStringLiteral("missing or invalid \"%1\"").arg(key));
    const qint64 parsed = raw.toInteger(-1);
    if (parsed < 0)
        return fail(error, QStringLiteral("\"%1\" must not be negative").arg(key));
    if (value) *value = parsed;
    return true;
}

bool readOptionalNonNegative(const QJsonObject &object, const QString &key, qint64 *value)
{
    const QJsonValue raw = object.value(key);
    if (!raw.isDouble()) return false;
    const qint64 parsed = raw.toInteger(-1);
    if (parsed < 0) return false;
    if (value) *value = parsed;
    return true;
}

// Accepts IPv4 and bracketed/unbracketed IPv6 literals.
bool splitEndpoint(const QString &endpoint, QString *address, quint16 *port)
{
    const QString text = endpoint.trimmed();
    QString host;
    QString portText;
    if (text.startsWith(QLatin1Char('['))) {
        const int close = text.indexOf(QLatin1Char(']'));
        if (close <= 1) return false;
        host = text.mid(1, close - 1);
        if (close + 1 >= text.size() || text.at(close + 1) != QLatin1Char(':')) return false;
        portText = text.mid(close + 2);
    } else {
        const int colon = text.lastIndexOf(QLatin1Char(':'));
        if (colon <= 0 || text.indexOf(QLatin1Char(':')) != colon) return false;
        host = text.left(colon);
        portText = text.mid(colon + 1);
    }
    bool portOk = false;
    const int parsedPort = portText.toInt(&portOk);
    if (!portOk || parsedPort < 0 || parsedPort > 65535) return false;
    QHostAddress parsed;
    if (!parsed.setAddress(host)) return false;
    if (address) *address = host;
    if (port) *port = static_cast<quint16>(parsedPort);
    return true;
}

QString normalizedBaseName(const QString &name)
{
    QString base = name.trimmed();
    const int slash = base.lastIndexOf(QLatin1Char('/'));
    const int backslash = base.lastIndexOf(QLatin1Char('\\'));
    const int cut = qMax(slash, backslash);
    if (cut >= 0) base = base.mid(cut + 1);
    return base.trimmed();
}

QString hashedId(const QString &prefix, const QString &material)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(material.toUtf8());
    return prefix + QString::fromLatin1(hash.result().toHex().left(16));
}

} // namespace

QString flowEndpoint(const QString &address, quint16 port)
{
    const QString trimmed = address.trimmed();
    QHostAddress parsed;
    if (trimmed.isEmpty() || !parsed.setAddress(trimmed)) return QString();
    const QString host = parsed.protocol() == QAbstractSocket::IPv6Protocol
                             ? QStringLiteral("[%1]").arg(trimmed)
                             : trimmed;
    return QStringLiteral("%1:%2").arg(host).arg(port);
}

QString normalizeFlowDomain(const QString &domain)
{
    QString text = domain.trimmed().toLower();
    while (text.endsWith(QLatin1Char('.'))) text.chop(1);
    if (text.isEmpty() || text.size() > 253) return QString();
    if (text.contains(QLatin1Char('/')) || text.contains(QLatin1Char('*'))
        || text.contains(QLatin1Char(':')) || text.contains(QLatin1Char(' ')))
        return QString();
    const QString ace = QUrl::toAce(text);
    if (ace.isEmpty()) return QString();
    const QString normalized = ace.toLower();
    return normalized.size() <= 253 ? normalized : QString();
}

bool isFlowIdentifier(const QString &id, const QString &prefix)
{
    static const QRegularExpression hex(QStringLiteral("^[0-9a-f]{8,32}$"));
    if (!id.startsWith(prefix)) return false;
    return hex.match(id.mid(prefix.size())).hasMatch();
}

QJsonObject toJson(const FlowObservation &observation)
{
    QJsonObject object;
    object.insert(QStringLiteral("schemaVersion"), FlowObservation::kSchemaVersion);
    object.insert(QStringLiteral("observationId"), observation.observationId);
    object.insert(QStringLiteral("timestamp"),
                  observation.timestamp.toUTC().toString(Qt::ISODate));

    QJsonObject process;
    process.insert(QStringLiteral("processInstanceId"), observation.process.processInstanceId);
    process.insert(QStringLiteral("pid"), static_cast<qint64>(observation.process.pid));
    process.insert(QStringLiteral("parentPid"), static_cast<qint64>(observation.process.parentPid));
    if (!observation.process.identityId.isEmpty())
        process.insert(QStringLiteral("identityId"), observation.process.identityId);
    process.insert(QStringLiteral("exeName"), observation.process.exeName);
    if (!observation.process.exePath.isEmpty())
        process.insert(QStringLiteral("exePath"), observation.process.exePath);
    if (!observation.process.exeVersion.isEmpty())
        process.insert(QStringLiteral("exeVersion"), observation.process.exeVersion);
    process.insert(QStringLiteral("processRole"), roleToken(observation.process.role));
    process.insert(QStringLiteral("foregroundState"), foregroundToken(observation.process.foregroundState));
    if (observation.process.foregroundRootPid != 0)
        process.insert(QStringLiteral("foregroundRootPid"),
                       static_cast<qint64>(observation.process.foregroundRootPid));
    if (observation.process.interactionState != Interaction::Unknown)
        process.insert(QStringLiteral("interactionState"),
                       interactionToken(observation.process.interactionState));
    object.insert(QStringLiteral("process"), process);

    QJsonObject flow;
    flow.insert(QStringLiteral("flowId"), observation.flow.flowId);
    flow.insert(QStringLiteral("protocol"), observation.flow.protocol);
    flow.insert(QStringLiteral("localEndpoint"), observation.flow.localEndpoint);
    flow.insert(QStringLiteral("remoteEndpoint"), observation.flow.remoteEndpoint);
    if (!observation.flow.domain.isEmpty()) {
        flow.insert(QStringLiteral("domain"), observation.flow.domain);
        flow.insert(QStringLiteral("domainSource"), domainSourceToken(observation.flow.domainSource));
        flow.insert(QStringLiteral("domainConfidence"), domainConfidenceToken(observation.flow.domainConfidence));
    }
    flow.insert(QStringLiteral("multiplexed"), observation.flow.multiplexed);
    flow.insert(QStringLiteral("shared"), observation.flow.shared);
    object.insert(QStringLiteral("flow"), flow);

    QJsonObject metrics;
    metrics.insert(QStringLiteral("rxBytes"), static_cast<qint64>(observation.metrics.rxBytes));
    metrics.insert(QStringLiteral("txBytes"), static_cast<qint64>(observation.metrics.txBytes));
    metrics.insert(QStringLiteral("durationMs"), observation.metrics.durationMs);
    metrics.insert(QStringLiteral("rateRxBitsPerSecond"),
                   static_cast<qint64>(observation.metrics.rateRxBitsPerSecond));
    metrics.insert(QStringLiteral("milestoneBytes"),
                   static_cast<qint64>(observation.metrics.milestoneBytes));
    metrics.insert(QStringLiteral("milestoneIndex"), observation.metrics.milestoneIndex);
    object.insert(QStringLiteral("metrics"), metrics);

    QJsonObject ux;
    ux.insert(QStringLiteral("blockingToUser"), observation.uxSignals.blockingToUser);
    ux.insert(QStringLiteral("latencySensitive"), observation.uxSignals.latencySensitive);
    ux.insert(QStringLiteral("deferrable"), observation.uxSignals.deferrable);
    ux.insert(QStringLiteral("avoidable"), observation.uxSignals.avoidable);
    ux.insert(QStringLiteral("detectorTags"), QJsonArray::fromStringList(observation.uxSignals.detectorTags));
    object.insert(QStringLiteral("uxSignals"), ux);
    return object;
}

bool fromJson(const QJsonObject &object, FlowObservation *observation, QString *error)
{
    if (error) error->clear();

    // §1: no schemaVersion means v1; a newer payload is rejected whole.
    const QJsonValue versionValue = object.value(QStringLiteral("schemaVersion"));
    if (!versionValue.isUndefined()) {
        if (!versionValue.isDouble())
            return fail(error, QStringLiteral("invalid schemaVersion"));
        const qint64 parsed = versionValue.toInteger(-1);
        if (parsed < 1)
            return fail(error, QStringLiteral("invalid schemaVersion"));
        if (parsed > FlowObservation::kSchemaVersion)
            return fail(error, QStringLiteral("unsupported newer schemaVersion %1").arg(parsed));
    }

    FlowObservation parsed;
    if (!readRequiredString(object, QStringLiteral("observationId"), &parsed.observationId, error))
        return false;
    if (!isFlowIdentifier(parsed.observationId, QStringLiteral("obs_")))
        return fail(error, QStringLiteral("invalid observationId"));

    QString timestampText;
    if (!readRequiredString(object, QStringLiteral("timestamp"), &timestampText, error))
        return false;
    parsed.timestamp = QDateTime::fromString(timestampText, Qt::ISODate);
    if (!parsed.timestamp.isValid())
        return fail(error, QStringLiteral("invalid timestamp"));
    parsed.timestamp = parsed.timestamp.toUTC();

    const QJsonValue processValue = object.value(QStringLiteral("process"));
    if (!processValue.isObject())
        return fail(error, QStringLiteral("missing process object"));
    const QJsonObject processObject = processValue.toObject();
    if (!readRequiredString(processObject, QStringLiteral("processInstanceId"),
                            &parsed.process.processInstanceId, error))
        return false;
    static const QRegularExpression instancePattern(QStringLiteral("^pid:[1-9][0-9]*:[0-9]+$"));
    if (!instancePattern.match(parsed.process.processInstanceId).hasMatch())
        return fail(error, QStringLiteral("invalid processInstanceId"));

    qint64 number = 0;
    if (!readRequiredNonNegative(processObject, QStringLiteral("pid"), &number, error))
        return false;
    parsed.process.pid = static_cast<quint32>(qMin<qint64>(number, 0xFFFFFFFF));
    if (parsed.process.pid == 0)
        return fail(error, QStringLiteral("invalid pid"));
    const QString instancePrefix = QStringLiteral("pid:%1:").arg(parsed.process.pid);
    if (!parsed.process.processInstanceId.startsWith(instancePrefix))
        return fail(error, QStringLiteral("processInstanceId does not match pid"));

    if (readOptionalNonNegative(processObject, QStringLiteral("parentPid"), &number))
        parsed.process.parentPid = static_cast<quint32>(qMin<qint64>(number, 0xFFFFFFFF));

    readOptionalString(processObject, QStringLiteral("identityId"), &parsed.process.identityId);
    if (!readRequiredString(processObject, QStringLiteral("exeName"), &parsed.process.exeName, error))
        return false;
    if (parsed.process.exeName.contains(QLatin1Char('/'))
        || parsed.process.exeName.contains(QLatin1Char('\\')))
        return fail(error, QStringLiteral("exeName must be a base name"));
    readOptionalString(processObject, QStringLiteral("exePath"), &parsed.process.exePath);
    readOptionalString(processObject, QStringLiteral("exeVersion"), &parsed.process.exeVersion);

    if (processObject.contains(QStringLiteral("processRole"))) {
        const QJsonValue roleValue = processObject.value(QStringLiteral("processRole"));
        if (!roleValue.isString()
            || !roleFromToken(roleValue.toString(), &parsed.process.role))
            return fail(error, QStringLiteral("invalid processRole"));
    }

    QString foregroundText;
    if (!readRequiredString(processObject, QStringLiteral("foregroundState"),
                            &foregroundText, error))
        return false;
    if (!foregroundFromToken(foregroundText, &parsed.process.foregroundState))
        return fail(error, QStringLiteral("invalid foregroundState"));

    if (readOptionalNonNegative(processObject, QStringLiteral("foregroundRootPid"), &number))
        parsed.process.foregroundRootPid = static_cast<quint32>(qMin<qint64>(number, 0xFFFFFFFF));

    if (processObject.contains(QStringLiteral("interactionState"))) {
        const QJsonValue interactionValue = processObject.value(QStringLiteral("interactionState"));
        if (!interactionValue.isString()
            || !interactionFromToken(interactionValue.toString(),
                                     &parsed.process.interactionState))
            return fail(error, QStringLiteral("invalid interactionState"));
    }

    const QJsonValue flowValue = object.value(QStringLiteral("flow"));
    if (!flowValue.isObject())
        return fail(error, QStringLiteral("missing flow object"));
    const QJsonObject flowObject = flowValue.toObject();
    if (!readRequiredString(flowObject, QStringLiteral("flowId"), &parsed.flow.flowId, error))
        return false;
    if (!isFlowIdentifier(parsed.flow.flowId, QStringLiteral("flow_")))
        return fail(error, QStringLiteral("invalid flowId"));
    if (!readRequiredString(flowObject, QStringLiteral("protocol"), &parsed.flow.protocol, error))
        return false;

    QString endpointAddress;
    quint16 endpointPort = 0;
    if (!readRequiredString(flowObject, QStringLiteral("localEndpoint"),
                            &parsed.flow.localEndpoint, error)
        || !splitEndpoint(parsed.flow.localEndpoint, &endpointAddress, &endpointPort))
        return fail(error, QStringLiteral("invalid localEndpoint"));
    if (!readRequiredString(flowObject, QStringLiteral("remoteEndpoint"),
                            &parsed.flow.remoteEndpoint, error)
        || !splitEndpoint(parsed.flow.remoteEndpoint, &endpointAddress, &endpointPort))
        return fail(error, QStringLiteral("invalid remoteEndpoint"));

    if (flowObject.contains(QStringLiteral("domain"))) {
        QString domainText;
        if (!readOptionalString(flowObject, QStringLiteral("domain"), &domainText))
            return fail(error, QStringLiteral("invalid domain"));
        parsed.flow.domain = normalizeFlowDomain(domainText);
        if (parsed.flow.domain.isEmpty())
            return fail(error, QStringLiteral("invalid domain"));

        QString sourceText;
        if (!readRequiredString(flowObject, QStringLiteral("domainSource"), &sourceText, error)
            || !domainSourceFromToken(sourceText, &parsed.flow.domainSource)
            || parsed.flow.domainSource == DomainSource::None)
            return fail(error, QStringLiteral("invalid domainSource"));

        QString confidenceText;
        if (!readRequiredString(flowObject, QStringLiteral("domainConfidence"),
                                &confidenceText, error)
            || !domainConfidenceFromToken(confidenceText, &parsed.flow.domainConfidence)
            || parsed.flow.domainConfidence == DomainConfidence::Unknown)
            return fail(error, QStringLiteral("invalid domainConfidence"));
    } else {
        // A source/confidence without a name is contradictory evidence.
        if (flowObject.contains(QStringLiteral("domainSource"))
            || flowObject.contains(QStringLiteral("domainConfidence")))
            return fail(error, QStringLiteral("domain evidence without a domain"));
    }

    if (!readRequiredBool(flowObject, QStringLiteral("multiplexed"),
                          &parsed.flow.multiplexed, error)
        || !readRequiredBool(flowObject, QStringLiteral("shared"), &parsed.flow.shared, error))
        return false;

    const QJsonValue metricsValue = object.value(QStringLiteral("metrics"));
    if (!metricsValue.isObject())
        return fail(error, QStringLiteral("missing metrics object"));
    const QJsonObject metricsObject = metricsValue.toObject();
    if (!readRequiredNonNegative(metricsObject, QStringLiteral("rxBytes"), &number, error))
        return false;
    parsed.metrics.rxBytes = static_cast<quint64>(number);
    if (!readRequiredNonNegative(metricsObject, QStringLiteral("txBytes"), &number, error))
        return false;
    parsed.metrics.txBytes = static_cast<quint64>(number);
    if (!readRequiredNonNegative(metricsObject, QStringLiteral("durationMs"), &number, error))
        return false;
    parsed.metrics.durationMs = number;
    if (!readRequiredNonNegative(metricsObject, QStringLiteral("rateRxBitsPerSecond"),
                                 &number, error))
        return false;
    parsed.metrics.rateRxBitsPerSecond = static_cast<quint64>(number);
    if (!readRequiredNonNegative(metricsObject, QStringLiteral("milestoneBytes"),
                                 &number, error))
        return false;
    parsed.metrics.milestoneBytes = static_cast<quint64>(number);
    if (!readRequiredNonNegative(metricsObject, QStringLiteral("milestoneIndex"),
                                 &number, error))
        return false;
    parsed.metrics.milestoneIndex = static_cast<int>(qMin<qint64>(number, 0x7FFFFFFF));

    const QJsonValue uxValue = object.value(QStringLiteral("uxSignals"));
    if (!uxValue.isObject())
        return fail(error, QStringLiteral("missing uxSignals object"));
    const QJsonObject uxObject = uxValue.toObject();
    if (!readRequiredBool(uxObject, QStringLiteral("blockingToUser"),
                          &parsed.uxSignals.blockingToUser, error)
        || !readRequiredBool(uxObject, QStringLiteral("latencySensitive"),
                             &parsed.uxSignals.latencySensitive, error)
        || !readRequiredBool(uxObject, QStringLiteral("deferrable"),
                             &parsed.uxSignals.deferrable, error)
        || !readRequiredBool(uxObject, QStringLiteral("avoidable"),
                             &parsed.uxSignals.avoidable, error))
        return false;

    const QJsonValue tagsValue = uxObject.value(QStringLiteral("detectorTags"));
    if (!tagsValue.isArray())
        return fail(error, QStringLiteral("missing detectorTags"));
    const QJsonArray tags = tagsValue.toArray();
    if (tags.size() > FlowObservation::UxSignalFields::kMaxDetectorTags)
        return fail(error, QStringLiteral("too many detectorTags"));
    for (const QJsonValue &tag : tags) {
        if (!tag.isString())
            return fail(error, QStringLiteral("invalid detectorTags entry"));
        const QString text = tag.toString();
        if (text.isEmpty()
            || text.size() > FlowObservation::UxSignalFields::kMaxDetectorTagLength)
            return fail(error, QStringLiteral("invalid detectorTags entry"));
        parsed.uxSignals.detectorTags.append(text);
    }

    if (observation) *observation = parsed;
    return true;
}

FlowObservationBuilder::FlowObservationBuilder(quint64 sessionNonce, int maxFlows)
    : m_nonce(sessionNonce != 0
                  ? sessionNonce
                  : (static_cast<quint64>(QDateTime::currentMSecsSinceEpoch()) << 17)
                        ^ static_cast<quint64>(quintptr(this)))
    , m_maxFlows(qMax(1, maxFlows))
{
}

void FlowObservationBuilder::setDestinationName(const QString &address, const QString &name,
                                                FlowDomainSource source,
                                                FlowDomainConfidence confidence,
                                                bool multiplexed)
{
    const QString normalized = normalizeFlowDomain(name);
    if (address.trimmed().isEmpty() || normalized.isEmpty()
        || source == FlowDomainSource::None
        || confidence == FlowDomainConfidence::Unknown)
        return;

    QMutexLocker locker(&m_mutex);
    const QString key = address.trimmed();
    const bool existing = m_destinations.contains(key);
    if (!existing && m_destinations.size() >= 2048)
        return; // bounded; keep the evidence already collected
    DestinationEvidence evidence = m_destinations.value(key);
    if (existing && confidenceRank(confidence) < confidenceRank(evidence.confidence))
        return; // never downgrade evidence for an address
    evidence.name = normalized;
    evidence.source = source;
    evidence.confidence = confidence;
    evidence.multiplexed = evidence.multiplexed || multiplexed;
    m_destinations.insert(key, evidence);
}

void FlowObservationBuilder::addSample(const FlowCaptureSample &sample)
{
    const QString exeName = normalizedBaseName(sample.processName);
    const QString protocol = sample.protocol.trimmed();
    const QString localEndpoint = flowEndpoint(sample.localAddress, sample.localPort);
    const QString remoteEndpoint = flowEndpoint(sample.remoteAddress, sample.remotePort);

    if (sample.pid == 0 || exeName.isEmpty() || protocol.isEmpty()
        || localEndpoint.isEmpty() || remoteEndpoint.isEmpty()
        || !sample.timestamp.isValid()) {
        QMutexLocker locker(&m_mutex);
        ++m_droppedSamples;
        return;
    }

    const QString processInstanceId =
        QStringLiteral("pid:%1:%2").arg(sample.pid).arg(qMax<qint64>(0, sample.processStartMs));
    const QString endpointKey =
        QStringLiteral("%1|%2|%3").arg(protocol, localEndpoint, remoteEndpoint);
    const QString flowKey = endpointKey + QLatin1Char('|') + processInstanceId;

    QMutexLocker locker(&m_mutex);
    auto it = m_flows.find(flowKey);
    if (it == m_flows.end()) {
        while (m_flows.size() >= m_maxFlows)
            evictOldestLocked();

        FlowState state;
        // The creation sequence makes a re-established connection a new flow
        // even when the endpoints and process instance are unchanged.
        state.flowId = hashedId(QStringLiteral("flow_"),
                                QStringLiteral("%1|%2|%3|%4|%5")
                                    .arg(m_nonce).arg(m_flowSequence++)
                                    .arg(endpointKey, processInstanceId)
                                    .arg(sample.processStartMs));
        state.endpointKey = endpointKey;
        state.protocol = protocol;
        state.localEndpoint = localEndpoint;
        state.remoteEndpoint = remoteEndpoint;
        state.processInstanceId = processInstanceId;
        state.pid = sample.pid;
        state.startMs = sample.monotonicMs;
        state.lastMs = sample.monotonicMs;
        state.lastRateMs = sample.monotonicMs;
        it = m_flows.insert(flowKey, state);
        m_endpointOwners[endpointKey].insert(processInstanceId);
    }

    FlowState &flow = it.value();
    flow.pid = sample.pid;
    flow.parentPid = sample.parentPid;
    flow.foregroundRootPid = sample.foregroundRootPid;
    flow.identityId = sample.identityId;
    flow.exeName = exeName;
    flow.exePath = sample.executablePath;
    flow.exeVersion = sample.executableVersion;
    flow.multiplexed = flow.multiplexed || sample.multiplexed;
    flow.lastTimestamp = sample.timestamp;
    if (sample.milestoneIndex > 0 || sample.milestoneBytes > 0) {
        flow.milestoneBytes = sample.milestoneBytes;
        flow.milestoneIndex = sample.milestoneIndex;
    }

    switch (sample.foreground) {
    case FlowCaptureSample::Foreground::App:
        flow.role = FlowProcessRole::Main;
        flow.foregroundState = FlowForegroundState::ForegroundActive;
        flow.interactionState = FlowInteractionState::Interactive;
        break;
    case FlowCaptureSample::Foreground::Child:
        flow.role = FlowProcessRole::Child;
        flow.foregroundState = FlowForegroundState::ForegroundActive;
        flow.interactionState = FlowInteractionState::Interactive;
        break;
    case FlowCaptureSample::Foreground::None:
        flow.role = sample.service ? FlowProcessRole::Service : FlowProcessRole::Unknown;
        flow.foregroundState = FlowForegroundState::Background;
        flow.interactionState = FlowInteractionState::Idle;
        break;
    case FlowCaptureSample::Foreground::Unknown:
        flow.role = sample.service ? FlowProcessRole::Service : FlowProcessRole::Unknown;
        flow.foregroundState = FlowForegroundState::Unknown;
        flow.interactionState = FlowInteractionState::Unknown;
        break;
    }
    if (sample.service && flow.role == FlowProcessRole::Unknown)
        flow.role = FlowProcessRole::Service;

    if (sample.download)
        flow.rxBytes += sample.bytes;
    else
        flow.txBytes += sample.bytes;

    if (sample.monotonicMs < flow.startMs)
        flow.startMs = sample.monotonicMs;
    if (sample.monotonicMs > flow.lastMs) {
        const qint64 elapsed = sample.monotonicMs - flow.lastRateMs;
        if (elapsed >= 50) {
            flow.rateRxBitsPerSecond =
                (flow.rxBytes - flow.lastRateRx) * 8000ULL / static_cast<quint64>(elapsed);
            flow.lastRateRx = flow.rxBytes;
            flow.lastRateMs = sample.monotonicMs;
        }
        flow.lastMs = sample.monotonicMs;
    }
}

void FlowObservationBuilder::expireIdleFlows(qint64 nowMs, qint64 maxIdleMs)
{
    QMutexLocker locker(&m_mutex);
    const QList<QString> keys = m_flows.keys();
    for (const QString &key : keys) {
        const FlowState &flow = m_flows[key];
        if (nowMs - flow.lastMs > maxIdleMs)
            removeFlowLocked(key);
    }
}

QList<FlowObservation> FlowObservationBuilder::observations() const
{
    QMutexLocker locker(&m_mutex);
    QList<FlowObservation> list;
    list.reserve(m_flows.size());
    for (auto it = m_flows.constBegin(); it != m_flows.constEnd(); ++it) {
        const FlowState &state = it.value();
        FlowObservation observation;
        observation.observationId = mintObservationId(state.flowId);
        observation.timestamp = state.lastTimestamp;

        observation.process.processInstanceId = state.processInstanceId;
        observation.process.pid = state.pid;
        observation.process.parentPid = state.parentPid;
        observation.process.identityId = state.identityId;
        observation.process.exeName = state.exeName;
        observation.process.exePath = state.exePath;
        observation.process.exeVersion = state.exeVersion;
        observation.process.role = state.role;
        observation.process.foregroundState = state.foregroundState;
        observation.process.foregroundRootPid = state.foregroundRootPid;
        observation.process.interactionState = state.interactionState;

        observation.flow.flowId = state.flowId;
        observation.flow.protocol = state.protocol;
        observation.flow.localEndpoint = state.localEndpoint;
        observation.flow.remoteEndpoint = state.remoteEndpoint;
        observation.flow.multiplexed = state.multiplexed;
        observation.flow.shared = m_endpointOwners.value(state.endpointKey).size() > 1;

        QString remoteAddress;
        quint16 remotePort = 0;
        if (splitEndpoint(state.remoteEndpoint, &remoteAddress, &remotePort)) {
            const auto evidence = m_destinations.constFind(remoteAddress);
            if (evidence != m_destinations.constEnd()) {
                observation.flow.domain = evidence->name;
                observation.flow.domainSource = evidence->source;
                observation.flow.domainConfidence = evidence->confidence;
                observation.flow.multiplexed =
                    observation.flow.multiplexed || evidence->multiplexed;
            }
        }

        observation.metrics.rxBytes = state.rxBytes;
        observation.metrics.txBytes = state.txBytes;
        observation.metrics.durationMs = qMax<qint64>(0, state.lastMs - state.startMs);
        observation.metrics.rateRxBitsPerSecond = state.rateRxBitsPerSecond;
        observation.metrics.milestoneBytes = state.milestoneBytes;
        observation.metrics.milestoneIndex = state.milestoneIndex;

        list.append(observation);
    }
    return list;
}

int FlowObservationBuilder::flowCount() const
{
    QMutexLocker locker(&m_mutex);
    return m_flows.size();
}

int FlowObservationBuilder::droppedSamples() const
{
    QMutexLocker locker(&m_mutex);
    return m_droppedSamples;
}

int FlowObservationBuilder::evictedFlows() const
{
    QMutexLocker locker(&m_mutex);
    return m_evictedFlows;
}

void FlowObservationBuilder::reset()
{
    QMutexLocker locker(&m_mutex);
    m_flows.clear();
    m_endpointOwners.clear();
    m_destinations.clear();
    m_sequence = 0;
    m_flowSequence = 0;
    m_droppedSamples = 0;
    m_evictedFlows = 0;
}

QString FlowObservationBuilder::mintObservationId(const QString &flowId) const
{
    return hashedId(QStringLiteral("obs_"),
                    QStringLiteral("%1|%2|%3")
                        .arg(m_nonce).arg(m_sequence++).arg(flowId));
}

void FlowObservationBuilder::evictOldestLocked()
{
    QString oldestKey;
    qint64 oldest = std::numeric_limits<qint64>::max();
    for (auto it = m_flows.constBegin(); it != m_flows.constEnd(); ++it) {
        if (it->lastMs < oldest) {
            oldest = it->lastMs;
            oldestKey = it.key();
        }
    }
    if (!oldestKey.isEmpty())
        removeFlowLocked(oldestKey);
}

void FlowObservationBuilder::removeFlowLocked(const QString &key)
{
    const auto it = m_flows.find(key);
    if (it == m_flows.end()) return;
    const QString endpointKey = it->endpointKey;
    const QString processInstanceId = it->processInstanceId;
    m_flows.erase(it);

    auto owners = m_endpointOwners.find(endpointKey);
    if (owners != m_endpointOwners.end()) {
        owners->remove(processInstanceId);
        if (owners->isEmpty())
            m_endpointOwners.erase(owners);
    }
    ++m_evictedFlows;
}
