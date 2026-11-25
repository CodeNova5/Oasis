/**
 * @file    networkwidgetinsights.cpp
 * @author  Oasis
 *
 * NetworkWidget insights: the one-second dashboard beat and the read-only
 * snapshots the Overview, Applications and Connections pages render.
 */
#include "networkwidget_p.h"

namespace {

// ...the beat that rebuilds the dashboard and notifies the other pages.
Oasis::GuiTiming::Probe dashboardProbe("NetworkWidget::refreshDashboard");

} // namespace

void NetworkWidget::refreshDashboard()
{
    Oasis::GuiTiming::Scope timing(dashboardProbe);
    if (!m_dashboard || !m_model) return;

    const QList<NetworkPolicy> policies = PolicyStore::loadPolicies();

    QList<TopConsumers::Consumer> consumers;
    const int rows = m_model->rowCount();
    consumers.reserve(rows);
    for (int row = 0; row < rows; ++row) {
        const ProcessRowSnapshot snap = m_model->snapshotForRow(row);
        if (!snap.isValid()) continue;

        TopConsumers::Consumer consumer;
        consumer.pid = snap.pid;
        consumer.parentPid = snap.parentPid;
        consumer.icon = snap.icon;
        consumer.name = snap.name;
        consumer.identity = snap.identityName.trimmed().isEmpty()
            ? snap.publisher.trimmed() : snap.identityName.trimmed();
        consumer.path = snap.query.executablePath.trimmed();
        if (consumer.path.isEmpty() && snap.pid != 0) {
            // The model's row evidence carries the process name, not the image
            // path, so resolve it once per (pid, start time) rather than on
            // every beat or per action.
            const QString key = QStringLiteral("%1:%2")
                                    .arg(snap.pid).arg(snap.processStartMs);
            auto cached = m_dashboardPathCache.find(key);
            if (cached == m_dashboardPathCache.end()) {
                if (m_dashboardPathCache.size() >= 1024) m_dashboardPathCache.clear();
                cached = m_dashboardPathCache.insert(
                    key, getExactProcessPath(snap.pid, snap.name));
            }
            consumer.path = cached.value().trimmed();
        }
        consumer.rxBytes = snap.rxBytes;
        consumer.txBytes = snap.txBytes;
        consumer.rxBytesPerSecond = snap.rxBytesPerSecond;
        consumer.txBytesPerSecond = snap.txBytesPerSecond;
        if (snap.activity.isKnown()) consumer.activity = snap.activity.summary();
        consumer.foreground = snap.foreground != Oasis::ForegroundAssociation::None;

        if (!consumer.path.isEmpty()) {
            consumer.blocked = m_firewall && m_firewall->isBlocked(consumer.path);
            consumer.throttled = m_throttlePolicies &&
                m_throttlePolicies->isThrottled(consumer.path);
            if (consumer.throttled) {
                const QString policyId = m_throttlePolicies->policyAttribution().value(
                    ThrottlePolicyManager::normalizePath(consumer.path));
                for (const NetworkPolicy &policy : policies) {
                    if (policy.id != policyId) continue;
                    consumer.controlOwner = ApplicationDetail::policySummaryText(policy);
                    break;
                }
            }
        }

        consumers.append(consumer);
    }

    const QDateTime now = QDateTime::currentDateTime();
    TopConsumers::Summary summary = TopConsumers::build(consumers, policies, now);

    // Suggestions are computed for the rows the panel shows, not for every row:
    // a suggestion for row 40 is not part of the first view.
    bool addedSuggestion = false;
    for (const TopConsumers::Row &row : summary.rows) {
        for (TopConsumers::Consumer &consumer : consumers) {
            if (consumer.pid != row.pid || consumer.path != row.path) continue;

            ActivityClassification activity;
            const ActivityQuery query = queryAndActivityFor(
                consumer.pid, consumer.name, consumer.path, &activity);
            RecommendationContext context =
                recommendationContextFor(query, consumer.pid, consumer.name);
            context.activity = activity;

            const Recommendation recommendation = m_recommendationEngine.recommend(context);
            if (recommendation.action != RecommendationAction::NoAction) {
                consumer.recommendation = recommendation.title;
                QString reason = recommendation.whyLikely.trimmed();
                if (reason.isEmpty()) reason = recommendation.expectedEffect.trimmed();
                if (reason.size() > 100)
                    reason = reason.left(97) + QStringLiteral("...");
                consumer.recommendationReason = reason;
                addedSuggestion = true;
            }
            break;
        }
    }
    if (addedSuggestion) summary = TopConsumers::build(consumers, policies, now);

    m_dashboard->setSummary(summary);
    m_dashboardSummary = summary;
    emit dashboardUpdated(summary);
}

QList<Applications::Snapshot> NetworkWidget::applicationSnapshots() const
{
    QList<Applications::Snapshot> rows;
    if (!m_model)
        return rows;

    // Reuse the beat's consumers, which already carry rates, totals and the
    // (comparatively expensive) firewall/throttle lookups. Only the evidence
    // that is unique to this screen is resolved again, by pid, from the model.
    rows.reserve(m_dashboardSummary.consumers.size());
    // Read once per beat, not once per row: the Rule column only needs to
    // know whether an advisory Ask policy covers the application.
    const QList<NetworkPolicy> storedPolicies = PolicyStore::loadPolicies();
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (const TopConsumers::Consumer &consumer : m_dashboardSummary.consumers) {
        if (consumer.name.trimmed().isEmpty() && consumer.pid == 0)
            continue;

        Applications::Snapshot row;
        row.pid = consumer.pid;
        row.name = consumer.name;
        row.path = consumer.path;
        row.rxBytesPerSecond = consumer.rxBytesPerSecond;
        row.txBytesPerSecond = consumer.txBytesPerSecond;
        row.totalBytes = consumer.totalBytes();

        const int modelRow = consumer.pid != 0 ? m_model->rowForPid(consumer.pid) : -1;
        const ProcessRowSnapshot snap =
            modelRow >= 0 ? m_model->snapshotForRow(modelRow) : ProcessRowSnapshot();

        AttributionConfidenceModel::Confidence confidence =
            AttributionConfidenceModel::Confidence::Unknown;
        if (snap.isValid()) {
            row.icon = snap.icon.isNull() ? genericExecutableIcon() : snap.icon;
            if (!snap.name.isEmpty())
                row.name = snap.name;
            if (!snap.identityName.trimmed().isEmpty())
                row.displayName = snap.identityName;
            row.publisher = snap.publisher;
            row.services = snap.services;
            confidence = snap.activity.assessment.confidence;
        }
        row.identity = AttributionConfidenceModel::displayName(confidence);

        const bool system = !row.services.isEmpty() || consumer.pid == 0
                            || consumer.pid == 4;
        row.activity = Applications::activityState(system, consumer.foreground);
        row.policy = Applications::policyLabel(consumer.blocked, consumer.throttled);
        row.policyToken = Applications::policyTokenFor(consumer.blocked,
                                                       consumer.throttled);
        row.rule = QStringLiteral("allow");
        if (consumer.blocked) {
            row.rule = QStringLiteral("block");
        } else if (snap.isValid()) {
            // The model's activity query carries the name but not the image
            // path, and the Ask rule the user creates is path-scoped.
            ActivityQuery policyQuery = snap.query;
            if (policyQuery.executablePath.trimmed().isEmpty())
                policyQuery.executablePath = consumer.path;
            for (const NetworkPolicy &policy : storedPolicies) {
                if (!policy.enabled || policy.action != NetworkPolicy::Action::Ask)
                    continue;
                if (policy.expiration.isValid() && policy.expiration <= now)
                    continue;
                if (ApplicationDetail::policyTargets(policy, policyQuery, consumer.pid)) {
                    row.rule = QStringLiteral("ask");
                    break;
                }
            }
        }
        if (row.icon.isNull())
            row.icon = genericExecutableIcon();
        rows.append(row);
    }
    return rows;
}

QList<Connections::Row> NetworkWidget::connectionGroups() const
{
    QList<Connections::Row> groups;
    if (!m_model)
        return groups;

    // The beat's consumers already hold the resolved executable path and the
    // firewall/shaping state, so the page does not repeat those lookups.
    QHash<quint32, const TopConsumers::Consumer *> consumers;
    consumers.reserve(m_dashboardSummary.consumers.size());
    for (const TopConsumers::Consumer &consumer : m_dashboardSummary.consumers) {
        if (consumer.pid != 0)
            consumers.insert(consumer.pid, &consumer);
    }

    QHash<QString, int> groupIndex;
    QHash<QString, quint64> groupBytes;
    const int processRows = m_model->processCount();
    for (int processRow = 0; processRow < processRows; ++processRow) {
        const ProcessRowSnapshot snapshot = m_model->snapshotForRow(processRow);
        if (!snapshot.isValid())
            continue;

        const TopConsumers::Consumer *consumer = consumers.value(snapshot.pid, nullptr);
        for (const ConnectionStat &connection : snapshot.connections) {
            const QString address = connection.remoteAddress.trimmed();
            if (address.isEmpty())
                continue;

            QString domain = connection.domain.trimmed();
            if (domain.isEmpty() && !connection.domains.isEmpty())
                domain = connection.domains.first().trimmed();
            const QString destination = domain.isEmpty() ? address : domain;

            // Group by application identity, not by process instance or
            // destination. A browser runs one process per tab and site
            // isolation, so the table must show one application row with all
            // of its sockets underneath it.
            QString appKey = snapshot.identityId.trimmed();
            if (appKey.isEmpty())
                appKey = QStringLiteral("name:%1").arg(snapshot.name.trimmed().toLower());
            if (appKey == QLatin1String("name:"))
                appKey = QStringLiteral("pid:%1").arg(snapshot.pid);
            const QString id = appKey;
            const quint64 processBytes = snapshot.rxBytes + snapshot.txBytes;

            int index = groupIndex.value(id, -1);
            if (index < 0) {
                Connections::Row row;
                row.id = id;
                row.appKey = appKey;
                row.pid = snapshot.pid;
                row.processStartMs = snapshot.processStartMs;
                row.icon = snapshot.icon.isNull() ? genericExecutableIcon()
                                                  : snapshot.icon;
                row.appName = snapshot.name;
                row.displayName = snapshot.identityName;
                row.publisher = snapshot.publisher;
                row.path = consumer ? consumer->path : QString();
                if (row.appName.isEmpty() && !row.path.isEmpty())
                    row.appName = QFileInfo(row.path).fileName();
                if (row.displayName.trimmed().isEmpty())
                    row.displayName = row.appName;
                if (snapshot.activity.isKnown())
                    row.activity = snapshot.activity.summary();
                row.destination = destination;
                row.hasDomain = !domain.isEmpty();
                row.policy = consumer
                    ? Applications::policyLabel(consumer->blocked, consumer->throttled)
                    : QStringLiteral("None");
                row.policyToken = consumer
                    ? Applications::policyTokenFor(consumer->blocked, consumer->throttled)
                    : QStringLiteral("none");
                index = groups.size();
                groups.append(row);
                groupIndex.insert(id, index);
                groupBytes.insert(id, processBytes);
            }

            Connections::Row &row = groups[index];

            // Actions target one process, so keep the busiest instance of the
            // application as the representative for the grouped row.
            if (processBytes > groupBytes.value(id)) {
                groupBytes[id] = processBytes;
                row.pid = snapshot.pid;
                row.processStartMs = snapshot.processStartMs;
                row.path = consumer ? consumer->path : QString();
            }
            // Every instance of one identity resolves to the same executable
            // path, so an empty path can be filled from any of them.
            if (row.path.isEmpty() && consumer)
                row.path = consumer->path;

            // Prefer a resolved name when the first socket was only identified
            // by its address. Additional names remain available in the row's
            // domain list and expanded endpoint details.
            if (!row.hasDomain && !domain.isEmpty()) {
                row.destination = destination;
                row.hasDomain = true;
            }

            Connections::Endpoint endpoint;
            endpoint.address = address;
            endpoint.protocol = connection.key.protocol;
            // The remote side is the destination for uploads and the source for
            // downloads; the model already named that side in remoteAddress.
            endpoint.port = (address == connection.key.dstIP)
                                ? connection.key.dstPort
                                : connection.key.srcPort;
            endpoint.domain = connection.domain;
            endpoint.domainNames = connection.domains;
            endpoint.evidence = connection.domainEvidence;
            endpoint.source = connection.domainSource;
            endpoint.confidence = connection.domainConfidence;
            endpoint.rxBytes = connection.rxBytes;
            endpoint.txBytes = connection.txBytes;
            endpoint.rxBytesPerSecond = connection.rxSpeed;
            endpoint.txBytesPerSecond = connection.txSpeed;
            endpoint.packets = connection.packets;

            Connections::Endpoint *existingEndpoint = nullptr;
            for (Connections::Endpoint &candidate : row.endpoints) {
                if (candidate.address == endpoint.address
                    && candidate.port == endpoint.port
                    && candidate.protocol.compare(endpoint.protocol, Qt::CaseInsensitive) == 0) {
                    existingEndpoint = &candidate;
                    break;
                }
            }

            if (existingEndpoint) {
                existingEndpoint->rxBytes += endpoint.rxBytes;
                existingEndpoint->txBytes += endpoint.txBytes;
                existingEndpoint->rxBytesPerSecond += endpoint.rxBytesPerSecond;
                existingEndpoint->txBytesPerSecond += endpoint.txBytesPerSecond;
                existingEndpoint->packets += endpoint.packets;

                if (existingEndpoint->domain.isEmpty() && !endpoint.domain.isEmpty())
                    existingEndpoint->domain = endpoint.domain;
                for (const QString &name : endpoint.domainNames) {
                    if (!existingEndpoint->domainNames.contains(name, Qt::CaseInsensitive))
                        existingEndpoint->domainNames.append(name);
                }
                for (const QString &evidence : endpoint.evidence) {
                    if (!existingEndpoint->evidence.contains(evidence))
                        existingEndpoint->evidence.append(evidence);
                }

                if (Connections::confidenceRank(endpoint.confidence)
                    > Connections::confidenceRank(existingEndpoint->confidence)) {
                    existingEndpoint->source = endpoint.source;
                    existingEndpoint->confidence = endpoint.confidence;
                }
            } else {
                row.endpoints.append(endpoint);
            }

            if (!row.addresses.contains(address))
                row.addresses.append(address);
            for (const QString &name : connection.domains) {
                if (!row.domainNames.contains(name, Qt::CaseInsensitive))
                    row.domainNames.append(name);
            }
            row.rxBytes += connection.rxBytes;
            row.txBytes += connection.txBytes;
            row.rxBytesPerSecond += connection.rxSpeed;
            row.txBytesPerSecond += connection.txSpeed;
            row.packets += connection.packets;
        }
    }

    // Roll each group up once, after every socket has been added.
    for (Connections::Row &row : groups) {
        row.endpointCount = row.endpoints.size();
        row.direction = Connections::directionFor(row.rxBytes, row.txBytes);

        QSet<QString> portLabels;
        QSet<QString> protocols;
        for (const Connections::Endpoint &endpoint : row.endpoints) {
            portLabels.insert(QStringLiteral("%1 / %2")
                                  .arg(endpoint.port)
                                  .arg(endpoint.protocol));
            if (!endpoint.protocol.trimmed().isEmpty())
                protocols.insert(endpoint.protocol);
        }
        if (portLabels.size() == 1) {
            row.ports = *portLabels.constBegin();
        } else if (portLabels.size() > 1) {
            row.ports = protocols.size() == 1
                ? QStringLiteral("Multiple ports / %1").arg(*protocols.constBegin())
                : QStringLiteral("Multiple ports / protocols");
        } else {
            row.ports = QStringLiteral("—");
        }

        // The strongest single observation represents the group. Sources are
        // never combined across sockets, because a DNS answer on one address
        // and an SNI on another do not confirm either one.
        AttributionSource bestSource = AttributionSource::Unknown;
        ApplicationIdentity::Confidence bestConfidence =
            ApplicationIdentity::Confidence::Unknown;
        auto sourcePriority = [](AttributionSource source) {
            switch (source) {
            case AttributionSource::DnsAndTls: return 3;
            case AttributionSource::DnsAnswer: return 2;
            case AttributionSource::TlsSni:    return 2;
            case AttributionSource::Unknown:   break;
            }
            return 0;
        };
        for (const Connections::Endpoint &endpoint : row.endpoints) {
            const int rank = Connections::confidenceRank(endpoint.confidence);
            const int bestRank = Connections::confidenceRank(bestConfidence);
            if (rank > bestRank
                || (rank == bestRank
                    && sourcePriority(endpoint.source) > sourcePriority(bestSource))) {
                bestConfidence = endpoint.confidence;
                bestSource = endpoint.source;
            }
        }
        row.evidenceKey = Connections::sourceKey(bestSource);
        row.evidenceLabel = Connections::sourceLabel(bestSource);
        row.confidence = Connections::confidenceLabel(bestConfidence);
        row.confidenceRank = Connections::confidenceRank(bestConfidence);
    }

    return groups;
}

void NetworkWidget::refreshConnectionEvidence()
{
    if (m_model)
        m_model->refreshDomains();
    // refreshDashboard() rebuilds the beat and emits dashboardUpdated, which is
    // what the Connections page listens to; forcing one here makes the refresh
    // action visible even between beats.
    refreshDashboard();
}

Applications::Details NetworkWidget::applicationDetails(quint32 pid, const QString &executablePath,
                                                       const QString &processName)
{
    Applications::Details details;
    details.pid = pid;
    details.name = processName.trimmed();
    details.path = executablePath.trimmed();

    const int modelRow = (m_model && pid != 0) ? m_model->rowForPid(pid) : -1;
    const ProcessRowSnapshot snap =
        modelRow >= 0 ? m_model->snapshotForRow(modelRow) : ProcessRowSnapshot();
    if (snap.isValid()) {
        if (!snap.name.trimmed().isEmpty())
            details.name = snap.name;
        details.displayName = snap.identityName;
        details.publisher = snap.publisher;
        details.icon = snap.icon;
        details.uploadedBytes = snap.txBytes;
        details.downloadedBytes = snap.rxBytes;
        if (details.path.isEmpty())
            details.path = getExactProcessPath(snap.pid, snap.name);

        QSet<QString> addresses;
        for (const ConnectionStat &connection : snap.connections) {
            if (!connection.remoteAddress.trimmed().isEmpty())
                addresses.insert(connection.remoteAddress);
            const QString endpoint = connection.domain.trimmed().isEmpty()
                ? connection.remoteAddress
                : connection.domain.trimmed() + QStringLiteral(" · ")
                      + connection.remoteAddress;
            if (!endpoint.trimmed().isEmpty()
                && !details.endpoints.contains(endpoint, Qt::CaseInsensitive)
                && details.endpoints.size() < 40) {
                details.endpoints.append(endpoint);
            }
        }
        details.connectionCount = snap.connections.size();
        details.remoteAddressCount = addresses.size();
    }
    if (details.name.isEmpty() && !details.path.isEmpty())
        details.name = QFileInfo(details.path).fileName();
    if (details.icon.isNull())
        details.icon = genericExecutableIcon();

    if (!details.path.isEmpty()) {
        const QFileInfo file(details.path);
        // Qt 6 has no QFileInfo::created(); birthTime is the file's creation
        // date on Windows and is exactly what "Installed" should show.
        const QDateTime born = file.birthTime();
        if (born.isValid())
            details.installedAt = born;
        details.version =
            Oasis::ApplicationIdentityResolver::readVersionMetadata(details.path).fileVersion;
    }

    ActivityQuery query = snap.isValid() ? snap.query : ActivityQuery();
    if (query.executablePath.trimmed().isEmpty())
        query.executablePath = details.path;
    if (query.executableName.trimmed().isEmpty())
        query.executableName = details.name;

    details.rule = QStringLiteral("allow");
    if (m_firewall && !details.path.isEmpty() && m_firewall->isBlocked(details.path)) {
        details.rule = QStringLiteral("block");
    } else {
        const QDateTime now = QDateTime::currentDateTimeUtc();
        for (const NetworkPolicy &policy : PolicyStore::loadPolicies()) {
            if (!policy.enabled || policy.action != NetworkPolicy::Action::Ask)
                continue;
            if (policy.expiration.isValid() && policy.expiration <= now)
                continue;
            if (ApplicationDetail::policyTargets(policy, query, pid)) {
                details.rule = QStringLiteral("ask");
                break;
            }
        }
    }
    return details;
}
