/**
 * @file    activityservice.cpp
 */

#include "activityservice.h"

#include "network/auditeventstore.h"
#include "network/networkwidget.h"
#include "network/topconsumers.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QSettings>
#include <QStandardPaths>

ActivityService::ActivityService(NetworkWidget *network, QObject *parent)
    : QObject(parent)
    , m_network(network)
{
    m_profile = Activity::DetectionProfileStore().load();
    m_detector.setSettings(Activity::detectionSettings(m_profile));

    QDir directory(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation));
    if (!directory.exists())
        directory.mkpath(QStringLiteral("."));
    m_seriesFilePath = directory.absoluteFilePath(
        QStringLiteral("Oasis_ActivitySeries.json"));

    QFile file(m_seriesFilePath);
    if (file.open(QIODevice::ReadOnly))
        m_series.fromJsonString(QString::fromUtf8(file.readAll()));

    if (m_network) {
        connect(m_network, &NetworkWidget::dashboardUpdated,
                this, &ActivityService::onDashboardUpdated);
        if (AuditEventStore *audit = m_network->auditStore()) {
            connect(audit, &AuditEventStore::changed,
                    this, &ActivityService::refreshAuditEvents);
        }
        const TopConsumers::Summary summary = m_network->dashboardSummary();
        for (const TopConsumers::Consumer &consumer : summary.consumers) {
            if (!consumer.name.isEmpty())
                m_applications.append(consumer.name);
        }
        m_applications.removeDuplicates();
        m_applications.sort(Qt::CaseInsensitive);
        refreshAuditEvents();
    }

    m_saveTimer.setInterval(30 * 1000);
    connect(&m_saveTimer, &QTimer::timeout, this, &ActivityService::save);
    m_saveTimer.start();
}

ActivityService::~ActivityService()
{
    save();
}

QVector<Activity::SeriesPoint> ActivityService::series(
    Activity::Range range, const QString &application) const
{
    return m_series.series(range, application);
}

Activity::SeriesTotals ActivityService::totals(
    Activity::Range range, const QString &application) const
{
    return m_series.totals(range, application);
}

void ActivityService::setProfile(Activity::DetectionProfile profile)
{
    if (m_profile == profile)
        return;

    m_profile = profile;
    Activity::DetectionProfileStore().save(profile);
    m_detector.setSettings(Activity::detectionSettings(profile));
    m_detector.clear();
    emit updated();
}

void ActivityService::save()
{
    if (m_seriesFilePath.isEmpty())
        return;

    QSaveFile file(m_seriesFilePath);
    if (!file.open(QIODevice::WriteOnly))
        return;
    file.write(m_series.toJsonString().toUtf8());
    file.commit();
}

void ActivityService::onDashboardUpdated(const TopConsumers::Summary &summary)
{
    if (!m_network)
        return;

    const QDateTime now = QDateTime::currentDateTime();
    const int elapsed = m_lastBeat.isValid()
        ? qBound(1, int(m_lastBeat.secsTo(now)), 5)
        : 1;
    m_lastBeat = now;

    QList<Activity::AppRate> apps;
    QList<Activity::ProcessRate> rates;
    QStringList names;
    apps.reserve(summary.consumers.size());
    rates.reserve(summary.consumers.size());

    for (const TopConsumers::Consumer &consumer : summary.consumers) {
        if (consumer.name.isEmpty())
            continue;
        names.append(consumer.name);

        Activity::AppRate app;
        app.name = consumer.name;
        app.rxBytesPerSecond = consumer.rxBytesPerSecond;
        app.txBytesPerSecond = consumer.txBytesPerSecond;
        apps.append(app);

        Activity::ProcessRate rate;
        rate.name = consumer.name;
        rate.path = consumer.path;
        rate.pid = consumer.pid;
        rate.rxBytesPerSecond = consumer.rxBytesPerSecond;
        rate.txBytesPerSecond = consumer.txBytesPerSecond;
        rate.foreground = consumer.foreground;
        rate.attribution = consumer.activity;
        if (consumer.pid != 0) {
            QString confidence;
            rate.destination = m_network->primaryDestinationForPid(
                consumer.pid, &confidence);
            if (rate.attribution.isEmpty() && !confidence.isEmpty())
                rate.attribution = confidence;
        }
        rates.append(rate);
    }

    m_series.addSample(now, summary.totalRxBytesPerSecond,
                       summary.totalTxBytesPerSecond, apps, elapsed);

    const QList<Activity::Event> detected =
        m_detector.observe(now, rates, summary.unresolvedBytes);
    bool added = false;
    for (const Activity::Event &event : detected) {
        const int before = m_events.size();
        appendEvent(event);
        added = added || m_events.size() != before;
    }

    names.removeDuplicates();
    names.sort(Qt::CaseInsensitive);
    m_applications = names;

    if (added)
        emit eventsChanged();
    emit updated();
}

void ActivityService::refreshAuditEvents()
{
    if (!m_network)
        return;
    AuditEventStore *store = m_network->auditStore();
    if (!store)
        return;

    bool added = false;
    for (const AuditEvent &audit : store->events()) {
        const QString result = audit.result.trimmed();
        const QString lowered = result.toLower();

        Activity::Category category;
        QString badge;
        QString titlePrefix;
        switch (audit.type) {
        case AuditEvent::EventType::PolicyChange:
            category = Activity::Category::Policy;
            badge = QStringLiteral("Policy Changed");
            titlePrefix = QStringLiteral("Policy changed for %1");
            break;
        case AuditEvent::EventType::AutomaticDecision:
            category = Activity::Category::Policy;
            badge = QStringLiteral("Auto-Throttled");
            titlePrefix = QStringLiteral("Data Saver limited %1");
            break;
        case AuditEvent::EventType::EnforcementResult:
            if (!lowered.contains(QLatin1String("fail"))
                && !lowered.contains(QLatin1String("partial"))
                && !lowered.contains(QLatin1String("stored")))
                continue;
            category = Activity::Category::Policy;
            badge = lowered.contains(QLatin1String("fail"))
                ? QStringLiteral("Enforcement Failed")
                : QStringLiteral("Enforcement Partial");
            titlePrefix = QStringLiteral("Enforcement outcome for %1");
            break;
        case AuditEvent::EventType::ProcessGroupMembershipChange:
            category = Activity::Category::Respawn;
            badge = QStringLiteral("Respawn Handled");
            titlePrefix = QStringLiteral("%1 inherited a policy after respawn");
            break;
        default:
            continue;
        }

        if (!audit.timestamp.isValid())
            continue;

        QString target = audit.scope.trimmed();
        const bool looksLikePath = target.contains(QLatin1Char('\\'))
            || target.contains(QLatin1Char('/'));
        if (looksLikePath)
            target = QFileInfo(target).fileName();
        if (target.isEmpty())
            target = QStringLiteral("an unrecognized target");

        Activity::Event event;
        event.at = audit.timestamp;
        event.category = category;
        event.badge = badge;
        event.title = titlePrefix.arg(target);
        event.appName = target;
        event.appPath = looksLikePath ? audit.scope.trimmed() : QString();
        event.description = !audit.reason.trimmed().isEmpty()
            ? audit.reason.trimmed()
            : (!audit.details.trimmed().isEmpty()
                   ? audit.details.trimmed()
                   : QStringLiteral("Recorded in the local audit log."));
        if (!result.isEmpty())
            event.extra.append({ QStringLiteral("Outcome"), result });
        if (!audit.relatedPolicyId.isEmpty())
            event.extra.append({ QStringLiteral("Policy"), audit.relatedPolicyId });
        if (!audit.details.trimmed().isEmpty()
            && audit.details.trimmed() != event.description)
            event.extra.append({ QStringLiteral("Details"), audit.details.trimmed() });
        if (!audit.errorInfo.trimmed().isEmpty())
            event.extra.append({ QStringLiteral("Error"), audit.errorInfo.trimmed() });

        event.id = Activity::makeEventId(
            category, event.at, audit.scope,
            QStringLiteral("audit-%1-%2")
                .arg(static_cast<int>(audit.type))
                .arg(result));
        const int before = m_events.size();
        appendEvent(event);
        added = added || m_events.size() != before;
    }

    if (added) {
        emit eventsChanged();
        emit updated();
    }
}

void ActivityService::appendEvent(const Activity::Event &event)
{
    if (!event.isValid() || m_eventIds.contains(event.id))
        return;
    m_eventIds.insert(event.id);
    m_events.append(event);

    constexpr int kMaxEvents = 800;
    while (m_events.size() > kMaxEvents) {
        const Activity::Event removed = m_events.takeFirst();
        m_eventIds.remove(removed.id);
    }
}