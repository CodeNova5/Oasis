/**
 * @file    overviewpage.cpp
 * @author  Oasis
 */
#include "overviewpage.h"

#include "ui/components/emptystatewidget.h"
#include "ui/components/metriccard.h"
#include "ui/components/statusbadge.h"
#include "ui/components/trafficchart.h"
#include "ui/theme/dimensions.h"

#include <QDateTime>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QStyle>
#include <QVBoxLayout>

#include <algorithm>

namespace {

/// Child labels and badges must not swallow the row's click.
void makeClickThrough(QWidget *widget)
{
    widget->setAttribute(Qt::WA_TransparentForMouseEvents, true);
}

void repolish(QWidget *widget)
{
    if (!widget->style())
        return;
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
}

void clearLayout(QLayout *layout)
{
    if (!layout)
        return;
    while (QLayoutItem *item = layout->takeAt(0)) {
        if (QWidget *widget = item->widget())
            delete widget;
        if (QLayout *child = item->layout()) {
            clearLayout(child);
            delete child;
        }
        delete item;
    }
}

StatusBadge::Status badgeStatus(const QString &token)
{
    if (token == QLatin1String("active"))      return StatusBadge::Status::Active;
    if (token == QLatin1String("pending"))     return StatusBadge::Status::Pending;
    if (token == QLatin1String("degraded"))    return StatusBadge::Status::Degraded;
    if (token == QLatin1String("stored-only")) return StatusBadge::Status::StoredOnly;
    if (token == QLatin1String("failed"))      return StatusBadge::Status::Failed;
    if (token == QLatin1String("inactive"))    return StatusBadge::Status::Inactive;
    if (token == QLatin1String("expired"))     return StatusBadge::Status::Expired;
    return StatusBadge::Status::Unknown;
}

} // namespace

OverviewPage::OverviewPage(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("OverviewPage"));

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    m_scroll = new QScrollArea(this);
    m_scroll->setWidgetResizable(true);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    root->addWidget(m_scroll);

    auto *content = new QWidget;
    content->setObjectName(QStringLiteral("OverviewContent"));
    auto *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(Theme::Dim::PagePaddingH, Theme::Dim::PagePaddingV,
                                      Theme::Dim::PagePaddingH, Theme::Dim::PagePaddingV);
    contentLayout->setSpacing(Theme::Dim::SpaceLg);
    m_scroll->setWidget(content);

    // ── Degraded / error banner ────────────────────────────────────────────
    m_banner = new QFrame(content);
    m_banner->setProperty("uiRole", QStringLiteral("banner"));
    m_banner->setProperty("severity", QStringLiteral("warning"));
    auto *bannerLayout = new QHBoxLayout(m_banner);
    bannerLayout->setContentsMargins(Theme::Dim::SpaceMd, Theme::Dim::SpaceSm,
                                     Theme::Dim::SpaceMd, Theme::Dim::SpaceSm);
    bannerLayout->setSpacing(Theme::Dim::SpaceSm);

    auto *bannerIcon = new QLabel(QStringLiteral("⚠"), m_banner);
    bannerIcon->setProperty("uiRole", QStringLiteral("bannerIcon"));
    m_bannerText = new QLabel(m_banner);
    m_bannerText->setProperty("uiRole", QStringLiteral("bannerText"));
    m_bannerText->setWordWrap(true);
    m_bannerAction = createLink(QStringLiteral("Open diagnostics"));
    connect(m_bannerAction, &QPushButton::clicked, this, &OverviewPage::diagnosticsRequested);

    bannerLayout->addWidget(bannerIcon);
    bannerLayout->addWidget(m_bannerText, 1);
    bannerLayout->addWidget(m_bannerAction);
    m_banner->hide();
    contentLayout->addWidget(m_banner);

    // ── Page body ──────────────────────────────────────────────────────────
    m_body = new QWidget(content);
    auto *bodyLayout = new QVBoxLayout(m_body);
    bodyLayout->setContentsMargins(0, 0, 0, 0);
    bodyLayout->setSpacing(Theme::Dim::SpaceLg);
    contentLayout->addWidget(m_body);

    // KPI row — four equal cards, 16 px gap.
    auto *kpiRow = new QHBoxLayout;
    kpiRow->setSpacing(Theme::Dim::SpaceLg);

    m_totalCard = new MetricCard(QStringLiteral("Total usage"), m_body);
    m_totalCard->setClickable(true);
    m_totalCard->setToolTipText(QStringLiteral("Open Activity for this session's traffic."));

    m_downloadCard = new MetricCard(QStringLiteral("Download"), m_body);
    m_uploadCard = new MetricCard(QStringLiteral("Upload"), m_body);
    m_appsCard = new MetricCard(QStringLiteral("Active applications"), m_body);

    connect(m_totalCard, &MetricCard::clicked, this, &OverviewPage::activityRequested);

    kpiRow->addWidget(m_totalCard, 1);
    kpiRow->addWidget(m_downloadCard, 1);
    kpiRow->addWidget(m_uploadCard, 1);
    kpiRow->addWidget(m_appsCard, 1);
    bodyLayout->addLayout(kpiRow);

    // Middle row — 65% traffic chart / 35% top consumers.
    auto *middleRow = new QHBoxLayout;
    middleRow->setSpacing(Theme::Dim::SpaceLg);

    QFrame *chartCard = createCard(QStringLiteral("Network traffic"),
                                   QStringLiteral("Last 60 minutes"));
    m_chart = new TrafficChart(chartCard);
    m_chart->setMinimumHeight(190);
    static_cast<QVBoxLayout *>(chartCard->layout())->addWidget(m_chart, 1);
    connect(m_chart, &TrafficChart::activated, this, &OverviewPage::activityRequested);

    QFrame *consumersCard = createCard(QStringLiteral("Top consumers"),
                                       QStringLiteral("Current rate"));
    consumersCard->setMinimumWidth(240);
    auto *consumersLayout = static_cast<QVBoxLayout *>(consumersCard->layout());

    m_consumerRows = new QVBoxLayout;
    m_consumerRows->setContentsMargins(0, 0, 0, 0);
    m_consumerRows->setSpacing(2);
    consumersLayout->addLayout(m_consumerRows);

    m_consumerEmpty = new EmptyStateWidget(consumersCard);
    m_consumerEmpty->setTitle(QStringLiteral("No applications yet"));
    m_consumerEmpty->setDetail(QStringLiteral(
        "Applications appear here once Oasis observes network activity from them."));
    m_consumerEmpty->setAction(QStringLiteral("Open applications"));
    consumersLayout->addWidget(m_consumerEmpty, 0, Qt::AlignHCenter);
    connect(m_consumerEmpty, &EmptyStateWidget::actionTriggered,
            this, &OverviewPage::applicationsRequested);

    consumersLayout->addStretch(1);

    auto *consumersFooter = new QHBoxLayout;
    consumersFooter->setSpacing(Theme::Dim::SpaceSm);
    m_consumerFootnote = new QLabel(consumersCard);
    m_consumerFootnote->setProperty("uiRole", QStringLiteral("muted"));
    m_consumerFootnote->setText(QStringLiteral("Ranked by current rate, then total volume."));
    auto *allApplications = createLink(QStringLiteral("View applications →"));
    connect(allApplications, &QPushButton::clicked, this, &OverviewPage::applicationsRequested);
    consumersFooter->addWidget(m_consumerFootnote, 1);
    consumersFooter->addWidget(allApplications);
    consumersLayout->addLayout(consumersFooter);

    middleRow->addWidget(chartCard, 65);
    middleRow->addWidget(consumersCard, 35);
    bodyLayout->addLayout(middleRow, 3);

    // Bottom row — 50% controls / 50% recent activity.
    auto *bottomRow = new QHBoxLayout;
    bottomRow->setSpacing(Theme::Dim::SpaceLg);

    QFrame *controlsCard = createCard(QStringLiteral("Controls in force"),
                                      QStringLiteral("Policies and unresolved traffic"));
    auto *controlsLayout = static_cast<QVBoxLayout *>(controlsCard->layout());

    auto *statsRow = new QHBoxLayout;
    statsRow->setSpacing(Theme::Dim::SpaceXl);

    const auto addStat = [&](const QString &caption, QLabel **valueOut) {
        auto *block = new QWidget(controlsCard);
        auto *blockLayout = new QVBoxLayout(block);
        blockLayout->setContentsMargins(0, 0, 0, 0);
        blockLayout->setSpacing(0);

        auto *value = new QLabel(QStringLiteral("—"), block);
        value->setProperty("uiRole", QStringLiteral("statValue"));
        auto *label = new QLabel(caption, block);
        label->setProperty("uiRole", QStringLiteral("muted"));

        blockLayout->addWidget(value);
        blockLayout->addWidget(label);
        statsRow->addWidget(block);
        *valueOut = value;
    };

    addStat(QStringLiteral("Active"), &m_activeCount);
    addStat(QStringLiteral("Stored only"), &m_storedCount);
    addStat(QStringLiteral("Expired"), &m_expiredCount);
    statsRow->addStretch(1);
    controlsLayout->addLayout(statsRow);

    m_unresolvedDetail = new QLabel(controlsCard);
    m_unresolvedDetail->setProperty("uiRole", QStringLiteral("secondary"));
    m_unresolvedDetail->setWordWrap(true);
    controlsLayout->addWidget(m_unresolvedDetail);
    controlsLayout->addStretch(1);

    auto *controlsFooter = new QHBoxLayout;
    controlsFooter->setSpacing(Theme::Dim::SpaceSm);
    m_controlSummary = new QLabel(controlsCard);
    m_controlSummary->setProperty("uiRole", QStringLiteral("muted"));
    auto *reviewPolicies = createLink(QStringLiteral("Review policies →"));
    connect(reviewPolicies, &QPushButton::clicked, this, &OverviewPage::policiesRequested);
    controlsFooter->addWidget(m_controlSummary, 1);
    controlsFooter->addWidget(reviewPolicies);
    controlsLayout->addLayout(controlsFooter);

    QFrame *alertsCard = createCard(QStringLiteral("Recent activity & alerts"),
                                    QStringLiteral("Policy and enforcement events"));
    auto *alertsLayout = static_cast<QVBoxLayout *>(alertsCard->layout());

    m_alertRows = new QVBoxLayout;
    m_alertRows->setContentsMargins(0, 0, 0, 0);
    m_alertRows->setSpacing(2);
    alertsLayout->addLayout(m_alertRows);

    m_alertEmpty = new QLabel(QStringLiteral("No policy changes or alerts yet."), alertsCard);
    m_alertEmpty->setProperty("uiRole", QStringLiteral("muted"));
    alertsLayout->addWidget(m_alertEmpty);
    alertsLayout->addStretch(1);

    bottomRow->addWidget(controlsCard, 1);
    bottomRow->addWidget(alertsCard, 1);
    bodyLayout->addLayout(bottomRow, 2);

    // ── Loading state ──────────────────────────────────────────────────────
    m_loading = new EmptyStateWidget(content);
    m_loading->setTitle(QStringLiteral("Collecting the first samples"));
    m_loading->setDetail(QStringLiteral(
        "Oasis is warming up the local capture engine. Counters stay blank until "
        "real telemetry arrives — nothing here is estimated."));
    m_loading->hide();
    contentLayout->addWidget(m_loading, 0, Qt::AlignHCenter);

    m_updated = new QLabel(content);
    m_updated->setProperty("uiRole", QStringLiteral("muted"));
    m_updated->setAlignment(Qt::AlignRight);
    m_updated->hide();
    contentLayout->addWidget(m_updated);

    contentLayout->addStretch(1);

    refreshChartState();
    refreshControls();
    rebuildAlerts();
    setTopConsumers({});
    setActiveAppCount(0);
}

// ============================================================================
// Card scaffolding
// ============================================================================

QFrame *OverviewPage::createCard(const QString &title, const QString &subtitle)
{
    auto *card = new QFrame(m_body);
    card->setProperty("uiRole", QStringLiteral("card"));

    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceLg,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    layout->setSpacing(Theme::Dim::SpaceMd);

    auto *header = new QHBoxLayout;
    header->setSpacing(Theme::Dim::SpaceSm);

    auto *heading = new QLabel(title, card);
    heading->setProperty("uiRole", QStringLiteral("cardHeading"));
    header->addWidget(heading);

    if (!subtitle.isEmpty()) {
        auto *caption = new QLabel(subtitle, card);
        caption->setProperty("uiRole", QStringLiteral("muted"));
        header->addWidget(caption, 0, Qt::AlignBottom);
    }
    header->addStretch(1);
    layout->addLayout(header);
    return card;
}

QPushButton *OverviewPage::createLink(const QString &text)
{
    auto *button = new QPushButton(text, this);
    button->setProperty("variant", QStringLiteral("ghost"));
    button->setProperty("uiRole", QStringLiteral("link"));
    button->setCursor(Qt::PointingHandCursor);
    button->setFlat(true);
    return button;
}

// ============================================================================
// Content
// ============================================================================

void OverviewPage::setUsageTotals(quint64 totalBytes, quint64 rxBytes, quint64 txBytes,
                                  quint64 rxBytesPerSecond, quint64 txBytesPerSecond)
{
    m_totalCard->setValue(formatBytes(totalBytes));
    m_totalCard->setCaption(QStringLiteral("Captured this session"));

    m_downloadCard->setValue(formatBytes(rxBytes));
    m_downloadCard->setCaption(QStringLiteral("↓ %1 now").arg(formatRate(rxBytesPerSecond)));

    m_uploadCard->setValue(formatBytes(txBytes));
    m_uploadCard->setCaption(QStringLiteral("↑ %1 now").arg(formatRate(txBytesPerSecond)));
}

void OverviewPage::setActiveAppCount(int count)
{
    m_appsCard->setValue(count > 0 ? QString::number(count) : QStringLiteral("0"));
    m_appsCard->setCaption(QStringLiteral("With observed network activity"));
}

void OverviewPage::setTrafficSeries(const QVector<Overview::TrafficPoint> &points)
{
    m_series = points;
    if (!m_series.isEmpty()) {
        const QDateTime cutoff = m_series.last().timestamp.addSecs(-3600);
        while (!m_series.isEmpty() && m_series.first().timestamp.isValid()
               && m_series.first().timestamp < cutoff)
            m_series.removeFirst();
    }
    m_chart->setSeries(m_series);
}

void OverviewPage::appendTrafficPoint(const Overview::TrafficPoint &point)
{
    // Keep exactly the last hour, matching the card's subtitle.
    m_series.append(point);
    const QDateTime cutoff = point.timestamp.addSecs(-3600);
    while (!m_series.isEmpty() && m_series.first().timestamp.isValid()
           && m_series.first().timestamp < cutoff)
        m_series.removeFirst();
    m_chart->setSeries(m_series);
}

void OverviewPage::setTopConsumers(const QVector<Overview::Consumer> &consumers)
{
    m_consumers = consumers;
    rebuildConsumers();
}

void OverviewPage::setControls(const Overview::ControlCounts &counts)
{
    m_controlCounts = counts;
    refreshControls();
}

void OverviewPage::setAlerts(const QVector<Overview::Alert> &alerts)
{
    m_alerts = alerts;
    rebuildAlerts();
}

// ============================================================================
// Page state
// ============================================================================

void OverviewPage::setBanner(Overview::BannerSeverity severity, const QString &text)
{
    const char *property = "info";
    if (severity == Overview::BannerSeverity::Warning)
        property = "warning";
    else if (severity == Overview::BannerSeverity::Danger)
        property = "danger";

    m_banner->setProperty("severity", QString::fromLatin1(property));
    m_bannerText->setText(text);
    m_banner->setVisible(!text.isEmpty());
    repolish(m_banner);
    for (QWidget *child : m_banner->findChildren<QWidget *>())
        repolish(child);
}

void OverviewPage::clearBanner()
{
    m_bannerText->clear();
    m_banner->hide();
}

void OverviewPage::setCollecting(bool collecting)
{
    m_collecting = collecting;
    m_body->setVisible(!collecting);
    m_loading->setVisible(collecting);
}

void OverviewPage::setMonitoringActive(bool active)
{
    m_monitoringActive = active;
    refreshChartState();
    rebuildConsumers();
}

void OverviewPage::setUpdated(const QDateTime &when)
{
    if (!when.isValid()) {
        m_updated->hide();
        return;
    }
    m_updated->setText(QStringLiteral("Last updated: %1")
                           .arg(when.toString(QStringLiteral("HH:mm:ss"))));
    m_updated->show();
}

// ============================================================================
// Builders
// ============================================================================

void OverviewPage::rebuildConsumers()
{
    if (!m_consumerRows)
        return;

    clearLayout(m_consumerRows);

    QWidget *parent = m_consumerRows->parentWidget();
    const int shown = std::min<int>(m_consumers.size(), 5);
    for (int i = 0; i < shown; ++i) {
        const Overview::Consumer &consumer = m_consumers.at(i);

        auto *row = new QPushButton(parent);
        row->setProperty("uiRole", QStringLiteral("listRow"));
        row->setCursor(Qt::PointingHandCursor);
        row->setMinimumHeight(44);
        row->setToolTip(consumer.path.isEmpty()
                            ? consumer.name + QLatin1Char('\n') + consumer.usage
                            : consumer.path + QLatin1Char('\n') + consumer.usage);

        auto *rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(Theme::Dim::SpaceXs, Theme::Dim::SpaceXs,
                                      Theme::Dim::SpaceXs, Theme::Dim::SpaceXs);
        rowLayout->setSpacing(Theme::Dim::SpaceSm);

        auto *rank = new QLabel(QString::number(i + 1), row);
        rank->setProperty("uiRole", QStringLiteral("rank"));
        rank->setFixedWidth(14);
        rank->setAlignment(Qt::AlignCenter);

        auto *avatar = new QLabel(row);
        avatar->setProperty("uiRole", QStringLiteral("avatar"));
        avatar->setFixedSize(24, 24);
        avatar->setAlignment(Qt::AlignCenter);
        if (consumer.icon.isNull()) {
            avatar->setText(consumer.name.left(1).toUpper());
        } else {
            avatar->setPixmap(consumer.icon.pixmap(20, 20));
        }

        auto *textBlock = new QWidget(row);
        auto *textLayout = new QVBoxLayout(textBlock);
        textLayout->setContentsMargins(0, 0, 0, 0);
        textLayout->setSpacing(0);

        auto *name = new QLabel(consumer.name.isEmpty()
                                    ? QStringLiteral("Unknown")
                                    : consumer.name,
                                textBlock);
        name->setProperty("uiRole", QStringLiteral("rowTitle"));
        auto *subtitle = new QLabel(consumer.subtitle, textBlock);
        subtitle->setProperty("uiRole", QStringLiteral("muted"));
        subtitle->setVisible(!consumer.subtitle.isEmpty());
        textLayout->addWidget(name);
        textLayout->addWidget(subtitle);

        auto *usage = new QLabel(consumer.usage, row);
        usage->setProperty("uiRole", QStringLiteral("rowValue"));
        usage->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

        for (QWidget *child : { static_cast<QWidget *>(rank), static_cast<QWidget *>(avatar),
                                static_cast<QWidget *>(textBlock), static_cast<QWidget *>(usage) })
            makeClickThrough(child);

        rowLayout->addWidget(rank);
        rowLayout->addWidget(avatar);
        rowLayout->addWidget(textBlock, 1);
        if (!consumer.stateLabel.isEmpty()) {
            auto *badge = new StatusBadge(row);
            badge->setStatus(badgeStatus(consumer.stateToken), consumer.stateLabel);
            makeClickThrough(badge);
            rowLayout->addWidget(badge, 0, Qt::AlignVCenter);
        }
        rowLayout->addWidget(usage);

        row->setAccessibleName(consumer.name);
        connect(row, &QPushButton::clicked, this, [this, consumer]() {
            emit applicationActivated(consumer.pid, consumer.path, consumer.name);
        });
        m_consumerRows->addWidget(row);
    }

    const bool empty = shown == 0;
    m_consumerEmpty->setVisible(empty);
    if (empty) {
        m_consumerEmpty->setTitle(m_monitoringActive
                                      ? QStringLiteral("No applications yet")
                                      : QStringLiteral("Monitoring is stopped"));
        m_consumerEmpty->setDetail(m_monitoringActive
            ? QStringLiteral("Applications appear here once Oasis observes network "
                             "activity from them.")
            : QStringLiteral("Start monitoring to see which applications are using "
                             "bandwidth. No live rows are shown until capture resumes."));
    }
}

void OverviewPage::rebuildAlerts()
{
    if (!m_alertRows)
        return;

    clearLayout(m_alertRows);

    QWidget *parent = m_alertRows->parentWidget();
    const int shown = std::min<int>(m_alerts.size(), 5);
    for (int i = 0; i < shown; ++i) {
        const Overview::Alert &alert = m_alerts.at(i);

        auto *row = new QPushButton(parent);
        row->setProperty("uiRole", QStringLiteral("listRow"));
        row->setCursor(Qt::PointingHandCursor);
        row->setMinimumHeight(40);
        row->setToolTip(alert.detail.isEmpty() ? alert.title : alert.detail);

        auto *rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(Theme::Dim::SpaceXs, Theme::Dim::SpaceXs,
                                      Theme::Dim::SpaceXs, Theme::Dim::SpaceXs);
        rowLayout->setSpacing(Theme::Dim::SpaceSm);

        auto *time = new QLabel(alert.at.isValid() ? relativeTime(alert.at)
                                                   : QString(),
                                row);
        time->setProperty("uiRole", QStringLiteral("muted"));
        time->setFixedWidth(64);

        auto *textBlock = new QWidget(row);
        auto *textLayout = new QVBoxLayout(textBlock);
        textLayout->setContentsMargins(0, 0, 0, 0);
        textLayout->setSpacing(0);

        auto *title = new QLabel(alert.title, textBlock);
        title->setProperty("uiRole", QStringLiteral("rowTitle"));
        title->setWordWrap(true);
        auto *detail = new QLabel(alert.detail, textBlock);
        detail->setProperty("uiRole", QStringLiteral("muted"));
        detail->setWordWrap(true);
        detail->setVisible(!alert.detail.isEmpty());
        textLayout->addWidget(title);
        textLayout->addWidget(detail);

        auto *action = new QLabel(alert.actionLabel, row);
        action->setProperty("uiRole", QStringLiteral("linkText"));
        action->setVisible(!alert.actionLabel.isEmpty());

        for (QWidget *child : { static_cast<QWidget *>(time), static_cast<QWidget *>(textBlock),
                                static_cast<QWidget *>(action) })
            makeClickThrough(child);

        rowLayout->addWidget(time, 0, Qt::AlignTop);
        rowLayout->addWidget(textBlock, 1);
        rowLayout->addWidget(action, 0, Qt::AlignVCenter);

        connect(row, &QPushButton::clicked, this, [this, i]() { emit alertActivated(i); });
        m_alertRows->addWidget(row);
    }

    m_alertEmpty->setVisible(shown == 0);
}

void OverviewPage::refreshControls()
{
    if (!m_activeCount)
        return;

    const Overview::ControlCounts &counts = m_controlCounts;
    m_activeCount->setText(QString::number(counts.active));
    m_activeCount->setProperty("tone", counts.active > 0 ? QStringLiteral("success")
                                                         : QStringLiteral("muted"));
    m_storedCount->setText(QString::number(counts.storedOnly));
    m_storedCount->setProperty("tone", counts.storedOnly > 0 ? QStringLiteral("warning")
                                                             : QStringLiteral("muted"));
    m_expiredCount->setText(QString::number(counts.expired));
    m_expiredCount->setProperty("tone", QStringLiteral("muted"));

    for (QLabel *value : { m_activeCount, m_storedCount, m_expiredCount })
        repolish(value);

    if (counts.unresolvedConsumers > 0) {
        m_unresolvedDetail->setText(
            QStringLiteral("%1 application%2 and %3 of traffic could not be tied to a "
                           "verified identity. They are never guessed.")
                .arg(counts.unresolvedConsumers)
                .arg(counts.unresolvedConsumers == 1 ? QString() : QStringLiteral("s"))
                .arg(formatBytes(counts.unresolvedBytes)));
    } else {
        m_unresolvedDetail->setText(
            QStringLiteral("Every observed consumer is currently attributed to an application."));
    }

    QStringList parts;
    parts << QStringLiteral("%1 enforced").arg(counts.active);
    if (counts.storedOnly > 0)
        parts << QStringLiteral("%1 stored only").arg(counts.storedOnly);
    if (counts.expired > 0)
        parts << QStringLiteral("%1 expired").arg(counts.expired);
    m_controlSummary->setText(parts.join(QStringLiteral(" · ")));

    m_controlSummary->setToolTip(
        QStringLiteral("Stored-only rules are saved locally but not enforced by the "
                       "operating system; they are not counted as active."));
}

void OverviewPage::refreshChartState()
{
    if (!m_chart)
        return;
    m_chart->setPlaceholder(m_monitoringActive
        ? QStringLiteral("Waiting for the first samples…")
        : QStringLiteral("Monitoring is stopped — no live samples."));
}

// ============================================================================
// Formatting
// ============================================================================

QString OverviewPage::formatBytes(quint64 bytes)
{
    const char *units[] = { "B", "KB", "MB", "GB", "TB" };
    double value = double(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    const int precision = (unit == 0 || value >= 10.0) ? 0 : 1;
    return QString::number(value, 'f', precision) + QLatin1Char(' ')
           + QString::fromLatin1(units[unit]);
}

QString OverviewPage::formatRate(quint64 bytesPerSecond)
{
    return formatBytes(bytesPerSecond) + QStringLiteral("/s");
}

QString OverviewPage::relativeTime(const QDateTime &when)
{
    const qint64 seconds = when.secsTo(QDateTime::currentDateTime());
    if (seconds < 60)
        return QStringLiteral("just now");
    if (seconds < 3600)
        return QStringLiteral("%1 min ago").arg(seconds / 60);
    if (seconds < 86400)
        return QStringLiteral("%1 h ago").arg(seconds / 3600);
    return when.toString(QStringLiteral("MMM d"));
}
