/**
 * @file    activitypage.cpp
 * @author  Oasis
 */
#include "activitypage.h"

#include "activitytimeline.h"
#include "ui/components/emptystatewidget.h"
#include "ui/theme/dimensions.h"

#include <QButtonGroup>
#include <QComboBox>
#include <QDateTime>
#include <QFrame>
#include <QGridLayout>
#include <QHash>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSet>
#include <QStyle>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>

namespace {

void repolish(QWidget *widget)
{
    if (!widget || !widget->style())
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

QString badgeToken(const QString &tone)
{
    if (tone == QLatin1String("danger"))
        return QStringLiteral("failed");
    if (tone == QLatin1String("success"))
        return QStringLiteral("active");
    if (tone == QLatin1String("info"))
        return QStringLiteral("pending");
    return QStringLiteral("degraded");
}

QString glyphForTone(const QString &tone)
{
    if (tone == QLatin1String("danger"))
        return QStringLiteral("!");
    if (tone == QLatin1String("success"))
        return QStringLiteral("✓");
    if (tone == QLatin1String("info"))
        return QStringLiteral("i");
    return QStringLiteral("⚠");
}

QPushButton *makeAction(const QString &text, const QString &variant, QWidget *parent)
{
    auto *button = new QPushButton(text, parent);
    button->setProperty("variant", variant);
    button->setCursor(Qt::PointingHandCursor);
    return button;
}

} // namespace

ActivityPage::ActivityPage(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("ActivityPage"));

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    root->addWidget(scroll);

    auto *content = new QWidget;
    content->setObjectName(QStringLiteral("ActivityContent"));
    auto *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(Theme::Dim::PagePaddingH, Theme::Dim::PagePaddingV,
                                      Theme::Dim::PagePaddingH, Theme::Dim::PagePaddingV);
    contentLayout->setSpacing(Theme::Dim::SpaceLg);
    scroll->setWidget(content);

    // ── Degraded banner (the host decides when it is shown) ────────────────
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
    bannerLayout->addWidget(bannerIcon);
    bannerLayout->addWidget(m_bannerText, 1);
    m_banner->hide();
    contentLayout->addWidget(m_banner);

    buildToolbar();
    contentLayout->addWidget(m_toolbar);

    buildTimelineCard();
    contentLayout->addWidget(m_timelineCard);

    buildFeed();
    contentLayout->addWidget(m_feedHost, 1);

    m_updatedLabel = new QLabel(content);
    m_updatedLabel->setProperty("uiRole", QStringLiteral("muted"));
    m_updatedLabel->setAlignment(Qt::AlignRight);
    m_updatedLabel->hide();
    contentLayout->addWidget(m_updatedLabel);

    refreshTimeline();
    refreshKpis();
    rebuildFeed();
}

// ============================================================================
// Construction
// ============================================================================

void ActivityPage::buildToolbar()
{
    m_toolbar = new QFrame;
    m_toolbar->setProperty("uiRole", QStringLiteral("card"));
    auto *layout = new QHBoxLayout(m_toolbar);
    layout->setContentsMargins(Theme::Dim::SpaceMd, Theme::Dim::SpaceSm,
                               Theme::Dim::SpaceMd, Theme::Dim::SpaceSm);
    layout->setSpacing(Theme::Dim::SpaceSm);

    auto *rangeGroup = new QButtonGroup(this);
    rangeGroup->setExclusive(true);
    const QList<Activity::Range> ranges = Activity::allRanges();
    for (Activity::Range range : ranges) {
        auto *button = new QToolButton(m_toolbar);
        button->setProperty("uiRole", QStringLiteral("filterPill"));
        button->setText(Activity::rangeLabel(range));
        button->setCheckable(true);
        button->setCursor(Qt::PointingHandCursor);
        button->setChecked(range == m_range);
        rangeGroup->addButton(button, static_cast<int>(range));
        layout->addWidget(button);
        m_rangeButtons.append(button);
        connect(button, &QToolButton::clicked, this, [this, range]() {
            setRange(range);
            emit rangeChanged(range);
        });
    }

    auto *separator = new QFrame(m_toolbar);
    separator->setProperty("uiRole", QStringLiteral("divider"));
    separator->setFixedWidth(1);
    separator->setMinimumHeight(20);
    layout->addSpacing(Theme::Dim::SpaceXs);
    layout->addWidget(separator);
    layout->addSpacing(Theme::Dim::SpaceXs);

    m_appCombo = new QComboBox(m_toolbar);
    m_appCombo->setMinimumWidth(190);
    m_appCombo->setToolTip(QStringLiteral("Show the timeline and feed for one application."));
    layout->addWidget(m_appCombo);
    connect(m_appCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            [this](int index) {
        const QString value = m_appCombo->itemData(index).toString();
        if (value == m_appFilter)
            return;
        m_appFilter = value;
        clearSelection();
        refreshTimeline();
        refreshMarkers();
        rebuildFeed();
        emit applicationChanged(value);
    });

    layout->addStretch(1);

    m_simulateButton = new QPushButton(QStringLiteral("Simulate spike"), m_toolbar);
    m_simulateButton->setProperty("variant", QStringLiteral("ghost"));
    m_simulateButton->setCursor(Qt::PointingHandCursor);
    m_simulateButton->setToolTip(QStringLiteral(
        "Debug build only: adds a clearly marked example event to the feed."));
    connect(m_simulateButton, &QPushButton::clicked, this, &ActivityPage::simulateRequested);
    m_simulateButton->hide();
    layout->addWidget(m_simulateButton);

    auto *exportButton = new QPushButton(QStringLiteral("Export feed"), m_toolbar);
    exportButton->setProperty("variant", QStringLiteral("ghost"));
    exportButton->setCursor(Qt::PointingHandCursor);
    auto *menu = new QMenu(exportButton);
    QAction *json = menu->addAction(QStringLiteral("Export as JSON…"));
    QAction *csv = menu->addAction(QStringLiteral("Export as CSV…"));
    exportButton->setMenu(menu);
    connect(json, &QAction::triggered, this, [this]() {
        emit exportRequested(QStringLiteral("json"));
    });
    connect(csv, &QAction::triggered, this, [this]() {
        emit exportRequested(QStringLiteral("csv"));
    });
    layout->addWidget(exportButton);
}

void ActivityPage::buildTimelineCard()
{
    m_timelineCard = new QFrame;
    m_timelineCard->setProperty("uiRole", QStringLiteral("card"));
    auto *layout = new QVBoxLayout(m_timelineCard);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceLg,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    layout->setSpacing(Theme::Dim::SpaceMd);

    auto *header = new QHBoxLayout;
    header->setSpacing(Theme::Dim::SpaceSm);
    auto *heading = new QLabel(QStringLiteral("Bandwidth timeline"), m_timelineCard);
    heading->setProperty("uiRole", QStringLiteral("cardHeading"));
    header->addWidget(heading);

    m_timelineSubtitle = new QLabel(m_timelineCard);
    m_timelineSubtitle->setProperty("uiRole", QStringLiteral("muted"));
    header->addWidget(m_timelineSubtitle, 0, Qt::AlignBottom);
    header->addStretch(1);

    m_selectionLabel = new QLabel(m_timelineCard);
    m_selectionLabel->setProperty("uiRole", QStringLiteral("muted"));
    header->addWidget(m_selectionLabel, 0, Qt::AlignVCenter);

    m_clearSelection = new QPushButton(QStringLiteral("Clear"), m_timelineCard);
    m_clearSelection->setProperty("variant", QStringLiteral("ghost"));
    m_clearSelection->setCursor(Qt::PointingHandCursor);
    m_clearSelection->hide();
    connect(m_clearSelection, &QPushButton::clicked, this, &ActivityPage::clearSelection);
    header->addWidget(m_clearSelection);

    m_collectingBadge = new QLabel(m_timelineCard);
    m_collectingBadge->setProperty("uiRole", QStringLiteral("badge"));
    m_collectingBadge->setProperty("status", QStringLiteral("active"));
    header->addWidget(m_collectingBadge);
    layout->addLayout(header);

    m_timeline = new ActivityTimeline(m_timelineCard);
    m_timeline->setMinimumHeight(190);
    layout->addWidget(m_timeline, 1);

    connect(m_timeline, &ActivityTimeline::selectionChanged, this,
            &ActivityPage::applyTimelineSelection);
    connect(m_timeline, &ActivityTimeline::selectionCleared, this,
            &ActivityPage::clearSelection);

    // ── KPI strip ──────────────────────────────────────────────────────────
    auto *kpis = new QHBoxLayout;
    kpis->setSpacing(Theme::Dim::SpaceLg);
    kpis->setContentsMargins(0, Theme::Dim::SpaceXs, 0, 0);

    const auto addKpi = [&](const QString &label, QLabel **valueOut) {
        auto *box = new QWidget(m_timelineCard);
        auto *boxLayout = new QVBoxLayout(box);
        boxLayout->setContentsMargins(0, 0, 0, 0);
        boxLayout->setSpacing(1);
        auto *value = new QLabel(QStringLiteral("—"), box);
        value->setProperty("uiRole", QStringLiteral("activityKpiValue"));
        auto *caption = new QLabel(label, box);
        caption->setProperty("uiRole", QStringLiteral("activityKpiLabel"));
        boxLayout->addWidget(value);
        boxLayout->addWidget(caption);
        kpis->addWidget(box, 1);
        *valueOut = value;
    };
    addKpi(QStringLiteral("Downloaded"), &m_downloadedValue);
    addKpi(QStringLiteral("Uploaded"), &m_uploadedValue);
    addKpi(QStringLiteral("Peak rate"), &m_peakValue);
    layout->addLayout(kpis);
}

void ActivityPage::buildFeed()
{
    m_feedHost = new QFrame;
    m_feedHost->setProperty("uiRole", QStringLiteral("card"));
    auto *layout = new QVBoxLayout(m_feedHost);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceLg,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    layout->setSpacing(Theme::Dim::SpaceMd);

    auto *header = new QHBoxLayout;
    header->setSpacing(Theme::Dim::SpaceSm);
    auto *heading = new QLabel(QStringLiteral("Activity feed"), m_feedHost);
    heading->setProperty("uiRole", QStringLiteral("cardHeading"));
    m_feedCount = new QLabel(m_feedHost);
    m_feedCount->setProperty("uiRole", QStringLiteral("muted"));
    header->addWidget(heading);
    header->addWidget(m_feedCount, 0, Qt::AlignBottom);
    header->addStretch(1);
    layout->addLayout(header);

    auto *pills = new QHBoxLayout;
    pills->setSpacing(Theme::Dim::SpaceXs);
    auto *group = new QButtonGroup(this);
    group->setExclusive(true);

    const QList<QPair<QString, int>> categories = {
        { QStringLiteral("All events"), -1 },
        { QStringLiteral("Spikes & surges"), static_cast<int>(Activity::Category::Spike) },
        { QStringLiteral("Unrecognized"), static_cast<int>(Activity::Category::Unresolved) },
        { QStringLiteral("Policy actions"), static_cast<int>(Activity::Category::Policy) },
        { QStringLiteral("Respawns"), static_cast<int>(Activity::Category::Respawn) }
    };
    for (const auto &entry : categories) {
        auto *button = new QToolButton(m_feedHost);
        button->setProperty("uiRole", QStringLiteral("filterPill"));
        button->setCheckable(true);
        button->setCursor(Qt::PointingHandCursor);
        button->setChecked(entry.second == m_category);
        group->addButton(button, entry.second);
        pills->addWidget(button);
        m_categoryButtons.append(button);
        connect(button, &QToolButton::clicked, this, [this, id = entry.second]() {
            m_category = id;
            rebuildFeed();
            refreshCategoryCounts();
        });
    }
    pills->addStretch(1);
    layout->addLayout(pills);

    m_feedLayout = new QVBoxLayout;
    m_feedLayout->setContentsMargins(0, 0, 0, 0);
    m_feedLayout->setSpacing(Theme::Dim::SpaceSm);
    layout->addLayout(m_feedLayout);
}

// ============================================================================
// Content
// ============================================================================

void ActivityPage::setSeries(const QVector<Activity::SeriesPoint> &points)
{
    m_points = points;
    refreshTimeline();
    refreshMarkers();

    // Keep a brush anchored to its timestamps while new samples shift indices.
    if (m_selectionFrom.isValid() && m_selectionTo.isValid()) {
        int first = -1;
        int last = -1;
        for (int i = 0; i < m_points.size(); ++i) {
            const QDateTime &start = m_points.at(i).start;
            if (start >= m_selectionFrom && start <= m_selectionTo) {
                if (first < 0)
                    first = i;
                last = i;
            }
        }
        if (first < 0) {
            clearSelection();
        } else {
            m_timeline->setSelection(first, last);
            m_selectionFrom = m_points.at(first).start;
            m_selectionTo = m_points.at(last).start
                .addSecs(Activity::rangeBucketSeconds(m_range));
            m_selectionLabel->setText(formatSpan(m_selectionFrom, m_selectionTo));
            m_clearSelection->show();
        }
    }
    refreshKpis();
    refreshCategoryCounts();
}

void ActivityPage::setEvents(const QList<Activity::Event> &events)
{
    m_events.clear();
    QSet<QString> seen;
    for (const Activity::Event &event : events) {
        if (!event.isValid() || seen.contains(event.id))
            continue;
        seen.insert(event.id);
        m_events.append(event);
    }
    std::sort(m_events.begin(), m_events.end(),
              [](const Activity::Event &left, const Activity::Event &right) {
                  return left.at > right.at;
              });
    refreshMarkers();
    refreshCategoryCounts();
    rebuildFeed();
}

void ActivityPage::setApplications(const QStringList &applications, const QString &current)
{
    m_applications = applications;
    m_applications.removeDuplicates();
    m_applications.sort(Qt::CaseInsensitive);

    if (!current.isEmpty() && !m_applications.contains(current))
        m_applications.append(current);
    if (!current.isEmpty())
        m_appFilter = current;
    else if (!m_appFilter.isEmpty() && !m_applications.contains(m_appFilter))
        m_appFilter.clear();

    if (m_appCombo) {
        const QSignalBlocker blocker(m_appCombo);
        m_appCombo->clear();
        m_appCombo->addItem(QStringLiteral("All applications"), QString());
        for (const QString &app : m_applications)
            m_appCombo->addItem(app, app);
        const int index = m_appCombo->findData(m_appFilter);
        m_appCombo->setCurrentIndex(index >= 0 ? index : 0);
    }

    refreshTimeline();
    refreshMarkers();
    rebuildFeed();
}

void ActivityPage::setDismissedIds(const QStringList &ids)
{
    m_dismissed = ids;
    refreshMarkers();
    refreshCategoryCounts();
    rebuildFeed();
}

void ActivityPage::setSimulationVisible(bool visible)
{
    if (m_simulateButton)
        m_simulateButton->setVisible(visible);
}

void ActivityPage::setMonitoringActive(bool active)
{
    m_monitoringActive = active;
    if (m_collectingBadge) {
        m_collectingBadge->setText(active ? QStringLiteral("Collecting")
                                          : QStringLiteral("Paused"));
        m_collectingBadge->setProperty("status",
                                       active ? QStringLiteral("active")
                                              : QStringLiteral("inactive"));
        repolish(m_collectingBadge);
    }
    refreshTimeline();
}

void ActivityPage::setUpdated(const QDateTime &when)
{
    m_updated = when;
    if (m_updatedLabel)
        m_updatedLabel->setText(when.isValid()
            ? QStringLiteral("Last updated %1").arg(when.toString(QStringLiteral("HH:mm:ss")))
            : QString());
    if (m_updatedLabel)
        m_updatedLabel->setVisible(when.isValid());
}

void ActivityPage::setBanner(const QString &text, const QString &severity)
{
    if (!m_banner || !m_bannerText)
        return;
    m_bannerText->setText(text);
    m_banner->setProperty("severity", severity);
    repolish(m_banner);
    m_banner->setVisible(!text.isEmpty());
}

void ActivityPage::clearBanner()
{
    if (m_banner)
        m_banner->hide();
}

void ActivityPage::setRange(Activity::Range range)
{
    if (m_range == range)
        return;
    m_range = range;
    for (int i = 0; i < m_rangeButtons.size(); ++i) {
        if (i < Activity::allRanges().size())
            m_rangeButtons.at(i)->setChecked(Activity::allRanges().at(i) == range);
    }
    clearSelection();
    refreshTimeline();
    refreshMarkers();
    refreshCategoryCounts();
    rebuildFeed();
}

// ============================================================================
// Refresh
// ============================================================================

void ActivityPage::refreshTimeline()
{
    if (!m_timeline)
        return;
    m_timeline->setRange(m_range);
    m_timeline->setBucketSeconds(Activity::rangeBucketSeconds(m_range));
    m_timeline->setPoints(m_points);

    if (m_timelineSubtitle) {
        m_timelineSubtitle->setText(QStringLiteral("%1 · %2 buckets")
            .arg(Activity::rangeLongLabel(m_range),
                 QString::number(Activity::rangeBucketSeconds(m_range))));
    }

    if (!m_monitoringActive) {
        m_timeline->setPlaceholder(QStringLiteral(
            "Monitoring is stopped. Stored events remain below; no new samples "
            "are being collected."));
    } else if (m_points.isEmpty()) {
        m_timeline->setPlaceholder(QStringLiteral(
            "No bandwidth samples in this range yet. The timeline fills as Oasis "
            "observes traffic."));
    } else {
        m_timeline->setPlaceholder(QString());
    }
}

void ActivityPage::refreshMarkers()
{
    if (!m_timeline)
        return;

    const QDateTime now = m_updated.isValid() ? m_updated : QDateTime::currentDateTime();
    QDateTime from = Activity::rangeStart(m_range, now);
    if (m_selectionFrom.isValid() && m_selectionFrom > from)
        from = m_selectionFrom;

    QDateTime to = m_selectionTo.isValid() ? m_selectionTo : now;
    if (m_range == Activity::Range::Live && to > now)
        to = now;

    QVector<ActivityMarker> markers;
    for (const Activity::Event &event : m_events) {
        if (isDismissed(event.id))
            continue;
        if (!m_appFilter.isEmpty() && event.appName != m_appFilter)
            continue;
        if (event.at < from || event.at > to)
            continue;
        ActivityMarker marker;
        marker.at = event.at;
        marker.tone = Activity::categoryTone(event.category);
        marker.label = event.badge;
        markers.append(marker);
    }
    m_timeline->setMarkers(markers);
}

void ActivityPage::refreshKpis()
{
    quint64 rx = 0;
    quint64 tx = 0;
    quint64 peak = 0;
    const int bucket = std::max(1, Activity::rangeBucketSeconds(m_range));
    for (const Activity::SeriesPoint &point : m_points) {
        if (m_selectionFrom.isValid() && point.start < m_selectionFrom)
            continue;
        if (m_selectionTo.isValid() && point.start > m_selectionTo)
            continue;
        rx += point.rxBytes;
        tx += point.txBytes;
        peak = std::max(peak, point.totalBytes());
    }

    if (m_downloadedValue)
        m_downloadedValue->setText(formatBytes(rx));
    if (m_uploadedValue)
        m_uploadedValue->setText(formatBytes(tx));
    if (m_peakValue)
        m_peakValue->setText(formatRate(peak / quint64(bucket)));
}

void ActivityPage::refreshCategoryCounts()
{
    const Activity::EventFilter base = currentFilter();
    QHash<int, int> counts = Activity::categoryCounts(m_events, base);

    // Dismissed cards are not events the user can select again.
    for (const Activity::Event &event : m_events) {
        if (!isDismissed(event.id))
            continue;
        if (!filterEvents(QList<Activity::Event>{ event }, base).isEmpty())
            counts[static_cast<int>(event.category)] =
                std::max(0, counts.value(static_cast<int>(event.category)) - 1);
    }

    int all = 0;
    for (auto it = counts.constBegin(); it != counts.constEnd(); ++it)
        all += it.value();

    for (int i = 0; i < m_categoryButtons.size(); ++i) {
        QToolButton *button = m_categoryButtons.at(i);
        const int id = i == 0 ? -1 : i - 1; // all, spike, unresolved, policy, respawn
        const int count = id < 0 ? all : counts.value(id);
        QString label;
        switch (id) {
        case -1: label = QStringLiteral("All events"); break;
        case static_cast<int>(Activity::Category::Spike):
            label = QStringLiteral("Spikes & surges"); break;
        case static_cast<int>(Activity::Category::Unresolved):
            label = QStringLiteral("Unrecognized"); break;
        case static_cast<int>(Activity::Category::Policy):
            label = QStringLiteral("Policy actions"); break;
        default: label = QStringLiteral("Respawns"); break;
        }
        button->setText(QStringLiteral("%1  %2").arg(label, QString::number(count)));
    }
    if (m_feedCount) {
        const int shown = m_category < 0 ? all : counts.value(m_category);
        m_feedCount->setText(QStringLiteral("%1 shown").arg(shown));
    }
}

QList<Activity::Event> ActivityPage::visibleEvents() const
{
    Activity::EventFilter filter = currentFilter();
    if (m_category >= 0) {
        filter.hasCategory = true;
        filter.category = static_cast<Activity::Category>(m_category);
    }
    QList<Activity::Event> visible;
    for (const Activity::Event &event : Activity::filterEvents(m_events, filter)) {
        if (!isDismissed(event.id))
            visible.append(event);
    }
    return visible;
}

void ActivityPage::rebuildFeed()
{
    if (!m_feedLayout)
        return;

    clearLayout(m_feedLayout);

    Activity::EventFilter filter = currentFilter();
    if (m_category >= 0) {
        filter.hasCategory = true;
        filter.category = static_cast<Activity::Category>(m_category);
    }

    QList<Activity::Event> visible;
    for (const Activity::Event &event : Activity::filterEvents(m_events, filter)) {
        if (!isDismissed(event.id))
            visible.append(event);
    }

    if (visible.isEmpty()) {
        auto *empty = new EmptyStateWidget(m_feedHost);
        empty->setTitle(QStringLiteral("No activity events here yet"));
        empty->setDetail(m_monitoringActive
            ? QStringLiteral("Oasis reports bandwidth spikes, unrecognized traffic, "
                             "policy changes and respawns as they are observed. "
                             "Nothing is inferred when evidence is missing.")
            : QStringLiteral("Monitoring is stopped, so no new events are being "
                             "recorded. Events already stored in this range remain."));
        m_feedLayout->addWidget(empty, 0, Qt::AlignHCenter);
    } else {
        for (const Activity::Event &event : visible) {
            const QString tone = Activity::categoryTone(event.category);

            auto *card = new QFrame(m_feedHost);
            card->setProperty("uiRole", QStringLiteral("activityCard"));
            card->setProperty("tone", tone);

            auto *cardLayout = new QHBoxLayout(card);
            cardLayout->setContentsMargins(0, 0, 0, 0);
            cardLayout->setSpacing(0);

            auto *accent = new QFrame(card);
            accent->setProperty("uiRole", QStringLiteral("activityAccent"));
            accent->setProperty("tone", tone);
            accent->setFixedWidth(3);
            cardLayout->addWidget(accent);

            auto *inner = new QWidget(card);
            auto *innerLayout = new QVBoxLayout(inner);
            innerLayout->setContentsMargins(Theme::Dim::SpaceMd, Theme::Dim::SpaceMd,
                                            Theme::Dim::SpaceMd, Theme::Dim::SpaceSm);
            innerLayout->setSpacing(Theme::Dim::SpaceSm);

            auto *header = new QHBoxLayout;
            header->setSpacing(Theme::Dim::SpaceSm);

            auto *icon = new QLabel(glyphForTone(tone), inner);
            icon->setProperty("uiRole", QStringLiteral("activityIcon"));
            icon->setProperty("tone", tone);
            icon->setAlignment(Qt::AlignCenter);
            icon->setFixedSize(36, 36);
            header->addWidget(icon, 0, Qt::AlignTop);

            auto *titleColumn = new QVBoxLayout;
            titleColumn->setSpacing(2);
            auto *title = new QLabel(event.title, inner);
            title->setProperty("uiRole", QStringLiteral("eventTitle"));
            title->setWordWrap(true);
            auto *description = new QLabel(event.description, inner);
            description->setProperty("uiRole", QStringLiteral("eventBody"));
            description->setWordWrap(true);
            titleColumn->addWidget(title);
            titleColumn->addWidget(description);
            header->addLayout(titleColumn, 1);

            auto *metaColumn = new QVBoxLayout;
            metaColumn->setSpacing(4);
            metaColumn->setAlignment(Qt::AlignTop | Qt::AlignRight);
            auto *badge = new QLabel(event.badge.isEmpty()
                                         ? Activity::categoryBadge(event.category)
                                         : event.badge, inner);
            badge->setProperty("uiRole", QStringLiteral("badge"));
            badge->setProperty("status", badgeToken(tone));
            badge->setAlignment(Qt::AlignCenter);
            auto *when = new QLabel(event.at.toString(QStringLiteral("MMM d, HH:mm:ss")),
                                    inner);
            when->setProperty("uiRole", QStringLiteral("eventTimestamp"));
            when->setAlignment(Qt::AlignRight);
            metaColumn->addWidget(badge, 0, Qt::AlignRight);
            metaColumn->addWidget(when, 0, Qt::AlignRight);
            header->addLayout(metaColumn);
            innerLayout->addLayout(header);

            // ── Metadata box: only observed facts, "Unknown" when absent ───
            QList<QPair<QString, QString>> facts;
            if (event.volumeBytes > 0)
                facts.append({ QStringLiteral("Volume"),
                               formatBytes(event.volumeBytes) });
            if (event.peakBytesPerSecond > 0)
                facts.append({ QStringLiteral("Peak rate"),
                               formatRate(event.peakBytesPerSecond) });
            facts.append({ QStringLiteral("Attribution"),
                           event.attribution.isEmpty()
                               ? QStringLiteral("Unknown") : event.attribution });
            facts.append({ QStringLiteral("Destination"),
                           event.destination.isEmpty()
                               ? QStringLiteral("Unknown") : event.destination });
            if (event.pid > 0)
                facts.append({ QStringLiteral("PID"), QString::number(event.pid) });
            for (const Activity::MetaItem &item : event.extra) {
                if (item.key.isEmpty() || item.value.isEmpty())
                    continue;
                facts.append({ item.key, item.value });
            }

            auto *meta = new QFrame(inner);
            meta->setProperty("uiRole", QStringLiteral("metaBox"));
            auto *metaGrid = new QGridLayout(meta);
            metaGrid->setContentsMargins(Theme::Dim::SpaceSm, Theme::Dim::SpaceSm,
                                         Theme::Dim::SpaceSm, Theme::Dim::SpaceSm);
            metaGrid->setHorizontalSpacing(Theme::Dim::SpaceLg);
            metaGrid->setVerticalSpacing(4);
            for (int i = 0; i < facts.size(); ++i) {
                const int row = i / 2;
                const int column = (i % 2) * 2;
                auto *key = new QLabel(facts.at(i).first, meta);
                key->setProperty("uiRole", QStringLiteral("metaKey"));
                auto *value = new QLabel(facts.at(i).second, meta);
                value->setProperty("uiRole", QStringLiteral("metaValue"));
                value->setTextInteractionFlags(Qt::TextSelectableByMouse);
                metaGrid->addWidget(key, row, column);
                metaGrid->addWidget(value, row, column + 1);
            }
            metaGrid->setColumnStretch(1, 1);
            metaGrid->setColumnStretch(3, 1);
            innerLayout->addWidget(meta);

            // ── Actions ───────────────────────────────────────────────────
            auto *footer = new QHBoxLayout;
            footer->setSpacing(Theme::Dim::SpaceSm);
            if (event.category == Activity::Category::Spike) {
                auto *policy = makeAction(QStringLiteral("Create policy"),
                                          QStringLiteral("secondary"), inner);
                connect(policy, &QPushButton::clicked, this, [this, event]() {
                    emit policyRequested(event.pid, event.appPath, event.appName);
                });
                footer->addWidget(policy);

                if (event.pid > 0) {
                    auto *inspect = makeAction(QStringLiteral("Inspect application"),
                                               QStringLiteral("ghost"), inner);
                    connect(inspect, &QPushButton::clicked, this, [this, event]() {
                        emit applicationRequested(event.pid, event.appPath, event.appName);
                    });
                    footer->addWidget(inspect);
                }
            } else if (event.category == Activity::Category::Unresolved) {
                // No per-IP rule exists in the backend, so the honest action is
                // reviewing the policy list rather than offering a block that
                // would be stored-only or fail.
                auto *policies = makeAction(QStringLiteral("Review policies"),
                                            QStringLiteral("secondary"), inner);
                connect(policies, &QPushButton::clicked, this, &ActivityPage::policiesRequested);
                footer->addWidget(policies);
            } else {
                auto *policies = makeAction(QStringLiteral("View policies"),
                                            QStringLiteral("secondary"), inner);
                connect(policies, &QPushButton::clicked, this, &ActivityPage::policiesRequested);
                footer->addWidget(policies);
            }

            if (event.simulated) {
                auto *simulated = new QLabel(QStringLiteral("Simulated — not observed"),
                                             inner);
                simulated->setProperty("uiRole", QStringLiteral("eventTimestamp"));
                footer->addWidget(simulated);
            }

            footer->addStretch(1);
            auto *dismiss = makeAction(QStringLiteral("Dismiss"),
                                       QStringLiteral("ghost"), inner);
            connect(dismiss, &QPushButton::clicked, this, [this, event]() {
                if (!m_dismissed.contains(event.id))
                    m_dismissed.append(event.id);
                refreshMarkers();
                refreshCategoryCounts();
                rebuildFeed();
                emit dismissRequested(event.id);
            });
            footer->addWidget(dismiss);
            innerLayout->addLayout(footer);

            cardLayout->addWidget(inner, 1);
            m_feedLayout->addWidget(card);
        }
    }

    refreshCategoryCounts();
}

void ActivityPage::applyTimelineSelection(int first, int last)
{
    if (first < 0 || last < 0 || first >= m_points.size() || last >= m_points.size()) {
        clearSelection();
        return;
    }
    m_selectionFrom = m_points.at(std::min(first, last)).start;
    m_selectionTo = m_points.at(std::max(first, last)).start
        .addSecs(Activity::rangeBucketSeconds(m_range));
    m_selectionLabel->setText(formatSpan(m_selectionFrom, m_selectionTo));
    m_clearSelection->show();
    refreshKpis();
    refreshMarkers();
    refreshCategoryCounts();
    rebuildFeed();
}

void ActivityPage::clearSelection()
{
    m_selectionFrom = QDateTime();
    m_selectionTo = QDateTime();
    if (m_timeline)
        m_timeline->setSelection(-1, -1);
    if (m_selectionLabel)
        m_selectionLabel->clear();
    if (m_clearSelection)
        m_clearSelection->hide();
    refreshKpis();
    refreshMarkers();
    refreshCategoryCounts();
    rebuildFeed();
}

// ============================================================================
// Filtering & formatting
// ============================================================================

Activity::EventFilter ActivityPage::currentFilter() const
{
    Activity::EventFilter filter;
    const QDateTime now = m_updated.isValid() ? m_updated : QDateTime::currentDateTime();
    QDateTime from = Activity::rangeStart(m_range, now);
    QDateTime to = now;

    if (m_selectionFrom.isValid() && m_selectionFrom > from)
        from = m_selectionFrom;
    if (m_selectionTo.isValid())
        to = m_selectionTo;
    if (to > now)
        to = now;

    filter.from = from;
    filter.to = to;
    filter.app = m_appFilter;
    return filter;
}

bool ActivityPage::isDismissed(const QString &id) const
{
    return m_dismissed.contains(id);
}

QString ActivityPage::formatBytes(quint64 bytes)
{
    static const char *units[] = { "B", "KB", "MB", "GB", "TB" };
    double value = double(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    const int decimals = value >= 100.0 || unit == 0 ? 0 : 1;
    return QStringLiteral("%1 %2")
        .arg(QString::number(value, 'f', decimals), QString::fromLatin1(units[unit]));
}

QString ActivityPage::formatRate(quint64 bytesPerSecond)
{
    return formatBytes(bytesPerSecond) + QStringLiteral("/s");
}

QString ActivityPage::formatSpan(const QDateTime &from, const QDateTime &to)
{
    if (!from.isValid() || !to.isValid())
        return QString();
    if (from.date() == to.date()) {
        return QStringLiteral("%1 · %2–%3")
            .arg(from.toString(QStringLiteral("MMM d")),
                 from.toString(QStringLiteral("HH:mm:ss")),
                 to.toString(QStringLiteral("HH:mm:ss")));
    }
    return QStringLiteral("%1 – %2")
        .arg(from.toString(QStringLiteral("MMM d, HH:mm")),
             to.toString(QStringLiteral("MMM d, HH:mm")));
}

QFrame *ActivityPage::createCard(const QString &title, const QString &subtitle)
{
    auto *card = new QFrame;
    card->setProperty("uiRole", QStringLiteral("card"));
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceLg,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    layout->setSpacing(Theme::Dim::SpaceMd);
    auto *header = new QHBoxLayout;
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
