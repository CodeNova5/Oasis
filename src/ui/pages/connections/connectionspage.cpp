/**
 * @file    connectionspage.cpp
 * @author  Oasis
 */
#include "connectionspage.h"

#include "connectionicons.h"
#include "connectionstable.h"
#include "ui/components/emptystatewidget.h"
#include "ui/theme/colors.h"
#include "ui/theme/dimensions.h"
#include "ui/theme/thememanager.h"
#include "ui/theme/typography.h"

#include <QAbstractButton>
#include <QAction>
#include <QActionGroup>
#include <QButtonGroup>
#include <QDateTime>
#include <QDir>
#include <QEnterEvent>
#include <QFile>
#include <QFileDialog>
#include <QFontMetrics>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLayout>
#include <QLayoutItem>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPair>
#include <QPushButton>
#include <QResizeEvent>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QStandardPaths>
#include <QStackedWidget>
#include <QStringConverter>
#include <QTextStream>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <initializer_list>

using ConnectionsUi::Glyph;

namespace {

Theme::Palette themePalette()
{
    return Theme::palette(ThemeManager::instance().isDark());
}

QColor token(const QString &value)
{
    return Theme::qcolor(value);
}

QFont uiFont(int pixelSize, QFont::Weight weight)
{
    QFont font = Theme::Type::baseFont();
    font.setPixelSize(pixelSize);
    font.setWeight(weight);
    return font;
}

QString applicationLabel(const Connections::Row &row)
{
    return row.displayName.trimmed().isEmpty() ? row.appName : row.displayName;
}

bool sameRowIds(const QList<Connections::Row> &left,
                const QList<Connections::Row> &right)
{
    if (left.size() != right.size())
        return false;
    QSet<QString> ids;
    for (const Connections::Row &row : left)
        ids.insert(row.id);
    for (const Connections::Row &row : right) {
        if (!ids.contains(row.id))
            return false;
    }
    return true;
}

QString formatAge(qint64 ageMs)
{
    if (ageMs < 60LL * 1000)
        return QStringLiteral("just now");
    const qint64 minutes = ageMs / (60LL * 1000);
    if (minutes < 60)
        return QStringLiteral("%1 min ago").arg(minutes);
    return QStringLiteral("%1 h ago").arg(minutes / 60);
}

int endpointCountFor(const Connections::Row &row)
{
    if (!row.endpoints.isEmpty())
        return int(row.endpoints.size());
    return qMax(1, row.endpointCount);
}

bool endpointNamed(const Connections::Endpoint &endpoint)
{
    return !endpoint.domainNames.isEmpty() || !endpoint.domain.trimmed().isEmpty();
}

quint16 rowPort(const Connections::Row &row)
{
    quint16 port = 0;
    for (const Connections::Endpoint &endpoint : row.endpoints) {
        if (port == 0 || endpoint.port < port)
            port = endpoint.port;
    }
    return port;
}

QString protoFor(quint16 port, const QString &protocol)
{
    switch (port) {
    case 80:   return QStringLiteral("HTTP");
    case 443:  return QStringLiteral("HTTPS");
    case 53:   return QStringLiteral("DNS");
    case 22:   return QStringLiteral("SSH");
    case 25:
    case 587:  return QStringLiteral("SMTP");
    case 993:  return QStringLiteral("IMAPS");
    case 3389: return QStringLiteral("RDP");
    case 445:  return QStringLiteral("SMB");
    default:
        break;
    }
    return protocol.isEmpty() ? QStringLiteral("TCP") : protocol.toUpper();
}

QString rowProtocol(const Connections::Row &row)
{
    quint16 port = 0;
    QString protocol;
    for (const Connections::Endpoint &endpoint : row.endpoints) {
        if (port == 0 || endpoint.port < port) {
            port = endpoint.port;
            protocol = endpoint.protocol;
        }
    }
    return protoFor(port, protocol);
}

void clearLayout(QLayout *layout)
{
    if (!layout)
        return;
    while (QLayoutItem *item = layout->takeAt(0)) {
        if (QWidget *widget = item->widget())
            widget->deleteLater();
        clearLayout(item->layout());
        delete item;
    }
}

} // namespace

// ============================================================================
// Metric tile
// ============================================================================

class MetricTile : public QFrame
{
public:
    enum class Tone { Accent, Danger, Success, Warning };

    MetricTile(Glyph glyph, const QString &label, QWidget *parent = nullptr)
        : QFrame(parent)
        , m_glyph(glyph)
    {
        setProperty("uiRole", QStringLiteral("card"));
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

        auto *layout = new QVBoxLayout(this);
        layout->setContentsMargins(16, 14, 16, 14);
        layout->setSpacing(4);

        auto *labelRow = new QHBoxLayout;
        labelRow->setContentsMargins(0, 0, 0, 0);
        labelRow->setSpacing(5);

        m_icon = new QLabel(this);
        m_icon->setFixedSize(13, 13);
        m_label = new QLabel(label, this);
        m_label->setFont(uiFont(11, QFont::Medium));
        labelRow->addWidget(m_icon, 0, Qt::AlignVCenter);
        labelRow->addWidget(m_label, 0, Qt::AlignVCenter);
        labelRow->addStretch(1);

        m_value = new QLabel(QStringLiteral("—"), this);
        m_value->setFont(uiFont(26, QFont::DemiBold));
        m_caption = new QLabel(this);
        m_caption->setFont(uiFont(11, QFont::Normal));
        m_caption->setWordWrap(false);

        layout->addLayout(labelRow);
        layout->addWidget(m_value);
        layout->addWidget(m_caption);

        refreshTheme();
    }

    void setValue(const QString &value, Tone tone)
    {
        m_value->setText(value);
        m_tone = tone;
        applyTone();
    }

    void setCaption(const QString &caption)
    {
        m_caption->setText(caption);
        m_caption->setVisible(!caption.isEmpty());
    }

    void refreshTheme()
    {
        const Theme::Palette pal = themePalette();
        m_icon->setPixmap(ConnectionsUi::glyphPixmap(m_glyph, 13, token(pal.textSecondary), 2.0));
        m_label->setStyleSheet(QStringLiteral("color: %1;").arg(pal.textSecondary));
        m_caption->setStyleSheet(QStringLiteral("color: %1;").arg(pal.textMuted));
        applyTone();
    }

private:
    void applyTone()
    {
        const Theme::Palette pal = themePalette();
        QString value;
        switch (m_tone) {
        case Tone::Accent:  value = pal.accentPrimary; break;
        case Tone::Danger:  value = pal.semanticDanger; break;
        case Tone::Success: value = pal.semanticSuccess; break;
        case Tone::Warning: value = pal.semanticWarning; break;
        }
        m_value->setStyleSheet(QStringLiteral("color: %1;").arg(value));
    }

    Glyph m_glyph;
    QLabel *m_icon = nullptr;
    QLabel *m_label = nullptr;
    QLabel *m_value = nullptr;
    QLabel *m_caption = nullptr;
    Tone m_tone = Tone::Accent;
};

// ============================================================================
// Filter pill
// ============================================================================

class FilterPill : public QAbstractButton
{
public:
    enum class CountTone { Muted, Danger, Warning };

    explicit FilterPill(const QString &label, QWidget *parent = nullptr)
        : QAbstractButton(parent)
        , m_label(label)
    {
        setCheckable(true);
        setCursor(Qt::PointingHandCursor);
        setFocusPolicy(Qt::NoFocus);
        setFixedHeight(26);
    }

    void setCount(const QString &count, CountTone tone = CountTone::Muted)
    {
        if (m_count == count && m_tone == tone)
            return;
        m_count = count;
        m_tone = tone;
        updateGeometry();
        update();
    }

    QSize sizeHint() const override
    {
        const QFontMetrics metrics(uiFont(12, QFont::Medium));
        int width = 24 + metrics.horizontalAdvance(m_label);
        if (!m_count.isEmpty()) {
            const QFontMetrics countMetrics(uiFont(11, QFont::Medium));
            width += 5 + countMetrics.horizontalAdvance(m_count);
        }
        return QSize(width, 26);
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        const Theme::Palette pal = themePalette();
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);

        if (isChecked()) {
            painter.setPen(QPen(token(pal.borderDefault), 1));
            painter.setBrush(token(pal.surfaceElevated));
            painter.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 5, 5);
        } else if (underMouse()) {
            painter.setPen(Qt::NoPen);
            painter.setBrush(token(pal.surfaceHover));
            painter.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 5, 5);
        }

        const QColor foreground = isChecked() || underMouse()
                                      ? token(pal.textPrimary)
                                      : token(pal.textSecondary);
        const QFont font = uiFont(12, QFont::Medium);
        painter.setFont(font);
        painter.setPen(foreground);
        const QRect textRect(12, 0, width() - 24, height());
        painter.drawText(textRect, Qt::AlignLeft | Qt::AlignVCenter, m_label);

        if (!m_count.isEmpty()) {
            QColor countColor;
            switch (m_tone) {
            case CountTone::Danger:  countColor = token(pal.semanticDanger); break;
            case CountTone::Warning: countColor = token(pal.semanticWarning); break;
            case CountTone::Muted:   countColor = token(pal.textMuted); break;
            }
            painter.setFont(uiFont(11, QFont::Medium));
            painter.setPen(countColor);
            painter.drawText(textRect, Qt::AlignRight | Qt::AlignVCenter, m_count);
        }
    }

    void enterEvent(QEnterEvent *event) override
    {
        QAbstractButton::enterEvent(event);
        update();
    }

    void leaveEvent(QEvent *event) override
    {
        QAbstractButton::leaveEvent(event);
        update();
    }

private:
    QString m_label;
    QString m_count;
    CountTone m_tone = CountTone::Muted;
};

// ============================================================================
// Page
// ============================================================================

ConnectionsPage::ConnectionsPage(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("connectionsPage"));

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::Dim::PagePaddingH, 20,
                             Theme::Dim::PagePaddingH, 0);
    root->setSpacing(16);

    buildMetrics(root);
    buildToolbar(root);
    buildTable(root);
    buildInspector();

    // Header actions: Export writes the connections currently shown.
    m_actionsWidget = new QWidget(this);
    auto *actionsLayout = new QHBoxLayout(m_actionsWidget);
    actionsLayout->setContentsMargins(0, 0, 0, 0);
    actionsLayout->setSpacing(8);

    m_exportButton = new QPushButton(QStringLiteral("Export"), m_actionsWidget);
    m_exportButton->setFixedHeight(Theme::Dim::ButtonHeight);
    m_exportButton->setIconSize(QSize(15, 15));
    m_exportButton->setCursor(Qt::PointingHandCursor);
    m_exportButton->setToolTip(QStringLiteral("Export the connections currently shown as CSV."));

    actionsLayout->addWidget(m_exportButton);

    connect(m_exportButton, &QPushButton::clicked, this, &ConnectionsPage::exportVisibleRows);

    connect(&ThemeManager::instance(), &ThemeManager::themeChanged, this,
            [this](ThemeManager::Mode) {
        refreshTheme();
    });

    // The window must keep ageing even if capture stops and no new beat
    // arrives, so closed rows expire on wall-clock time rather than on data.
    m_clock = new QTimer(this);
    m_clock->setInterval(1000);
    m_clock->setTimerType(Qt::CoarseTimer);
    connect(m_clock, &QTimer::timeout, this, &ConnectionsPage::onClockTick);
    m_clock->start();

    refreshMetrics();
    refreshPills();
    refreshEmptyState();
    refreshTheme();
}

void ConnectionsPage::buildMetrics(QVBoxLayout *root)
{
    auto *grid = new QGridLayout;
    grid->setContentsMargins(0, 0, 0, 0);
    grid->setHorizontalSpacing(12);
    grid->setVerticalSpacing(12);

    m_activeTile = new MetricTile(Glyph::Globe, QStringLiteral("Active Connections"), this);
    m_blockedTile = new MetricTile(Glyph::Shield, QStringLiteral("Blocked"), this);
    m_outboundTile = new MetricTile(Glyph::TrendUp, QStringLiteral("Outbound ↑"), this);
    m_inboundTile = new MetricTile(Glyph::TrendDown, QStringLiteral("Inbound ↓"), this);
    m_unknownTile = new MetricTile(Glyph::Info, QStringLiteral("Unknown"), this);

    MetricTile *tiles[] = {m_activeTile, m_blockedTile, m_outboundTile,
                           m_inboundTile, m_unknownTile};
    for (int i = 0; i < 5; ++i) {
        grid->addWidget(tiles[i], 0, i);
        grid->setColumnStretch(i, 1);
    }
    root->addLayout(grid);
}

void ConnectionsPage::buildToolbar(QVBoxLayout *root)
{
    auto *toolbar = new QHBoxLayout;
    toolbar->setContentsMargins(0, 0, 0, 0);
    toolbar->setSpacing(10);

    m_search = new QLineEdit(this);
    m_search->setPlaceholderText(QStringLiteral("Filter by app, domain, IP, or port…"));
    m_search->setClearButtonEnabled(true);
    m_search->setFixedHeight(36);
    m_search->setMinimumWidth(220);
    m_search->setMaximumWidth(340);
    m_search->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_searchAction = m_search->addAction(QIcon(), QLineEdit::LeadingPosition);
    toolbar->addWidget(m_search);

    m_pillHost = new QFrame(this);
    m_pillHost->setObjectName(QStringLiteral("connectionFilterPills"));
    m_pillHost->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    auto *pillLayout = new QHBoxLayout(m_pillHost);
    pillLayout->setContentsMargins(3, 3, 3, 3);
    pillLayout->setSpacing(2);

    m_pillGroup = new QButtonGroup(this);
    m_pillGroup->setExclusive(true);

    auto makePill = [this, pillLayout](FilterPill **store, const QString &text,
                                       Connections::Filter filter) {
        auto *pill = new FilterPill(text, m_pillHost);
        m_pillGroup->addButton(pill, int(filter));
        pillLayout->addWidget(pill);
        *store = pill;
        return pill;
    };

    m_pillAll = makePill(&m_pillAll, QStringLiteral("All"), Connections::Filter::All);
    m_pillOutbound = makePill(&m_pillOutbound, QStringLiteral("Outbound"),
                              Connections::Filter::Outbound);
    m_pillInbound = makePill(&m_pillInbound, QStringLiteral("Inbound"),
                             Connections::Filter::Inbound);
    m_pillBlocked = makePill(&m_pillBlocked, QStringLiteral("Blocked"),
                             Connections::Filter::Blocked);
    m_pillUnknown = makePill(&m_pillUnknown, QStringLiteral("Unknown"),
                             Connections::Filter::Unknown);
    m_pillAll->setChecked(true);

    toolbar->addWidget(m_pillHost);
    toolbar->addStretch(1);

    m_groupButton = new QPushButton(QStringLiteral("Group by App"), this);
    m_groupButton->setFixedHeight(36);
    m_groupButton->setIconSize(QSize(14, 14));
    m_groupButton->setCursor(Qt::PointingHandCursor);
    m_groupButton->setToolTip(QStringLiteral(
        "Rows are grouped by application and destination. Expand a row to see its sockets."));
    auto *groupMenu = new QMenu(m_groupButton);
    auto *groupAction = groupMenu->addAction(QStringLiteral("Group by App"));
    groupAction->setCheckable(true);
    groupAction->setChecked(true);
    m_groupButton->setMenu(groupMenu);
    toolbar->addWidget(m_groupButton);

    m_rangeButton = new QPushButton(timeRangeLabel(m_timeRange), this);
    m_rangeButton->setFixedHeight(36);
    m_rangeButton->setIconSize(QSize(14, 14));
    m_rangeButton->setCursor(Qt::PointingHandCursor);
    m_rangeButton->setToolTip(QStringLiteral(
        "Shows connections observed in the selected window. Connections that "
        "close stay listed, marked closed, until they age out of the window."));
    auto *rangeMenu = new QMenu(m_rangeButton);
    auto *rangeGroup = new QActionGroup(rangeMenu);
    rangeGroup->setExclusive(true);
    for (TimeRange range : {TimeRange::Live, TimeRange::OneMinute,
                            TimeRange::FiveMinutes, TimeRange::FifteenMinutes,
                            TimeRange::OneHour}) {
        QAction *action = rangeMenu->addAction(timeRangeLabel(range));
        action->setCheckable(true);
        action->setChecked(range == m_timeRange);
        rangeGroup->addAction(action);
        connect(action, &QAction::triggered, this, [this, range]() {
            setTimeRange(range);
        });
    }
    m_rangeButton->setMenu(rangeMenu);
    toolbar->addWidget(m_rangeButton);

    root->addLayout(toolbar);

    connect(m_search, &QLineEdit::textChanged, this, [this](const QString &text) {
        m_query = text;
        applyFilters();
    });
    connect(m_pillGroup, &QButtonGroup::idClicked, this, [this](int id) {
        setFilter(static_cast<Connections::Filter>(id));
    });
}

void ConnectionsPage::buildTable(QVBoxLayout *root)
{
    m_stack = new QStackedWidget(this);

    m_table = new ConnectionsTable(m_stack);
    m_stack->addWidget(m_table);

    m_empty = new EmptyStateWidget(m_stack);
    m_stack->addWidget(m_empty);

    m_stack->setCurrentWidget(m_table);
    root->addWidget(m_stack, 1);

    connect(m_table, &ConnectionsTable::selectionChanged,
            this, &ConnectionsPage::onSelectionChanged);
    connect(m_table, &ConnectionsTable::inspectRequested, this, [this](const QString &id) {
        openInspector(id);
    });

    connect(m_empty, &EmptyStateWidget::actionTriggered, this, [this]() {
        if (m_emptyFiltered)
            clearFilters();
        else
            emit refreshRequested();
    });
}

void ConnectionsPage::buildInspector()
{
    m_inspector = new QFrame(this);
    m_inspector->setObjectName(QStringLiteral("connectionInspector"));
    m_inspector->setFixedWidth(320);
    m_inspector->hide();

    auto *layout = new QVBoxLayout(m_inspector);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto *header = new QWidget(m_inspector);
    auto *headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(16, 16, 12, 12);
    headerLayout->setSpacing(8);

    auto *titleBox = new QVBoxLayout;
    titleBox->setContentsMargins(0, 0, 0, 0);
    titleBox->setSpacing(2);

    m_inspectorTitle = new QLabel(QStringLiteral("Connection Detail"), header);
    m_inspectorTitle->setFont(uiFont(14, QFont::DemiBold));
    m_inspectorTitle->setWordWrap(true);
    m_inspectorSubtitle = new QLabel(QStringLiteral("—"), header);
    m_inspectorSubtitle->setFont(uiFont(11, QFont::Normal));
    m_inspectorSubtitle->setWordWrap(true);
    titleBox->addWidget(m_inspectorTitle);
    titleBox->addWidget(m_inspectorSubtitle);

    auto *closeButton = new QPushButton(header);
    closeButton->setFixedSize(26, 26);
    closeButton->setProperty("variant", QStringLiteral("ghost"));
    closeButton->setCursor(Qt::PointingHandCursor);
    closeButton->setToolTip(QStringLiteral("Close inspector"));
    closeButton->setIconSize(QSize(14, 14));
    closeButton->setIcon(ConnectionsUi::glyphIcon(Glyph::Close, 14,
                                                  token(themePalette().textSecondary), 2.0));

    headerLayout->addLayout(titleBox, 1);
    headerLayout->addWidget(closeButton, 0, Qt::AlignTop);
    layout->addWidget(header);

    auto *divider = new QFrame(m_inspector);
    divider->setProperty("uiRole", QStringLiteral("divider"));
    layout->addWidget(divider);

    m_inspectorScroll = new QScrollArea(m_inspector);
    m_inspectorScroll->setWidgetResizable(true);
    m_inspectorScroll->setFrameShape(QFrame::NoFrame);
    m_inspectorScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    auto *body = new QWidget(m_inspectorScroll);
    m_inspectorBody = new QVBoxLayout(body);
    m_inspectorBody->setContentsMargins(16, 16, 16, 16);
    m_inspectorBody->setSpacing(0);
    m_inspectorScroll->setWidget(body);
    layout->addWidget(m_inspectorScroll, 1);

    connect(closeButton, &QPushButton::clicked, this, &ConnectionsPage::closeInspector);
}

void ConnectionsPage::setGroups(const QList<Connections::Row> &groups)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    m_liveIds.clear();
    for (const Connections::Row &row : groups) {
        ObservedRow &observed = m_history[row.id];
        observed.row = row;
        if (!m_monitoringActive) {
            // A beat delivered while capture is stopped is a stale repeat of
            // the last observation, not proof the connection is still open.
            if (observed.lastSeenMs == 0)
                observed.lastSeenMs = now;
            continue;
        }
        m_liveIds.insert(row.id);
        observed.lastSeenMs = now;
    }

    // When a destination gains a name, its row id changes and the unnamed row
    // closes. If a live row for the same application still covers one of those
    // addresses, the closed row is only a stale identity for sockets that are
    // represented above, so it must not linger as a second copy of the app.
    if (!m_liveIds.isEmpty()) {
        QHash<QString, QSet<QString>> liveAddresses;
        for (auto it = m_history.cbegin(); it != m_history.cend(); ++it) {
            const QString &key = it.value().row.appKey;
            if (key.isEmpty() || !m_liveIds.contains(it.key()))
                continue;
            QSet<QString> &addresses = liveAddresses[key];
            for (const QString &address : it.value().row.addresses)
                addresses.insert(address);
        }
        for (auto it = m_history.begin(); it != m_history.end();) {
            bool superseded = false;
            const QString &key = it.value().row.appKey;
            if (!key.isEmpty() && !m_liveIds.contains(it.key())) {
                const QSet<QString> live = liveAddresses.value(key);
                for (const QString &address : it.value().row.addresses) {
                    if (live.contains(address)) {
                        superseded = true;
                        break;
                    }
                }
            }
            if (superseded)
                it = m_history.erase(it);
            else
                ++it;
        }
    }

    // Forget closed rows once they leave the widest window on offer. Live rows
    // are never dropped, however long they have been connected.
    pruneHistory(now);

    rebuildVisibleRows();
    refreshMetrics();
    applyFilters();

    if (!m_inspectorId.isEmpty())
        renderInspector();
}

void ConnectionsPage::setTimeRange(TimeRange range)
{
    m_timeRange = range;
    if (m_rangeButton)
        m_rangeButton->setText(timeRangeLabel(range));
    rebuildVisibleRows();
    applyFilters();

    if (!m_inspectorId.isEmpty())
        renderInspector();
}

void ConnectionsPage::rebuildVisibleRows()
{
    m_rows = collectVisibleRows(QDateTime::currentMSecsSinceEpoch());
}

QList<Connections::Row> ConnectionsPage::collectVisibleRows(qint64 nowMs) const
{
    const qint64 window = timeRangeWindowMs(m_timeRange);

    QList<Connections::Row> visible;
    for (auto it = m_history.cbegin(); it != m_history.cend(); ++it) {
        const ObservedRow &observed = it.value();
        const bool live = m_liveIds.contains(it.key());
        if (m_timeRange == TimeRange::Live && !live)
            continue;
        if (!live && nowMs - observed.lastSeenMs > window)
            continue;
        visible.append(observed.row);
    }
    return visible;
}

void ConnectionsPage::pruneHistory(qint64 nowMs)
{
    const qint64 retention = timeRangeWindowMs(TimeRange::OneHour);
    for (auto it = m_history.begin(); it != m_history.end();) {
        if (!m_liveIds.contains(it.key()) && nowMs - it.value().lastSeenMs > retention)
            it = m_history.erase(it);
        else
            ++it;
    }
}

void ConnectionsPage::onClockTick()
{
    // Only closed rows age; live rows stay visible for as long as they live.
    bool hasClosed = false;
    for (auto it = m_history.cbegin(); it != m_history.cend() && !hasClosed; ++it)
        hasClosed = !m_liveIds.contains(it.key());
    if (!hasClosed)
        return;

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    pruneHistory(now);

    const QList<Connections::Row> visible = collectVisibleRows(now);
    if (!sameRowIds(m_rows, visible)) {
        m_rows = visible;
        applyFilters();
        if (!m_inspectorId.isEmpty())
            renderInspector();
        return;
    }

    // Row contents are unchanged, but the "Closed 2 min ago" labels are drawn
    // at paint time, so a repaint is all that ageing needs.
    m_table->refreshClosedTimestamps();
    if (!m_inspectorId.isEmpty() && m_inspectorSubtitle) {
        if (const Connections::Row *row = rowForId(m_inspectorId)) {
            if (!m_liveIds.contains(row->id))
                m_inspectorSubtitle->setText(inspectorSubtitle(*row));
        }
    }
}

QString ConnectionsPage::timeRangeLabel(TimeRange range)
{
    switch (range) {
    case TimeRange::Live:           return QStringLiteral("Live");
    case TimeRange::OneMinute:      return QStringLiteral("Last 1 min");
    case TimeRange::FiveMinutes:    return QStringLiteral("Last 5 min");
    case TimeRange::FifteenMinutes: return QStringLiteral("Last 15 min");
    case TimeRange::OneHour:        return QStringLiteral("Last 1 hour");
    }
    return QStringLiteral("Last 5 min");
}

qint64 ConnectionsPage::timeRangeWindowMs(TimeRange range)
{
    switch (range) {
    case TimeRange::Live:           return 0;
    case TimeRange::OneMinute:      return 60LL * 1000;
    case TimeRange::FiveMinutes:    return 5LL * 60 * 1000;
    case TimeRange::FifteenMinutes: return 15LL * 60 * 1000;
    case TimeRange::OneHour:        return 60LL * 60 * 1000;
    }
    return 5LL * 60 * 1000;
}

void ConnectionsPage::setMonitoringActive(bool active)
{
    const bool stopped = m_monitoringActive && !active;
    m_monitoringActive = active;

    if (stopped) {
        // No further beat will confirm these rows, so the last observation is
        // the moment capture stopped. They become closed and the page clock
        // ages them out of the selected window from here on.
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        for (auto it = m_history.begin(); it != m_history.end(); ++it) {
            if (m_liveIds.contains(it.key()))
                it.value().lastSeenMs = now;
        }
        m_liveIds.clear();
        rebuildVisibleRows();
        refreshMetrics();
        applyFilters();
        if (!m_inspectorId.isEmpty())
            renderInspector();
    }

    refreshEmptyState();
}

void ConnectionsPage::setFilter(Connections::Filter filter)
{
    m_filter = filter;
    if (QAbstractButton *button = m_pillGroup->button(int(filter)))
        button->setChecked(true);
    applyFilters();
}

void ConnectionsPage::clearFilters()
{
    m_filter = Connections::Filter::All;
    if (m_pillAll)
        m_pillAll->setChecked(true);
    if (m_search) {
        const QSignalBlocker blocker(m_search);
        m_search->clear();
    }
    m_query.clear();
    applyFilters();
}

void ConnectionsPage::applyFilters()
{
    m_filtered.clear();
    for (const Connections::Row &row : m_rows) {
        if (Connections::matchesFilter(row, m_filter)
            && Connections::matchesQuery(row, m_query)) {
            m_filtered.append(row);
        }
    }

    QHash<QString, qint64> closedAt;
    for (const Connections::Row &row : m_filtered) {
        if (!m_liveIds.contains(row.id))
            closedAt.insert(row.id, m_history.value(row.id).lastSeenMs);
    }

    m_table->setClosedAt(closedAt);
    m_table->setRows(m_filtered);
    refreshPills();
    refreshEmptyState();
}

void ConnectionsPage::refreshPills()
{
    int endpoints = 0;
    int blocked = 0;
    int unknown = 0;

    for (const Connections::Row &row : m_rows) {
        const int count = endpointCountFor(row);
        endpoints += count;
        if (row.policyToken == QLatin1String("blocked"))
            blocked += count;

        for (const Connections::Endpoint &endpoint : row.endpoints) {
            if (!endpointNamed(endpoint))
                ++unknown;
        }
        if (row.endpoints.isEmpty() && !row.hasDomain)
            unknown += count;
    }

    if (m_pillAll)
        m_pillAll->setCount(QString::number(endpoints));
    if (m_pillBlocked)
        m_pillBlocked->setCount(QString::number(blocked), FilterPill::CountTone::Danger);
    if (m_pillUnknown)
        m_pillUnknown->setCount(QString::number(unknown), FilterPill::CountTone::Warning);
}

void ConnectionsPage::refreshMetrics()
{
    int endpoints = 0;
    int blocked = 0;
    int unknown = 0;
    quint64 rxBytes = 0;
    quint64 txBytes = 0;
    quint64 rxRate = 0;
    quint64 txRate = 0;
    QSet<QString> seen;

    for (const Connections::Row &row : m_rows) {
        // Tiles describe the live capture, not rows that closed in the window.
        if (!m_liveIds.contains(row.id))
            continue;

        const int count = endpointCountFor(row);
        endpoints += count;
        if (row.policyToken == QLatin1String("blocked"))
            blocked += count;

        rxBytes += row.rxBytes;
        txBytes += row.txBytes;
        rxRate += row.rxBytesPerSecond;
        txRate += row.txBytesPerSecond;

        for (const Connections::Endpoint &endpoint : row.endpoints) {
            seen.insert(QStringLiteral("%1|%2|%3")
                            .arg(row.id, endpoint.address)
                            .arg(endpoint.port));
            if (!endpointNamed(endpoint))
                ++unknown;
        }
        if (row.endpoints.isEmpty() && !row.hasDomain)
            unknown += count;
    }

    int added = 0;
    if (!m_seenEndpoints.isEmpty()) {
        for (const QString &key : seen) {
            if (!m_seenEndpoints.contains(key))
                ++added;
        }
    }
    m_seenEndpoints = seen;

    m_activeTile->setValue(QString::number(endpoints), MetricTile::Tone::Accent);
    m_activeTile->setCaption(QStringLiteral("↑ %1 in last 60s").arg(added));

    m_blockedTile->setValue(QString::number(blocked), MetricTile::Tone::Danger);
    m_blockedTile->setCaption(QStringLiteral("%1 blocked this session").arg(blocked));

    m_outboundTile->setValue(Connections::formatBytes(txBytes), MetricTile::Tone::Accent);
    m_outboundTile->setCaption(
        QStringLiteral("Avg %1").arg(Connections::formatRate(txRate)));

    m_inboundTile->setValue(Connections::formatBytes(rxBytes), MetricTile::Tone::Success);
    m_inboundTile->setCaption(
        QStringLiteral("Avg %1").arg(Connections::formatRate(rxRate)));

    m_unknownTile->setValue(QString::number(unknown), MetricTile::Tone::Warning);
    m_unknownTile->setCaption(QStringLiteral("No domain attribution"));
}

void ConnectionsPage::refreshEmptyState()
{
    if (!m_stack)
        return;

    if (!m_filtered.isEmpty()) {
        m_emptyFiltered = false;
        m_stack->setCurrentWidget(m_table);
        return;
    }

    if (!m_rows.isEmpty()) {
        m_emptyFiltered = true;
        m_empty->setTitle(QStringLiteral("No matching connections"));
        m_empty->setDetail(
            QStringLiteral("No destination matches the current search or filter."));
        m_empty->setAction(QStringLiteral("Clear filters"));
    } else {
        m_emptyFiltered = false;
        m_empty->setTitle(QStringLiteral("No connections observed"));
        m_empty->setDetail(
            m_monitoringActive
                ? QStringLiteral("Traffic will appear here as applications connect. "
                                 "Every destination is named only from observed DNS or "
                                 "TLS SNI evidence.")
                : QStringLiteral("Monitoring is stopped. Start capture to collect "
                                 "destination evidence."));
        m_empty->setAction(QStringLiteral("Refresh"));
    }

    m_stack->setCurrentWidget(m_empty);
}

void ConnectionsPage::refreshTheme()
{
    const Theme::Palette pal = themePalette();

    m_inspector->setStyleSheet(
        QStringLiteral("QFrame#connectionInspector {"
                       " background-color: %1;"
                       " border-left: 1px solid %2; }")
            .arg(pal.surfaceSidebar, pal.borderDefault));

    if (m_pillHost) {
        m_pillHost->setStyleSheet(
            QStringLiteral("QFrame#connectionFilterPills {"
                           " background-color: %1;"
                           " border: 1px solid %2;"
                           " border-radius: 8px; }")
                .arg(pal.surfacePrimary, pal.borderDefault));
    }

    const QColor secondary = token(pal.textSecondary);
    if (m_searchAction)
        m_searchAction->setIcon(ConnectionsUi::glyphIcon(Glyph::Search, 15,
                                                        token(pal.textMuted), 2.0));
    if (m_exportButton)
        m_exportButton->setIcon(ConnectionsUi::glyphIcon(Glyph::Download, 15, secondary, 2.0));
    if (m_groupButton)
        m_groupButton->setIcon(ConnectionsUi::glyphIcon(Glyph::GroupLines, 14, secondary, 2.0));
    if (m_rangeButton)
        m_rangeButton->setIcon(ConnectionsUi::glyphIcon(Glyph::Clock, 14, secondary, 2.0));

    for (MetricTile *tile : {m_activeTile, m_blockedTile, m_outboundTile,
                             m_inboundTile, m_unknownTile}) {
        if (tile)
            tile->refreshTheme();
    }

    if (m_inspectorTitle)
        m_inspectorTitle->setStyleSheet(
            QStringLiteral("color: %1;").arg(pal.textPrimary));
    if (m_inspectorSubtitle)
        m_inspectorSubtitle->setStyleSheet(
            QStringLiteral("color: %1;").arg(pal.textMuted));

    update();
}

void ConnectionsPage::exportVisibleRows()
{
    if (m_filtered.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Export connections"),
                                 QStringLiteral("There are no connections to export."));
        return;
    }

    const QString directory =
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    const QString suggestion = QDir(directory).filePath(
        QStringLiteral("oasis-connections-%1.csv")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"))));

    const QString fileName = QFileDialog::getSaveFileName(
        this, QStringLiteral("Export connections"), suggestion,
        QStringLiteral("CSV files (*.csv)"));
    if (fileName.isEmpty())
        return;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, QStringLiteral("Export failed"),
                             QStringLiteral("The file could not be written:\n%1")
                                 .arg(file.errorString()));
        return;
    }

    auto quote = [](QString value) {
        value.replace(QLatin1Char('"'), QStringLiteral("\"\""));
        return QStringLiteral("\"%1\"").arg(value);
    };

    QTextStream out(&file);
    out.setEncoding(QStringConverter::Utf8);
    out << "Application,Process,PID,Destination,Addresses,Port,Protocol,Direction,"
           "Confidence,Policy,Rx bytes,Tx bytes,Status\n";

    for (const Connections::Row &row : m_filtered) {
        out << quote(applicationLabel(row)) << ','
            << quote(row.appName) << ','
            << row.pid << ','
            << quote(row.hasDomain ? row.destination : QStringLiteral("No domain")) << ','
            << quote(row.addresses.join(QStringLiteral("; "))) << ','
            << rowPort(row) << ','
            << quote(rowProtocol(row)) << ','
            << quote(row.direction) << ','
            << quote(row.confidence) << ','
            << quote(row.policy) << ','
            << row.rxBytes << ','
            << row.txBytes << ','
            << quote(m_liveIds.contains(row.id) ? QStringLiteral("Live")
                                                : QStringLiteral("Closed")) << '\n';
    }
    file.close();
}

void ConnectionsPage::openInspector(const QString &id)
{
    if (!rowForId(id))
        return;
    m_inspectorId = id;
    renderInspector();
    if (!m_inspector->isVisible()) {
        m_inspector->show();
        m_inspector->raise();
    }
}

void ConnectionsPage::closeInspector()
{
    m_inspectorId.clear();
    if (m_inspector)
        m_inspector->hide();
}

void ConnectionsPage::onSelectionChanged(const QString &id)
{
    m_selectedId = id;
    if (id.isEmpty()) {
        closeInspector();
        return;
    }
    if (m_inspector && m_inspector->isVisible()) {
        m_inspectorId = id;
        renderInspector();
    }
}

void ConnectionsPage::renderInspector()
{
    const Connections::Row *row = rowForId(m_inspectorId);
    if (!row) {
        closeInspector();
        return;
    }

    m_inspectorTitle->setText(
        QStringLiteral("%1 → %2")
            .arg(applicationLabel(*row),
                 row->hasDomain ? row->destination : QStringLiteral("No domain")));

    m_inspectorSubtitle->setText(inspectorSubtitle(*row));

    const quint16 port = rowPort(*row);

    clearLayout(m_inspectorBody);

    auto addSection = [this](const QString &title,
                             const QList<QPair<QString, QString>> &rows,
                             bool monoValues = false) {
        auto *titleLabel = new QLabel(title, m_inspectorScroll);
        QFont titleFont = uiFont(10, QFont::DemiBold);
        titleFont.setCapitalization(QFont::AllUppercase);
        titleFont.setLetterSpacing(QFont::AbsoluteSpacing, 0.5);
        titleLabel->setFont(titleFont);
        titleLabel->setStyleSheet(
            QStringLiteral("color: %1; margin-top: 4px;")
                .arg(themePalette().textMuted));
        m_inspectorBody->addWidget(titleLabel);
        m_inspectorBody->addSpacing(6);

        bool first = true;
        for (const auto &entry : rows) {
            if (!first) {
                auto *divider = new QFrame(m_inspectorScroll);
                divider->setProperty("uiRole", QStringLiteral("divider"));
                divider->setStyleSheet(QStringLiteral("background-color: %1;")
                                           .arg(themePalette().borderDefault));
                m_inspectorBody->addWidget(divider);
            }
            first = false;

            auto *line = new QWidget(m_inspectorScroll);
            auto *lineLayout = new QHBoxLayout(line);
            lineLayout->setContentsMargins(0, 6, 0, 6);
            lineLayout->setSpacing(10);

            auto *key = new QLabel(entry.first, line);
            key->setFont(uiFont(11, QFont::Normal));
            key->setStyleSheet(
                QStringLiteral("color: %1;").arg(themePalette().textMuted));
            key->setAlignment(Qt::AlignLeft | Qt::AlignTop);

            auto *value = new QLabel(entry.second.isEmpty() ? QStringLiteral("—")
                                                            : entry.second,
                                     line);
            QFont valueFont = monoValues ? QFont(QStringLiteral("Consolas"))
                                         : uiFont(12, QFont::Normal);
            if (monoValues)
                valueFont.setPixelSize(11);
            value->setFont(valueFont);
            value->setStyleSheet(
                QStringLiteral("color: %1;").arg(themePalette().textPrimary));
            value->setWordWrap(true);
            value->setAlignment(Qt::AlignRight | Qt::AlignTop);
            value->setTextInteractionFlags(Qt::TextSelectableByMouse);

            lineLayout->addWidget(key, 0);
            lineLayout->addWidget(value, 1);
            m_inspectorBody->addWidget(line);
        }
        m_inspectorBody->addSpacing(14);
    };

    QStringList names = row->domainNames;
    if (row->hasDomain && names.isEmpty())
        names << row->destination;

    addSection(QStringLiteral("Application"), {
        {QStringLiteral("Process"), row->appName.isEmpty()
                                        ? QStringLiteral("Unknown process")
                                        : row->appName},
        {QStringLiteral("PID"), QString::number(row->pid)},
        {QStringLiteral("Binary path"), row->path.isEmpty()
                                            ? QStringLiteral("Unable to resolve")
                                            : row->path},
        {QStringLiteral("Publisher"), row->publisher},
        {QStringLiteral("Attribution"), QStringLiteral("%1 — %2")
                                            .arg(row->confidence, row->evidenceLabel)},
    }, true);

    addSection(QStringLiteral("Destination"), {
        {QStringLiteral("Domain"), row->hasDomain ? names.join(QStringLiteral(", "))
                                                  : QStringLiteral("None resolved")},
        {QStringLiteral("Resolved IPs"), row->addresses.join(QStringLiteral(", "))},
        {QStringLiteral("Port"), port ? QString::number(port) : QStringLiteral("—")},
        {QStringLiteral("Protocol"), rowProtocol(*row)},
        {QStringLiteral("Direction"), row->direction},
        {QStringLiteral("Observed names"), row->domainNames.join(QStringLiteral(", "))},
    });

    addSection(QStringLiteral("Policy"), {
        {QStringLiteral("Status"), row->policy == QLatin1String("None")
                                       ? QStringLiteral("No policy")
                                       : row->policy},
        {QStringLiteral("Scope"), QStringLiteral("Rules apply to %1, not to a single IP.")
                                      .arg(applicationLabel(*row))},
    });

    addSection(QStringLiteral("Traffic (session)"), {
        {QStringLiteral("Inbound"), Connections::formatBytes(row->rxBytes)},
        {QStringLiteral("Outbound"), Connections::formatBytes(row->txBytes)},
        {QStringLiteral("Current rate"), Connections::formatRate(row->bytesPerSecond())},
        {QStringLiteral("Endpoints"), QString::number(endpointCountFor(*row))},
        {QStringLiteral("Packets"), QString::number(row->packets)},
    });

    auto *actions = new QWidget(m_inspectorScroll);
    auto *actionsLayout = new QVBoxLayout(actions);
    actionsLayout->setContentsMargins(0, 0, 0, 0);
    actionsLayout->setSpacing(8);

    auto *trafficButton = new QPushButton(QStringLiteral("Manage app traffic"), actions);
    trafficButton->setFixedHeight(34);
    auto *detailsButton = new QPushButton(QStringLiteral("Application details"), actions);
    detailsButton->setFixedHeight(34);

    const bool canAct = row->pid != 0 || !row->path.trimmed().isEmpty();
    trafficButton->setEnabled(canAct);
    detailsButton->setEnabled(canAct);

    const quint32 pid = row->pid;
    const QString path = row->path;
    const QString name = row->appName;
    connect(trafficButton, &QPushButton::clicked, this, [this, pid, path, name]() {
        emit trafficRequested(pid, path, name);
    });
    connect(detailsButton, &QPushButton::clicked, this, [this, pid, path, name]() {
        emit detailsRequested(pid, path, name);
    });

    actionsLayout->addWidget(trafficButton);
    actionsLayout->addWidget(detailsButton);
    m_inspectorBody->addWidget(actions);
    m_inspectorBody->addStretch(1);
}

QString ConnectionsPage::inspectorSubtitle(const Connections::Row &row) const
{
    QString subtitle = QStringLiteral("PID %1 · %2 :%3 · %4")
                           .arg(row.pid)
                           .arg(rowProtocol(row))
                           .arg(rowPort(row))
                           .arg(row.confidence);
    if (!m_liveIds.contains(row.id)) {
        const qint64 age = QDateTime::currentMSecsSinceEpoch()
                           - m_history.value(row.id).lastSeenMs;
        subtitle += QStringLiteral(" · Closed %1").arg(formatAge(age));
    }
    return subtitle;
}

const Connections::Row *ConnectionsPage::rowForId(const QString &id) const
{
    if (id.isEmpty())
        return nullptr;
    for (const Connections::Row &row : m_rows) {
        if (row.id == id)
            return &row;
    }
    return nullptr;
}

void ConnectionsPage::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    if (m_inspector) {
        m_inspector->setGeometry(width() - m_inspector->width(), 0,
                                 m_inspector->width(), height());
        m_inspector->raise();
    }
}
