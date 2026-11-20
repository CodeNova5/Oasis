/**
 * @file    applicationspage.cpp
 * @author  Oasis
 */
#include "applicationspage.h"
#include "applicationspage_p.h"

#include "ui/components/emptystatewidget.h"
#include "ui/theme/colors.h"
#include "ui/theme/dimensions.h"
#include "ui/theme/thememanager.h"
#include "ui/theme/typography.h"

#include <QAbstractTableModel>
#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QFontMetrics>
#include <QFrame>
#include <QGridLayout>
#include <QHash>
#include <QScrollArea>
#include <QTabWidget>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>
#include <QPair>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QKeySequence>
#include <QShortcut>
#include <QSizePolicy>
#include <QSortFilterProxyModel>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QVBoxLayout>
#include <QVector>

using namespace ApplicationsPageDetail;

namespace Applications {

QString filterLabel(Filter filter)
{
    switch (filter) {
    case Filter::All:
        return QStringLiteral("All applications");
    case Filter::Active:
        return QStringLiteral("Active now");
    case Filter::Idle:
        return QStringLiteral("Idle");
    case Filter::AllowRule:
        return QStringLiteral("Rule · Allow");
    case Filter::AskRule:
        return QStringLiteral("Rule · Ask");
    case Filter::BlockRule:
        return QStringLiteral("Rule · Block");
    }
    return QStringLiteral("All applications");
}

} // namespace Applications

// ============================================================================
// Page
// ============================================================================

ApplicationsPage::ApplicationsPage(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("applicationsPage"));

    auto *rootLayout = new QHBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    auto *content = new QWidget(this);
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(Theme::Dim::PagePaddingH, Theme::Dim::SpaceLg,
                               Theme::Dim::PagePaddingH, Theme::Dim::PagePaddingV);
    layout->setSpacing(Theme::Dim::SpaceLg);
    rootLayout->addWidget(content, 1);

    // ── Toolbar: search, filters, sort and page actions ─────────────────────
    m_actionsWidget = new QWidget(this);
    auto *toolbar = m_actionsWidget;
    auto *toolbarLayout = new QHBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(Theme::Dim::SpaceSm);

    m_search = new QLineEdit(toolbar);
    m_search->setPlaceholderText(QStringLiteral("Search applications…"));
    m_search->setClearButtonEnabled(true);
    m_search->setMinimumWidth(260);
    m_search->setMaximumWidth(340);
    m_search->setFixedHeight(Theme::Dim::InputHeight);
    m_search->setAccessibleName(QStringLiteral("Search applications"));
    m_searchAction = m_search->addAction(QIcon(), QLineEdit::LeadingPosition);
    toolbarLayout->addWidget(m_search);

    auto makeButton = [&](const QString &tooltip) {
        auto *button = new QPushButton(toolbar);
        button->setProperty("variant", QStringLiteral("ghost"));
        button->setFixedSize(Theme::Dim::ButtonHeight, Theme::Dim::ButtonHeight);
        button->setIconSize(QSize(18, 18));
        button->setCursor(Qt::PointingHandCursor);
        button->setToolTip(tooltip);
        button->setAccessibleName(tooltip);
        return button;
    };

    m_filterButton = makeButton(QStringLiteral("Filter applications"));
    m_sortButton = makeButton(QStringLiteral("Sort applications"));
    m_moreButton = makeButton(QStringLiteral("More actions"));
    toolbarLayout->addWidget(m_filterButton);
    toolbarLayout->addWidget(m_sortButton);
    toolbarLayout->addWidget(m_moreButton);

    connect(m_search, &QLineEdit::textChanged, this, &ApplicationsPage::applyQuery);
    connect(m_filterButton, &QPushButton::clicked, this, &ApplicationsPage::showFilterMenu);
    connect(m_sortButton, &QPushButton::clicked, this, &ApplicationsPage::showSortMenu);
    connect(m_moreButton, &QPushButton::clicked, this, &ApplicationsPage::showMoreMenu);

    // ── Table ───────────────────────────────────────────────────────────────
    m_model = new ApplicationsPageTableModel(this);
    m_proxy = new ApplicationsPageFilterModel(m_model, this);

    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSortingEnabled(true);
    m_table->sortByColumn(ApplicationsPageTableModel::Application, Qt::AscendingOrder);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setShowGrid(false);
    m_table->setWordWrap(false);
    m_table->setFrameShape(QFrame::NoFrame);
    m_table->setAlternatingRowColors(false);
    m_table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_table->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_table->verticalHeader()->hide();
    m_table->verticalHeader()->setDefaultSectionSize(kRowHeight);
    m_table->verticalHeader()->setMinimumSectionSize(kRowHeight);
    m_table->setItemDelegateForColumn(ApplicationsPageTableModel::Application,
                                      new ApplicationNameDelegate(m_table));
    m_table->setItemDelegateForColumn(ApplicationsPageTableModel::Rule,
                                      new RuleDelegate(m_table));
    m_table->setItemDelegateForColumn(ApplicationsPageTableModel::Activity,
                                      new ActivityDelegate(m_table));

    QHeaderView *header = m_table->horizontalHeader();
    header->setStretchLastSection(false);
    header->setHighlightSections(false);
    header->setSectionsClickable(true);
    header->setMinimumSectionSize(64);
    header->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    header->setSectionResizeMode(ApplicationsPageTableModel::Application,
                                 QHeaderView::Stretch);
    header->setSectionResizeMode(ApplicationsPageTableModel::Total,
                                 QHeaderView::ResizeToContents);
    header->setSectionResizeMode(ApplicationsPageTableModel::Rule,
                                 QHeaderView::Fixed);
    header->setSectionResizeMode(ApplicationsPageTableModel::Activity,
                                 QHeaderView::Fixed);
    m_table->setColumnWidth(ApplicationsPageTableModel::Rule, 148);
    m_table->setColumnWidth(ApplicationsPageTableModel::Activity, 220);

    // Row actions live on the row: a right-click menu, a click that selects,
    // a double-click or Enter that opens the details drawer, and a click on the
    // rule that opens its menu.
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QTableView::customContextMenuRequested,
            this, &ApplicationsPage::showContextMenu);
    connect(m_table, &QTableView::clicked, this, [this](const QModelIndex &index) {
        if (!index.isValid())
            return;
        if (index.column() == ApplicationsPageTableModel::Rule) {
            showRuleMenu(index);
            return;
        }
        // A click only selects. Opening the drawer here made selection
        // impossible on its own and paid for a details query every time the
        // user scanned the table. Once the drawer is up, though, the selection
        // and the panel must not disagree about which application is shown.
        m_table->selectRow(index.row());
        if (m_detailsOpen)
            openDetailsAt(index);
    });
    connect(m_table, &QTableView::doubleClicked, this, [this](const QModelIndex &index) {
        // The rule pill owns its column; the first click already opened a menu.
        if (index.isValid() && index.column() != ApplicationsPageTableModel::Rule)
            openDetailsAt(index);
    });
    connect(m_table, &QTableView::activated, this, &ApplicationsPage::openDetailsAt);
    layout->addWidget(m_table, 1);

    // ── Empty state ─────────────────────────────────────────────────────────
    m_emptyHost = new QWidget(this);
    auto *emptyLayout = new QVBoxLayout(m_emptyHost);
    emptyLayout->setContentsMargins(0, 0, 0, 0);
    m_empty = new EmptyStateWidget(m_emptyHost);
    emptyLayout->addStretch(1);
    emptyLayout->addWidget(m_empty, 0, Qt::AlignHCenter);
    emptyLayout->addStretch(1);
    m_emptyHost->hide();
    layout->addWidget(m_emptyHost, 1);

    // ── Footer: count and rule legend ───────────────────────────────────────
    m_footer = new QWidget(this);
    auto *footerLayout = new QHBoxLayout(m_footer);
    footerLayout->setContentsMargins(Theme::Dim::SpaceXs, 0,
                                     Theme::Dim::SpaceXs, 0);
    m_footerCount = new QLabel(m_footer);
    m_footerCount->setProperty("uiRole", QStringLiteral("muted"));
    footerLayout->addWidget(m_footerCount);
    footerLayout->addStretch(1);
    m_legend = new QLabel(m_footer);
    m_legend->setTextFormat(Qt::RichText);
    footerLayout->addWidget(m_legend);
    layout->addWidget(m_footer);

    auto *drawer = buildDrawer();
    m_drawer->hide();
    rootLayout->addWidget(drawer);

    // Escape gives the ✕ a keyboard equivalent whenever the drawer is up.
    auto *escape = new QShortcut(QKeySequence(Qt::Key_Escape), this);
    escape->setContext(Qt::WindowShortcut);
    connect(escape, &QShortcut::activated, this, [this]() {
        if (m_detailsOpen && m_drawer && m_drawer->isVisible())
            closeDetails();
    });

    connect(&ThemeManager::instance(), &ThemeManager::themeChanged, this,
            [this](ThemeManager::Mode) {
        refreshThemeIcons();
        refreshFooter();
    });

    refreshThemeIcons();
    refreshFooter();
    refreshEmptyState();
}

QWidget *ApplicationsPage::buildDrawer()
{
    m_drawer = new QFrame(this);
    m_drawer->setObjectName(QStringLiteral("applicationDrawer"));
    m_drawer->setFixedWidth(320);

    auto *layout = new QVBoxLayout(m_drawer);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto *header = new QWidget(m_drawer);
    auto *headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceLg,
                                     Theme::Dim::SpaceMd, Theme::Dim::SpaceSm);
    headerLayout->setSpacing(Theme::Dim::SpaceMd);

    m_drawerIcon = new QLabel(header);
    m_drawerIcon->setFixedSize(32, 32);
    headerLayout->addWidget(m_drawerIcon, 0, Qt::AlignVCenter);

    m_drawerName = new QLabel(header);
    m_drawerName->setObjectName(QStringLiteral("drawerAppName"));
    m_drawerName->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_drawerName->setWordWrap(false);
    headerLayout->addWidget(m_drawerName, 1, Qt::AlignVCenter);

    auto *close = new QPushButton(QStringLiteral("✕"), header);
    close->setProperty("variant", QStringLiteral("ghost"));
    close->setFixedSize(28, 28);
    close->setCursor(Qt::PointingHandCursor);
    close->setToolTip(QStringLiteral("Close details"));
    close->setAccessibleName(QStringLiteral("Close details"));
    headerLayout->addWidget(close, 0, Qt::AlignVCenter);
    layout->addWidget(header);

    m_drawerTabs = new QTabWidget(m_drawer);
    m_drawerTabs->setDocumentMode(true);
    m_drawerTabs->setTabPosition(QTabWidget::North);
    m_drawerTabs->addTab(buildDetailsTab(), QStringLiteral("Details"));
    m_drawerTabs->addTab(buildConnectionsTab(), QStringLiteral("Connections"));
    m_drawerTabs->addTab(buildRulesTab(), QStringLiteral("Rules"));
    layout->addWidget(m_drawerTabs, 1);

    connect(close, &QPushButton::clicked, this, &ApplicationsPage::closeDetails);
    return m_drawer;
}

QWidget *ApplicationsPage::buildDetailsTab()
{
    auto *page = new QWidget(m_drawer);
    auto *pageLayout = new QVBoxLayout(page);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(0);

    auto *scroll = new QScrollArea(page);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    pageLayout->addWidget(scroll);

    auto *content = new QWidget;
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceMd,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    layout->setSpacing(Theme::Dim::SpaceMd);
    scroll->setWidget(content);

    auto *facts = new QGridLayout;
    facts->setHorizontalSpacing(Theme::Dim::SpaceMd);
    facts->setVerticalSpacing(Theme::Dim::SpaceSm);
    facts->setColumnStretch(1, 1);

    auto addFact = [&](int row, const QString &label, QLabel **target, bool wrap) {
        auto *key = new QLabel(label, content);
        key->setProperty("uiRole", QStringLiteral("muted"));
        auto *value = new QLabel(content);
        value->setProperty("uiRole", QStringLiteral("rowValue"));
        value->setWordWrap(wrap);
        value->setTextInteractionFlags(Qt::TextSelectableByMouse);
        value->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        facts->addWidget(key, row, 0, Qt::AlignTop);
        facts->addWidget(value, row, 1, Qt::AlignTop);
        *target = value;
    };
    addFact(0, QStringLiteral("Publisher"), &m_drawerPublisher, false);
    addFact(1, QStringLiteral("Version"), &m_drawerVersion, false);
    addFact(2, QStringLiteral("Installed"), &m_drawerInstalled, false);
    addFact(3, QStringLiteral("Path"), &m_drawerPath, true);
    layout->addLayout(facts);

    auto *ruleHeading = new QLabel(QStringLiteral("Rule"), content);
    ruleHeading->setProperty("uiRole", QStringLiteral("cardHeading"));
    layout->addWidget(ruleHeading);

    m_drawerRuleButton = new QPushButton(content);
    m_drawerRuleButton->setFixedHeight(Theme::Dim::ButtonHeight);
    m_drawerRuleButton->setCursor(Qt::PointingHandCursor);
    m_drawerRuleButton->setToolTip(QStringLiteral("Change the network rule for this application."));
    layout->addWidget(m_drawerRuleButton);
    connect(m_drawerRuleButton, &QPushButton::clicked, this, [this]() {
        if (!m_detailsOpen)
            return;
        showRuleMenuFor(m_details.pid, m_details.path, m_details.name, m_details.rule,
                        m_drawerRuleButton->mapToGlobal(
                            QPoint(0, m_drawerRuleButton->height() + Theme::Dim::SpaceXs)));
    });

    m_ruleHint = new QLabel(content);
    m_ruleHint->setProperty("uiRole", QStringLiteral("muted"));
    m_ruleHint->setWordWrap(true);
    layout->addWidget(m_ruleHint);

    auto *statistics = new QLabel(QStringLiteral("Statistics"), content);
    statistics->setProperty("uiRole", QStringLiteral("cardHeading"));
    layout->addWidget(statistics);

    auto *session = new QLabel(QStringLiteral("This session"), content);
    session->setProperty("uiRole", QStringLiteral("muted"));
    layout->addWidget(session);

    auto *sessionGrid = new QGridLayout;
    sessionGrid->setHorizontalSpacing(Theme::Dim::SpaceMd);
    sessionGrid->setVerticalSpacing(Theme::Dim::SpaceSm);
    auto addStat = [&](QGridLayout *grid, int row, const QString &label, QLabel **target) {
        auto *key = new QLabel(label, content);
        key->setProperty("uiRole", QStringLiteral("muted"));
        auto *value = new QLabel(QStringLiteral("0 B"), content);
        value->setProperty("uiRole", QStringLiteral("rowValue"));
        value->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        grid->addWidget(key, row, 0);
        grid->addWidget(value, row, 1);
        *target = value;
    };
    addStat(sessionGrid, 0, QStringLiteral("Uploaded"), &m_sessionUploaded);
    addStat(sessionGrid, 1, QStringLiteral("Downloaded"), &m_sessionDownloaded);
    addStat(sessionGrid, 2, QStringLiteral("Total"), &m_sessionTotal);
    layout->addLayout(sessionGrid);

    auto *week = new QLabel(QStringLiteral("Last 7 days"), content);
    week->setProperty("uiRole", QStringLiteral("rowTitle"));
    layout->addWidget(week);

    auto *weekGrid = new QGridLayout;
    weekGrid->setHorizontalSpacing(Theme::Dim::SpaceMd);
    weekGrid->setVerticalSpacing(Theme::Dim::SpaceSm);
    addStat(weekGrid, 0, QStringLiteral("Uploaded"), &m_weekUploaded);
    addStat(weekGrid, 1, QStringLiteral("Downloaded"), &m_weekDownloaded);
    addStat(weekGrid, 2, QStringLiteral("Total"), &m_weekTotal);
    layout->addLayout(weekGrid);

    auto *lastActivity = new QLabel(QStringLiteral("Last activity"), content);
    lastActivity->setProperty("uiRole", QStringLiteral("cardHeading"));
    layout->addWidget(lastActivity);

    auto *activityGrid = new QGridLayout;
    activityGrid->setHorizontalSpacing(Theme::Dim::SpaceMd);
    activityGrid->setVerticalSpacing(Theme::Dim::SpaceSm);
    addStat(activityGrid, 0, QStringLiteral("Active"), &m_lastActive);
    addStat(activityGrid, 1, QStringLiteral("Connections"), &m_lastConnections);
    addStat(activityGrid, 2, QStringLiteral("Remote addresses"), &m_lastRemoteAddresses);
    layout->addLayout(activityGrid);

    layout->addStretch(1);
    return page;
}

QWidget *ApplicationsPage::buildConnectionsTab()
{
    auto *page = new QWidget(m_drawer);
    auto *pageLayout = new QVBoxLayout(page);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(0);

    auto *scroll = new QScrollArea(page);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    pageLayout->addWidget(scroll);

    auto *content = new QWidget;
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceMd,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    layout->setSpacing(Theme::Dim::SpaceSm);
    scroll->setWidget(content);

    m_connectionsEmpty = new QLabel(
        QStringLiteral("No connections observed for this application."), content);
    m_connectionsEmpty->setProperty("uiRole", QStringLiteral("muted"));
    m_connectionsEmpty->setWordWrap(true);
    layout->addWidget(m_connectionsEmpty);

    m_connectionsLayout = new QVBoxLayout;
    m_connectionsLayout->setSpacing(Theme::Dim::SpaceSm);
    layout->addLayout(m_connectionsLayout);
    layout->addStretch(1);
    return page;
}

QWidget *ApplicationsPage::buildRulesTab()
{
    auto *page = new QWidget(m_drawer);
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceLg,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    layout->setSpacing(Theme::Dim::SpaceMd);

    auto *heading = new QLabel(QStringLiteral("Rule"), page);
    heading->setProperty("uiRole", QStringLiteral("cardHeading"));
    layout->addWidget(heading);

    m_rulesRuleButton = new QPushButton(page);
    m_rulesRuleButton->setFixedHeight(Theme::Dim::ButtonHeight);
    m_rulesRuleButton->setCursor(Qt::PointingHandCursor);
    layout->addWidget(m_rulesRuleButton);
    connect(m_rulesRuleButton, &QPushButton::clicked, this, [this]() {
        if (!m_detailsOpen)
            return;
        showRuleMenuFor(m_details.pid, m_details.path, m_details.name, m_details.rule,
                        m_rulesRuleButton->mapToGlobal(
                            QPoint(0, m_rulesRuleButton->height() + Theme::Dim::SpaceXs)));
    });

    m_rulesDescription = new QLabel(page);
    m_rulesDescription->setProperty("uiRole", QStringLiteral("muted"));
    m_rulesDescription->setWordWrap(true);
    layout->addWidget(m_rulesDescription);

    auto *note = new QLabel(
        QStringLiteral("Rules set here apply to this executable. Broader publisher "
                       "and group policies still apply."),
        page);
    note->setProperty("uiRole", QStringLiteral("muted"));
    note->setWordWrap(true);
    layout->addWidget(note);
    layout->addStretch(1);
    return page;
}

void ApplicationsPage::showDetails(const Applications::Details &details)
{
    m_details = details;
    m_detailsOpen = true;
    populateDetails();
    if (m_drawerTabs)
        m_drawerTabs->setCurrentIndex(0);
    m_drawer->show();
    m_drawer->raise();
    // Land focus inside the drawer so Tab walks its content instead of
    // continuing through the page behind it.
    if (m_drawerTabs)
        m_drawerTabs->setFocus(Qt::TabFocusReason);
}

void ApplicationsPage::openDetailsAt(const QModelIndex &index)
{
    if (!index.isValid())
        return;
    m_table->selectRow(index.row());
    Applications::Row row;
    if (!rowForIndex(index, &row))
        return;
    // A double-click can arrive as both doubleClicked and activated, and the
    // shell resolves details synchronously; ask once for the open drawer.
    if (m_detailsOpen && m_details.pid == row.pid && m_details.path == row.path)
        return;
    emit detailsRequested(row.pid, row.path, row.name);
}

void ApplicationsPage::closeDetails()
{
    m_detailsOpen = false;
    if (m_drawer)
        m_drawer->hide();
}

void ApplicationsPage::populateDetails()
{
    const QString label = m_details.displayName.trimmed().isEmpty()
        ? m_details.name : m_details.displayName;
    m_drawerName->setText(orDash(label));
    m_drawerPublisher->setText(orDash(m_details.publisher));
    m_drawerVersion->setText(orDash(m_details.version));
    m_drawerInstalled->setText(m_details.installedAt.isValid()
                                   ? m_details.installedAt.toLocalTime().toString(
                                         QStringLiteral("M/d/yyyy"))
                                   : QStringLiteral("—"));
    m_drawerPath->setText(orDash(m_details.path));

    if (!m_details.icon.isNull()) {
        const qreal dpr = m_drawerIcon->devicePixelRatioF();
        m_drawerIcon->setPixmap(m_details.icon.pixmap(QSize(32, 32), dpr));
    } else {
        m_drawerIcon->clear();
    }

    m_sessionUploaded->setText(formattedBytes(m_details.uploadedBytes));
    m_sessionDownloaded->setText(formattedBytes(m_details.downloadedBytes));
    m_sessionTotal->setText(
        formattedBytes(m_details.uploadedBytes + m_details.downloadedBytes));
    m_weekUploaded->setText(formattedBytes(m_details.weeklyUploadedBytes));
    m_weekDownloaded->setText(formattedBytes(m_details.weeklyDownloadedBytes));
    m_weekTotal->setText(
        formattedBytes(m_details.weeklyUploadedBytes + m_details.weeklyDownloadedBytes));

    const Applications::Row *row = nullptr;
    for (const Applications::Row &candidate : m_rows) {
        if (candidate.pid == m_details.pid) {
            row = &candidate;
            break;
        }
    }
    if (row) {
        m_lastActive->setText(blockedRow(*row) ? QStringLiteral("Blocked")
                              : (row->rxBytesPerSecond + row->txBytesPerSecond > 0
                                     ? QStringLiteral("now") : QStringLiteral("—")));
    } else {
        m_lastActive->setText(QStringLiteral("—"));
    }
    m_lastConnections->setText(QString::number(m_details.connectionCount));
    m_lastRemoteAddresses->setText(QString::number(m_details.remoteAddressCount));

    while (QLayoutItem *item = m_connectionsLayout->takeAt(0)) {
        delete item->widget();
        delete item;
    }
    m_connectionsEmpty->setVisible(m_details.endpoints.isEmpty());
    QWidget *connectionsHost = m_connectionsLayout->parentWidget();
    for (const QString &endpoint : m_details.endpoints) {
        auto *line = new QLabel(endpoint, connectionsHost);
        line->setProperty("uiRole", QStringLiteral("rowValue"));
        line->setWordWrap(true);
        line->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_connectionsLayout->addWidget(line);
    }

    applyDetailsRule(m_details.rule);
}

void ApplicationsPage::applyDetailsRule(const QString &rule)
{
    m_details.rule = rule;
    styleRuleButton(m_drawerRuleButton, rule);
    styleRuleButton(m_rulesRuleButton, rule);
    if (m_ruleHint)
        m_ruleHint->setText(ruleDescriptionForToken(rule));
    if (m_rulesDescription)
        m_rulesDescription->setText(ruleDescriptionForToken(rule));
}

void ApplicationsPage::setRows(const QList<Applications::Row> &rows)
{
    // The model diffs the beat in place, so selection, keyboard focus and the
    // scroll offset stay where the user left them; nothing to restore here.
    m_rows = rows;
    m_model->setRows(rows);

    if (m_detailsOpen) {
        for (const Applications::Row &row : m_rows) {
            if (row.pid != m_details.pid)
                continue;
            if (m_drawerName)
                m_drawerName->setText(applicationLabel(row));
            if (m_drawerPublisher)
                m_drawerPublisher->setText(orDash(row.publisher));
            if (m_drawerPath && !row.path.trimmed().isEmpty())
                m_drawerPath->setText(row.path.trimmed());
            if (!row.icon.isNull() && m_drawerIcon) {
                m_drawerIcon->setPixmap(row.icon.pixmap(
                    QSize(32, 32), m_drawerIcon->devicePixelRatioF()));
            }
            if (m_lastActive) {
                m_lastActive->setText(
                    blockedRow(row) ? QStringLiteral("Blocked")
                    : (row.rxBytesPerSecond + row.txBytesPerSecond > 0
                           ? QStringLiteral("now") : QStringLiteral("—")));
            }
            const QString rule = ruleToken(row);
            if (rule != m_details.rule)
                applyDetailsRule(rule);
            break;
        }
    }

    refreshFooter();
    refreshEmptyState();
}

void ApplicationsPage::applyFilter(Applications::Filter filter)
{
    m_filter = filter;
    m_proxy->setFilter(filter);
    refreshFooter();
    refreshEmptyState();
}

void ApplicationsPage::applyQuery(const QString &query)
{
    m_proxy->setQuery(query);
    refreshFooter();
    refreshEmptyState();
}

void ApplicationsPage::refreshEmptyState()
{
    const bool empty = m_proxy->rowCount() == 0;
    m_table->setVisible(!empty);
    m_footer->setVisible(!empty);
    m_emptyHost->setVisible(empty);
    if (!empty)
        return;

    if (m_rows.isEmpty()) {
        m_empty->setTitle(QStringLiteral("No applications found"));
        m_empty->setDetail(
            QStringLiteral("Applications appear here once Oasis observes network "
                           "activity. Start monitoring to populate the list."));
    } else {
        m_empty->setTitle(QStringLiteral("No applications found"));
        m_empty->setDetail(
            QStringLiteral("Try adjusting your search or filters."));
    }
}

void ApplicationsPage::refreshFooter()
{
    if (!m_footerCount || !m_legend)
        return;
    const int visible = m_proxy->rowCount();
    const int total = int(m_rows.size());
    if (visible == total) {
        m_footerCount->setText(
            QStringLiteral("%1 %2")
                .arg(total)
                .arg(total == 1 ? QStringLiteral("application")
                                : QStringLiteral("applications")));
    } else {
        m_footerCount->setText(
            QStringLiteral("Showing %1 of %2 applications").arg(visible).arg(total));
    }
    m_legend->setText(legendHtml());
}

void ApplicationsPage::refreshThemeIcons()
{
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
    const QColor primary = Theme::qcolor(palette.textSecondary);
    const QColor muted = Theme::qcolor(palette.textMuted);
    if (m_filterButton)
        m_filterButton->setIcon(glyphIcon(Glyph::Filter, primary));
    if (m_sortButton)
        m_sortButton->setIcon(glyphIcon(Glyph::Sort, primary));
    if (m_moreButton)
        m_moreButton->setIcon(glyphIcon(Glyph::More, primary));
    if (m_searchAction)
        m_searchAction->setIcon(glyphIcon(Glyph::Search, muted));
    if (m_detailsOpen)
        applyDetailsRule(m_details.rule);
}

void ApplicationsPage::showFilterMenu()
{
    QMenu menu(this);
    QActionGroup group(&menu);
    group.setExclusive(true);

    const QList<Applications::Filter> filters = {
        Applications::Filter::All,
        Applications::Filter::Active,
        Applications::Filter::Idle,
        Applications::Filter::AllowRule,
        Applications::Filter::AskRule,
        Applications::Filter::BlockRule
    };
    for (Applications::Filter filter : filters) {
        QAction *action = menu.addAction(Applications::filterLabel(filter));
        action->setCheckable(true);
        action->setChecked(filter == m_filter);
        action->setData(int(filter));
        group.addAction(action);
    }
    connect(&group, &QActionGroup::triggered, this, [this](QAction *action) {
        applyFilter(static_cast<Applications::Filter>(action->data().toInt()));
    });

    menu.exec(m_filterButton->mapToGlobal(
        QPoint(0, m_filterButton->height() + Theme::Dim::SpaceXs)));
}

void ApplicationsPage::showSortMenu()
{
    QHeaderView *header = m_table->horizontalHeader();
    const int currentColumn = header->sortIndicatorSection();
    const Qt::SortOrder currentOrder = header->sortIndicatorOrder();

    QMenu menu(this);
    QActionGroup columnGroup(&menu);
    columnGroup.setExclusive(true);

    const QList<QPair<QString, int>> columns = {
        { QStringLiteral("Application"), ApplicationsPageTableModel::Application },
        { QStringLiteral("Total consumed"), ApplicationsPageTableModel::Total },
        { QStringLiteral("Rule"), ApplicationsPageTableModel::Rule },
        { QStringLiteral("Activity"), ApplicationsPageTableModel::Activity }
    };
    for (const auto &column : columns) {
        QAction *action = menu.addAction(column.first);
        action->setCheckable(true);
        action->setChecked(column.second == currentColumn);
        action->setData(column.second);
        columnGroup.addAction(action);
    }
    connect(&columnGroup, &QActionGroup::triggered, this, [this](QAction *action) {
        m_table->sortByColumn(action->data().toInt(),
                              m_table->horizontalHeader()->sortIndicatorOrder());
    });

    menu.addSeparator();
    QActionGroup orderGroup(&menu);
    orderGroup.setExclusive(true);
    QAction *ascending = menu.addAction(QStringLiteral("Ascending"));
    ascending->setCheckable(true);
    ascending->setChecked(currentOrder == Qt::AscendingOrder);
    orderGroup.addAction(ascending);
    QAction *descending = menu.addAction(QStringLiteral("Descending"));
    descending->setCheckable(true);
    descending->setChecked(currentOrder == Qt::DescendingOrder);
    orderGroup.addAction(descending);
    connect(&orderGroup, &QActionGroup::triggered, this, [this](QAction *action) {
        m_table->sortByColumn(m_table->horizontalHeader()->sortIndicatorSection(),
                              action->text() == QLatin1String("Descending")
                                  ? Qt::DescendingOrder : Qt::AscendingOrder);
    });

    menu.exec(m_sortButton->mapToGlobal(
        QPoint(0, m_sortButton->height() + Theme::Dim::SpaceXs)));
}

void ApplicationsPage::showMoreMenu()
{
    QMenu menu(this);
    QAction *policies = menu.addAction(QStringLiteral("Manage policies"));
    menu.addSeparator();
    QAction *clear = menu.addAction(QStringLiteral("Clear search and filters"));

    QAction *chosen = menu.exec(m_moreButton->mapToGlobal(
        QPoint(0, m_moreButton->height() + Theme::Dim::SpaceXs)));
    if (!chosen)
        return;
    if (chosen == policies) {
        emit policiesRequested();
    } else if (chosen == clear) {
        m_search->clear();
        applyFilter(Applications::Filter::All);
    }
}

void ApplicationsPage::showRuleMenu(const QModelIndex &index)
{
    Applications::Row row;
    if (!rowForIndex(index, &row))
        return;

    m_table->selectRow(index.row());
    // While the drawer is up it follows the selected row, including when the
    // selection moved because the rule menu was opened from another row.
    if (m_detailsOpen && m_details.pid != row.pid)
        openDetailsAt(index);
    const QRect cell = m_table->visualRect(index);
    showRuleMenuFor(row.pid, row.path, row.name, ruleToken(row),
                    m_table->viewport()->mapToGlobal(cell.bottomLeft() + QPoint(0, 2)));
}

void ApplicationsPage::showRuleMenuFor(quint32 pid, const QString &path,
                                       const QString &name, const QString &rule,
                                       const QPoint &globalPos)
{
    QMenu menu(this);
    QActionGroup group(&menu);
    group.setExclusive(true);

    const QString current = rule.trimmed().toLower();
    const QList<QPair<QString, QString>> rules = {
        { QStringLiteral("allow"), QStringLiteral("Allow") },
        { QStringLiteral("ask"), QStringLiteral("Ask") },
        { QStringLiteral("block"), QStringLiteral("Block") }
    };
    for (const auto &entry : rules) {
        QAction *action = menu.addAction(dotIcon(ruleColor(entry.first)), entry.second);
        action->setCheckable(true);
        action->setChecked(current == entry.first);
        action->setData(entry.first);
        group.addAction(action);
    }

    QAction *chosen = menu.exec(globalPos);
    if (!chosen)
        return;
    const QString chosenRule = chosen->data().toString();
    if (m_detailsOpen && m_details.pid == pid)
        applyDetailsRule(chosenRule);
    emit ruleChangeRequested(pid, path, name, chosenRule);
}

bool ApplicationsPage::rowForIndex(const QModelIndex &index, Applications::Row *row) const
{
    if (!row || !index.isValid())
        return false;

    const QModelIndex source = m_proxy->mapToSource(index);
    if (!source.isValid() || source.row() < 0 || source.row() >= m_model->rowCount())
        return false;

    *row = m_model->rowAt(source.row());
    return true;
}

void ApplicationsPage::showContextMenu(const QPoint &pos)
{
    const QModelIndex index = m_table->indexAt(pos);
    Applications::Row row;
    if (!rowForIndex(index, &row))
        return;

    m_table->selectRow(index.row());

    QMenu menu(this);
    QAction *details = menu.addAction(QStringLiteral("Details"));
    QAction *traffic = menu.addAction(QStringLiteral("Manage traffic"));
    QAction *policy = menu.addAction(QStringLiteral("Create policy"));
    menu.addSeparator();
    QAction *activity = menu.addAction(QStringLiteral("Inspect activity"));

    QAction *chosen = menu.exec(m_table->viewport()->mapToGlobal(pos));
    if (!chosen)
        return;

    if (chosen == details)
        emit detailsRequested(row.pid, row.path, row.name);
    else if (chosen == traffic)
        emit trafficRequested(row.pid, row.path, row.name);
    else if (chosen == policy)
        emit policyRequested(row.pid, row.path, row.name);
    else if (chosen == activity)
        emit activityRequested(row.pid, row.path, row.name);
}
