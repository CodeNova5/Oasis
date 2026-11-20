/**
 * @file    policiespage.cpp
 * @author  Oasis
 */
#include "policiespage.h"

#include "ui/components/emptystatewidget.h"
#include "ui/components/metriccard.h"
#include "ui/components/statusbadge.h"
#include "ui/theme/dimensions.h"
#include "ui/theme/typography.h"

#include <QButtonGroup>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QString>
#include <QStringList>
#include <QTableWidget>
#include <QToolButton>
#include <QVBoxLayout>

namespace Policies {

QString statusLabel(Status status)
{
    switch (status) {
    case Status::Active:      return QStringLiteral("Active");
    case Status::Scheduled:   return QStringLiteral("Scheduled");
    case Status::Disabled:    return QStringLiteral("Disabled");
    case Status::StoredOnly:  return QStringLiteral("Stored only");
    case Status::Expired:     return QStringLiteral("Expired");
    case Status::Unsupported: return QStringLiteral("Unsupported");
    }
    return QStringLiteral("Unknown");
}

QString filterLabel(Filter filter)
{
    switch (filter) {
    case Filter::All:         return QStringLiteral("All");
    case Filter::Active:      return QStringLiteral("Active");
    case Filter::Scheduled:   return QStringLiteral("Scheduled");
    case Filter::Disabled:    return QStringLiteral("Disabled");
    case Filter::StoredOnly:  return QStringLiteral("Stored only");
    case Filter::Expired:     return QStringLiteral("Expired");
    case Filter::Unsupported: return QStringLiteral("Unsupported");
    }
    return QString();
}

Filter filterFor(Status status)
{
    switch (status) {
    case Status::Active:      return Filter::Active;
    case Status::Scheduled:   return Filter::Scheduled;
    case Status::Disabled:    return Filter::Disabled;
    case Status::StoredOnly:  return Filter::StoredOnly;
    case Status::Expired:     return Filter::Expired;
    case Status::Unsupported: return Filter::Unsupported;
    }
    return Filter::All;
}

} // namespace Policies

namespace {

constexpr int kActionColumn = 4;

StatusBadge::Status badgeFor(Policies::Status status)
{
    switch (status) {
    case Policies::Status::Active:      return StatusBadge::Status::Active;
    case Policies::Status::Scheduled:   return StatusBadge::Status::Pending;
    case Policies::Status::Disabled:    return StatusBadge::Status::Inactive;
    case Policies::Status::StoredOnly:  return StatusBadge::Status::StoredOnly;
    case Policies::Status::Expired:     return StatusBadge::Status::Expired;
    case Policies::Status::Unsupported: return StatusBadge::Status::Degraded;
    }
    return StatusBadge::Status::Unknown;
}

QVBoxLayout *cellLayout(QWidget *cell)
{
    auto *layout = new QVBoxLayout(cell);
    layout->setContentsMargins(Theme::Dim::SpaceMd, Theme::Dim::SpaceSm,
                               Theme::Dim::SpaceMd, Theme::Dim::SpaceSm);
    layout->setSpacing(2);
    return layout;
}

QLabel *cellLabel(const QString &text, QWidget *parent)
{
    auto *label = new QLabel(text, parent);
    label->setWordWrap(false);
    return label;
}

} // namespace

PoliciesPage::PoliciesPage(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("policiesPage"));

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::Dim::PagePaddingH, 20,
                             Theme::Dim::PagePaddingH, 0);
    root->setSpacing(Theme::Dim::SpaceLg);

    // The mock puts Verify and Create in the page header; the shell keeps the
    // header for the title, so this page hosts them in its own body toolbar.
    buildToolbar(root);
    buildMetrics(root);
    buildFilterBar(root);
    buildTable(root);
    buildEmptyStates(root);

    refreshContent();
}

void PoliciesPage::buildToolbar(QVBoxLayout *root)
{
    auto *toolbar = new QHBoxLayout;
    toolbar->setContentsMargins(0, 0, 0, 0);
    toolbar->setSpacing(Theme::Dim::SpaceSm);

    toolbar->addStretch(1);

    m_verifyButton = new QPushButton(QStringLiteral("Verify rules"), this);
    m_verifyButton->setFixedHeight(Theme::Dim::ButtonHeight);
    m_verifyButton->setCursor(Qt::PointingHandCursor);
    m_verifyButton->setEnabled(false);
    m_verifyButton->setToolTip(QStringLiteral("Not available yet."));
    toolbar->addWidget(m_verifyButton);

    m_createButton = new QPushButton(QStringLiteral("Create policy"), this);
    m_createButton->setProperty("variant", QStringLiteral("primary"));
    m_createButton->setFixedHeight(Theme::Dim::ButtonHeight);
    m_createButton->setCursor(Qt::PointingHandCursor);
    m_createButton->setEnabled(false);
    m_createButton->setToolTip(QStringLiteral("Not available yet."));
    toolbar->addWidget(m_createButton);

    connect(m_verifyButton, &QPushButton::clicked,
            this, &PoliciesPage::verifyRequested);
    connect(m_createButton, &QPushButton::clicked,
            this, &PoliciesPage::createRequested);

    root->addLayout(toolbar);
}

void PoliciesPage::buildMetrics(QVBoxLayout *root)
{
    auto *grid = new QGridLayout;
    grid->setContentsMargins(0, 0, 0, 0);
    grid->setHorizontalSpacing(Theme::Dim::SpaceMd);
    grid->setVerticalSpacing(Theme::Dim::SpaceMd);

    m_activeCard = new MetricCard(QStringLiteral("Active"), this);
    m_activeCard->setCaption(QStringLiteral("enforced right now"));
    m_activeCard->setClickable(true);

    m_scheduledCard = new MetricCard(QStringLiteral("Scheduled / Paused"), this);
    m_scheduledCard->setCaption(QStringLiteral("window / disabled / expired"));
    m_scheduledCard->setClickable(true);

    m_storedOnlyCard = new MetricCard(QStringLiteral("Stored only"), this);
    m_storedOnlyCard->setCaption(QStringLiteral("saved without a live rule"));
    m_storedOnlyCard->setClickable(true);

    MetricCard *cards[] = {m_activeCard, m_scheduledCard, m_storedOnlyCard};
    for (int column = 0; column < 3; ++column) {
        grid->addWidget(cards[column], 0, column);
        grid->setColumnStretch(column, 1);
    }

    connect(m_activeCard, &MetricCard::clicked, this, [this]() {
        setFilter(Policies::Filter::Active);
    });
    connect(m_scheduledCard, &MetricCard::clicked, this, [this]() {
        setFilter(Policies::Filter::Scheduled);
    });
    connect(m_storedOnlyCard, &MetricCard::clicked, this, [this]() {
        setFilter(Policies::Filter::StoredOnly);
    });

    root->addLayout(grid);
}

void PoliciesPage::buildFilterBar(QVBoxLayout *root)
{
    m_filterBar = new QWidget(this);
    auto *bar = new QHBoxLayout(m_filterBar);
    bar->setContentsMargins(0, 0, 0, 0);
    bar->setSpacing(Theme::Dim::SpaceSm);

    m_pillGroup = new QButtonGroup(this);
    m_pillGroup->setExclusive(true);

    // One pill per filter, in the mock's order. The Unsupported pill is hidden
    // until a stored policy actually lands in that state.
    const Policies::Filter filters[] = {
        Policies::Filter::All,        Policies::Filter::Active,
        Policies::Filter::Scheduled,  Policies::Filter::Disabled,
        Policies::Filter::StoredOnly, Policies::Filter::Expired,
        Policies::Filter::Unsupported
    };

    for (const Policies::Filter filter : filters) {
        auto *pill = new QToolButton(m_filterBar);
        pill->setProperty("uiRole", QStringLiteral("filterPill"));
        pill->setCheckable(true);
        pill->setToolButtonStyle(Qt::ToolButtonTextOnly);
        pill->setCursor(Qt::PointingHandCursor);
        pill->setFixedHeight(Theme::Dim::FilterPillHeight);
        pill->setText(Policies::filterLabel(filter));
        pill->setChecked(filter == Policies::Filter::All);
        m_pillGroup->addButton(pill, int(filter));
        m_pills << pill;
        bar->addWidget(pill);
    }

    // The pill list is indexed by filter, so it is filled in enum order.
    connect(m_pillGroup, &QButtonGroup::idClicked, this, [this](int id) {
        setFilter(static_cast<Policies::Filter>(id));
    });

    bar->addStretch(1);

    m_search = new QLineEdit(m_filterBar);
    m_search->setPlaceholderText(QStringLiteral("Search app, service, note…"));
    m_search->setClearButtonEnabled(true);
    m_search->setFixedHeight(Theme::Dim::ButtonHeight);
    m_search->setFixedWidth(260);
    connect(m_search, &QLineEdit::textChanged, this, [this](const QString &text) {
        m_query = text.trimmed();
        applyFilters();
    });
    bar->addWidget(m_search);

    root->addWidget(m_filterBar);
}

void PoliciesPage::buildTable(QVBoxLayout *root)
{
    m_table = new QTableWidget(0, 5, this);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("Application"),
        QStringLiteral("Action & Limit"),
        QStringLiteral("Window & Expires"),
        QStringLiteral("Status / Enforcement"),
        QStringLiteral("Actions")
    });
    m_table->verticalHeader()->setVisible(false);
    m_table->setShowGrid(false);
    m_table->setWordWrap(false);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionMode(QAbstractItemView::NoSelection);
    m_table->setFocusPolicy(Qt::NoFocus);
    m_table->verticalHeader()->setDefaultSectionSize(62);
    m_table->setMinimumHeight(240);

    QHeaderView *header = m_table->horizontalHeader();
    header->setSectionResizeMode(0, QHeaderView::Stretch);
    header->setSectionResizeMode(1, QHeaderView::Stretch);
    header->setSectionResizeMode(2, QHeaderView::Stretch);
    header->setSectionResizeMode(3, QHeaderView::Stretch);
    header->setSectionResizeMode(kActionColumn, QHeaderView::Fixed);
    header->resizeSection(kActionColumn, 64);
    header->setStretchLastSection(false);

    root->addWidget(m_table, 1);
}

void PoliciesPage::buildEmptyStates(QVBoxLayout *root)
{
    m_emptyHost = new QWidget(this);
    auto *emptyLayout = new QVBoxLayout(m_emptyHost);
    emptyLayout->setContentsMargins(0, 0, 0, 0);
    emptyLayout->setSpacing(0);

    m_empty = new EmptyStateWidget(m_emptyHost);
    m_empty->setTitle(QStringLiteral("No policies configured yet"));
    m_empty->setDetail(QStringLiteral(
        "Policies cap an application's bandwidth, block its traffic, or exempt "
        "it from limits. Stored policies appear here with their live state."));
    // The action stays hidden while the create flow is not wired to this page.
    emptyLayout->addStretch(1);
    emptyLayout->addWidget(m_empty, 0, Qt::AlignHCenter);
    emptyLayout->addStretch(1);

    m_noMatchHost = new QWidget(this);
    auto *noMatchLayout = new QVBoxLayout(m_noMatchHost);
    noMatchLayout->setContentsMargins(0, 0, 0, 0);
    noMatchLayout->setSpacing(0);

    m_noMatch = new EmptyStateWidget(m_noMatchHost);
    m_noMatch->setTitle(QStringLiteral("No matching policies"));
    m_noMatch->setDetail(QStringLiteral(
        "Try clearing the search field or switching back to All policies."));
    noMatchLayout->addStretch(1);
    noMatchLayout->addWidget(m_noMatch, 0, Qt::AlignHCenter);
    noMatchLayout->addStretch(1);

    root->addWidget(m_emptyHost, 1);
    root->addWidget(m_noMatchHost, 1);
}

void PoliciesPage::setRows(const QList<Policies::Row> &rows)
{
    m_rows = rows;
    refreshCounts();
    refreshPills();
    applyFilters();
}

void PoliciesPage::setFilter(Policies::Filter filter)
{
    m_filter = filter;
    if (int(filter) >= 0 && int(filter) < m_pills.size()) {
        QToolButton *pill = m_pills.at(int(filter));
        if (pill && !pill->isChecked())
            pill->setChecked(true);
    }
    applyFilters();
}

void PoliciesPage::applyFilters()
{
    QList<Policies::Row> filtered;
    filtered.reserve(m_rows.size());
    for (const Policies::Row &row : m_rows) {
        if (m_filter != Policies::Filter::All
            && Policies::filterFor(row.status) != m_filter) {
            continue;
        }
        if (!m_query.isEmpty()) {
            const QString haystack = QStringList{
                row.name, row.subtitle, row.effect, row.window, row.expires,
                Policies::statusLabel(row.status), row.statusReason, row.tooltip
            }.join(QLatin1Char(' '));
            if (!haystack.contains(m_query, Qt::CaseInsensitive))
                continue;
        }
        filtered << row;
    }

    populateTable(filtered);
    refreshContent();
}

void PoliciesPage::refreshPills()
{
    for (int i = 0; i < m_pills.size(); ++i) {
        QToolButton *pill = m_pills.at(i);
        if (!pill)
            continue;
        const Policies::Filter filter = static_cast<Policies::Filter>(i);
        const int count = countFor(filter);
        pill->setText(QStringLiteral("%1  %2")
                          .arg(Policies::filterLabel(filter))
                          .arg(count));
        if (filter == Policies::Filter::Unsupported)
            pill->setVisible(count > 0);
    }
}

void PoliciesPage::refreshCounts()
{
    if (!m_activeCard)
        return;

    m_activeCard->setValue(QString::number(countFor(Policies::Filter::Active)));
    m_storedOnlyCard->setValue(QString::number(countFor(Policies::Filter::StoredOnly)));

    // Everything that is not active or stored-only is paused for a reason, and
    // the mock groups those reasons in one card.
    int paused = 0;
    for (const Policies::Row &row : m_rows) {
        if (row.status != Policies::Status::Active
            && row.status != Policies::Status::StoredOnly) {
            ++paused;
        }
    }
    m_scheduledCard->setValue(QString::number(paused));
}

int PoliciesPage::countFor(Policies::Filter filter) const
{
    if (filter == Policies::Filter::All)
        return int(m_rows.size());

    int count = 0;
    for (const Policies::Row &row : m_rows) {
        if (Policies::filterFor(row.status) == filter)
            ++count;
    }
    return count;
}

void PoliciesPage::refreshContent()
{
    if (!m_table || !m_emptyHost || !m_noMatchHost)
        return;

    const bool hasRows = !m_rows.isEmpty();
    const bool tableHasRows = m_table->rowCount() > 0;

    m_filterBar->setVisible(hasRows);
    m_table->setVisible(hasRows && tableHasRows);
    m_emptyHost->setVisible(!hasRows);
    m_noMatchHost->setVisible(hasRows && !tableHasRows);
}

void PoliciesPage::populateTable(const QList<Policies::Row> &rows)
{
    m_table->setUpdatesEnabled(false);
    m_table->setRowCount(0);
    m_table->setRowCount(rows.size());

    for (int rowIndex = 0; rowIndex < rows.size(); ++rowIndex) {
        const Policies::Row &row = rows.at(rowIndex);

        // The cells hold widgets, but a plain item keeps selection and hover
        // painting consistent across the row.
        for (int column = 0; column < m_table->columnCount(); ++column)
            m_table->setItem(rowIndex, column, new QTableWidgetItem);

        m_table->setCellWidget(rowIndex, 0, applicationCell(row));
        m_table->setCellWidget(rowIndex, 1,
                               textCell(row.effect, QString(), row.tooltip));
        m_table->setCellWidget(rowIndex, 2,
                               textCell(row.window, row.expires, row.tooltip));
        m_table->setCellWidget(rowIndex, 3, statusCell(row));

        auto *actions = new QWidget;
        auto *actionsLayout = cellLayout(actions);
        auto *dash = cellLabel(QStringLiteral("—"), actions);
        dash->setProperty("uiRole", QStringLiteral("muted"));
        dash->setAlignment(Qt::AlignCenter);
        actions->setToolTip(QStringLiteral(
            "Editing and toggling are being rebuilt on this screen."));
        actionsLayout->addWidget(dash, 0, Qt::AlignCenter);
        m_table->setCellWidget(rowIndex, kActionColumn, actions);
    }

    m_table->setUpdatesEnabled(true);
}

QWidget *PoliciesPage::applicationCell(const Policies::Row &row)
{
    auto *cell = new QWidget;
    QVBoxLayout *layout = cellLayout(cell);

    auto *name = cellLabel(row.name, cell);
    QFont nameFont = Theme::Type::baseFont();
    nameFont.setWeight(QFont::DemiBold);
    name->setFont(nameFont);

    auto *subtitle = cellLabel(row.subtitle, cell);
    subtitle->setProperty("uiRole", QStringLiteral("muted"));

    layout->addWidget(name);
    layout->addWidget(subtitle);
    cell->setToolTip(row.tooltip);
    return cell;
}

QWidget *PoliciesPage::statusCell(const Policies::Row &row)
{
    auto *cell = new QWidget;
    QVBoxLayout *layout = cellLayout(cell);

    auto *badge = new StatusBadge(cell);
    badge->setStatus(badgeFor(row.status), Policies::statusLabel(row.status));
    // The reason is more specific than the badge's generic tooltip.
    badge->setToolTip(row.statusReason);

    auto *reason = cellLabel(row.statusReason, cell);
    reason->setProperty("uiRole", QStringLiteral("muted"));
    reason->setToolTip(row.statusReason);

    layout->addWidget(badge, 0, Qt::AlignLeft);
    layout->addWidget(reason);
    return cell;
}

QWidget *PoliciesPage::textCell(const QString &primary, const QString &secondary,
                                const QString &tooltip)
{
    auto *cell = new QWidget;
    QVBoxLayout *layout = cellLayout(cell);

    auto *primaryLabel = cellLabel(primary, cell);
    layout->addWidget(primaryLabel);

    if (!secondary.isEmpty()) {
        auto *secondaryLabel = cellLabel(secondary, cell);
        secondaryLabel->setProperty("uiRole", QStringLiteral("muted"));
        layout->addWidget(secondaryLabel);
    }

    if (!tooltip.isEmpty())
        cell->setToolTip(tooltip);
    return cell;
}
