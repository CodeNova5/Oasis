/**
 * @file   dashboardpanel.cpp
 * @brief  Rendering for the top-consumer dashboard (NG-054).
 * @author Codebuff
 */

#include "dashboardpanel.h"

#include "policyschedule.h"

#include <QAbstractItemView>
#include <QItemSelectionModel>
#include <QFont>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {

enum Column {
    ConsumerColumn,
    UsageColumn,
    ActivityColumn,
    ControlColumn,
    ColumnCount
};

} // namespace

DashboardPanel::DashboardPanel(QWidget *parent)
    : QGroupBox(QStringLiteral("At a glance"), parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setSpacing(4);

    m_headline = new QLabel(this);
    QFont headlineFont = m_headline->font();
    headlineFont.setBold(true);
    m_headline->setFont(headlineFont);
    m_headline->setWordWrap(true);
    layout->addWidget(m_headline);

    m_topDetail = new QLabel(this);
    m_topDetail->setWordWrap(true);
    m_topDetail->setStyleSheet(QStringLiteral("color: palette(mid);"));
    layout->addWidget(m_topDetail);

    m_table = new QTableWidget(this);
    m_table->setColumnCount(ColumnCount);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("Consumer"), QStringLiteral("Usage"),
        QStringLiteral("Activity"), QStringLiteral("Control")
    });
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(22);
    m_table->horizontalHeader()->setSectionResizeMode(ConsumerColumn, QHeaderView::Stretch);
    for (int column = UsageColumn; column < ColumnCount; ++column)
        m_table->horizontalHeader()->setSectionResizeMode(column, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setHighlightSections(false);
    m_table->setShowGrid(false);
    m_table->setFocusPolicy(Qt::NoFocus);
    layout->addWidget(m_table);

    m_controls = new QLabel(this);
    m_controls->setWordWrap(true);
    m_unresolved = new QLabel(this);
    m_unresolved->setWordWrap(true);
    m_recommendations = new QLabel(this);
    m_recommendations->setWordWrap(true);
    layout->addWidget(m_controls);
    layout->addWidget(m_unresolved);
    layout->addWidget(m_recommendations);

    auto *buttons = new QHBoxLayout;
    m_detailsButton = new QPushButton(QStringLiteral("Details..."), this);
    m_detailsButton->setToolTip(
        QStringLiteral("Open the application detail view for this consumer"));
    m_recommendButton = new QPushButton(QStringLiteral("Suggested action..."), this);
    m_recommendButton->setToolTip(
        QStringLiteral("Review the recommendation for this consumer"));
    auto *policiesButton = new QPushButton(QStringLiteral("Policies..."), this);
    policiesButton->setToolTip(QStringLiteral("Show every stored policy and its state"));
    buttons->addWidget(m_detailsButton);
    buttons->addWidget(m_recommendButton);
    buttons->addWidget(policiesButton);
    buttons->addStretch(1);
    layout->addLayout(buttons);

    connect(m_detailsButton, &QPushButton::clicked, this, [this]() {
        const int row = effectiveRow();
        if (row < 0 || row >= m_summary.rows.size()) return;
        const TopConsumers::Row &entry = m_summary.rows.at(row);
        emit detailsRequested(entry.pid, entry.path, entry.name);
    });
    connect(m_recommendButton, &QPushButton::clicked, this, [this]() {
        const int row = effectiveRow();
        if (row < 0 || row >= m_summary.rows.size()) return;
        const TopConsumers::Row &entry = m_summary.rows.at(row);
        emit recommendationRequested(entry.pid, entry.path, entry.name);
    });
    connect(policiesButton, &QPushButton::clicked, this, &DashboardPanel::policiesRequested);
    connect(m_table, &QTableWidget::cellClicked, this, [this](int row, int) {
        const int target = effectiveRow();
        if (target < 0 || target >= m_summary.rows.size()) return;
        const TopConsumers::Row &entry = m_summary.rows.at(target);
        emit detailsRequested(entry.pid, entry.path, entry.name);
    });
    connect(m_table, &QTableWidget::itemSelectionChanged, this,
            &DashboardPanel::updateButtons);

    setSummary(TopConsumers::Summary());
}

void DashboardPanel::setSummary(const TopConsumers::Summary &summary)
{
    m_summary = summary;

    m_headline->setText(QStringLiteral("Top consumers: ") + summary.headline);
    m_topDetail->setText(summary.topSummary);

    m_table->setRowCount(summary.rows.size());
    for (int row = 0; row < summary.rows.size(); ++row) {
        const TopConsumers::Row &entry = summary.rows.at(row);
        QString name = entry.name;
        if (!entry.identity.trimmed().isEmpty() && entry.identity != entry.name)
            name += QStringLiteral(" (%1)").arg(entry.identity);

        const QString values[ColumnCount] = {
            name, entry.usage, entry.activity, entry.control
        };
        for (int column = 0; column < ColumnCount; ++column) {
            auto *item = new QTableWidgetItem(values[column]);
            if (column == ConsumerColumn)
                item->setToolTip(entry.path.isEmpty()
                    ? QStringLiteral("No executable path is known for this process")
                    : entry.path);
            if (column == ActivityColumn && entry.unresolved)
                item->setToolTip(QStringLiteral(
                    "This build cannot say what this traffic is: no executable "
                    "path or no activity match"));
            m_table->setItem(row, column, item);
        }
    }

    // Show the controls, not just how many: the point of the panel is that the
    // first view answers "what is controlling traffic right now".
    QString controls = QStringLiteral("Controls: ") + summary.controlSummary;
    for (const TopConsumers::Control &control : summary.controls) {
        controls += QStringLiteral("\n• %1 — %2, %3")
            .arg(control.summary, control.effect, control.enforcement);
        if (control.temporary && control.expiration.isValid()) {
            controls += QStringLiteral(" (%1)")
                .arg(policyExpirationSummary(control.expiration, QDateTime::currentDateTime()));
        }
    }
    m_controls->setText(controls);

    m_unresolved->setText(QStringLiteral("Unresolved: ") + summary.unresolvedSummary);
    m_unresolved->setStyleSheet(summary.unresolvedConsumers > 0
        ? QStringLiteral("color: palette(mid);")
        : QString());

    QString recommendations = QStringLiteral("Suggested: ") + summary.recommendationSummary;
    for (const TopConsumers::Recommendation &recommendation : summary.recommendations) {
        recommendations += QStringLiteral("\n• %1 — %2")
            .arg(recommendation.title, recommendation.name);
        if (!recommendation.reason.trimmed().isEmpty())
            recommendations += QStringLiteral(" (%1)").arg(recommendation.reason);
    }
    m_recommendations->setText(recommendations);
    m_recommendations->setToolTip(
        QStringLiteral("Suggestions are local, advisory, and always require approval"));

    m_table->resizeRowsToContents();
    updateButtons();
}

int DashboardPanel::effectiveRow() const
{
    const QModelIndexList selected = m_table->selectionModel()
        ? m_table->selectionModel()->selectedRows() : QModelIndexList();
    if (!selected.isEmpty()) return selected.first().row();
    return m_summary.rows.isEmpty() ? -1 : 0;
}

void DashboardPanel::updateButtons()
{
    const int row = effectiveRow();
    const bool hasRow = row >= 0 && row < m_summary.rows.size();
    m_detailsButton->setEnabled(hasRow);

    bool hasRecommendation = false;
    if (hasRow) {
        const TopConsumers::Row &entry = m_summary.rows.at(row);
        for (const TopConsumers::Recommendation &recommendation : m_summary.recommendations) {
            if (recommendation.pid == entry.pid) { hasRecommendation = true; break; }
        }
    }
    m_recommendButton->setEnabled(hasRecommendation);
}
