/**
 * @file   bandwidthlimitsdialog.cpp
 * @brief  Active bandwidth limits and their owning policies.
 * @author Codebuff
 */

#include "bandwidthlimitsdialog.h"

#include "network/policy.h"
#include "throttlepolicymanager.h"

#include <QAbstractItemView>
#include <QDialogButtonBox>
#include <QDir>
#include <QHash>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {

enum Column {
    PathColumn,
    LimitColumn,
    OwnerColumn,
    ColumnCount
};

QString limitText(const QString &path, const ThrottlePolicyManager *manager)
{
    const QString rate = QStringLiteral("50 KiB/s");
    const bool download = manager->downloadLimits().contains(path);
    return download ? QStringLiteral("%1 (upload + download)").arg(rate)
                    : QStringLiteral("%1 (upload; download shaping unavailable)").arg(rate);
}

QString ownerText(const QString &path, const ThrottlePolicyManager *manager,
                  const QHash<QString, NetworkPolicy> &policies)
{
    const QString policyId = manager->policyAttribution().value(path);
    if (policyId.isEmpty())
        return QStringLiteral("Manual (applied outside a policy)");

    const auto policy = policies.constFind(policyId);
    if (policy == policies.constEnd())
        return QStringLiteral("Policy %1 (not found)").arg(policyId);

    const QString label = policy->description.trimmed().isEmpty()
        ? policy->targetId.trimmed()
        : policy->description.trimmed();
    return label.isEmpty() ? policyId : QStringLiteral("%1 (%2)").arg(label, policyId);
}

} // namespace

BandwidthLimitsDialog::BandwidthLimitsDialog(ThrottlePolicyManager *manager, QWidget *parent)
    : QDialog(parent)
    , m_manager(manager)
{
    setWindowTitle(QStringLiteral("Active bandwidth limits"));
    resize(780, 380);

    auto *layout = new QVBoxLayout(this);

    auto *intro = new QLabel(
        QStringLiteral("Every limit applies to the whole executable path. The owner is the saved "
                       "policy that requested the limit; a limit applied from the process menu has "
                       "no policy. Remove a limit from the process menu."),
        this);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    m_summary = new QLabel(this);
    layout->addWidget(m_summary);

    m_table = new QTableWidget(0, ColumnCount, this);
    m_table->setHorizontalHeaderLabels(
        {QStringLiteral("Executable"), QStringLiteral("Limit"), QStringLiteral("Owner")});
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(PathColumn, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(LimitColumn, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(OwnerColumn, QHeaderView::Stretch);
    connect(m_table, &QTableWidget::itemSelectionChanged, this,
            &BandwidthLimitsDialog::updateButtons);
    layout->addWidget(m_table, 1);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    QPushButton *refreshButton = buttons->addButton(QStringLiteral("Refresh"),
                                                   QDialogButtonBox::ActionRole);
    connect(refreshButton, &QPushButton::clicked, this, &BandwidthLimitsDialog::refresh);
    m_removeButton = buttons->addButton(QStringLiteral("Remove limit"),
                                        QDialogButtonBox::ActionRole);
    connect(m_removeButton, &QPushButton::clicked, this,
            &BandwidthLimitsDialog::removeSelected);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);

    if (m_manager) {
        // Results arrive asynchronously, so the list stays current while open.
        connect(m_manager, &ThrottlePolicyManager::throttleApplied, this,
                [this](const QString &, const ThrottleResult &) { refresh(); });
        connect(m_manager, &ThrottlePolicyManager::throttleRemoved, this,
                [this](const QString &, const ThrottleResult &) { refresh(); });
        connect(m_manager, &ThrottlePolicyManager::throttlesRestored, this,
                [this](const ThrottleResult &) { refresh(); });
    }

    refresh();
}

void BandwidthLimitsDialog::refresh()
{
    m_table->setRowCount(0);
    if (!m_manager) {
        m_summary->setText(QStringLiteral("The throttle manager is not available."));
        return;
    }

    QStringList paths = m_manager->activePaths();
    paths.sort(Qt::CaseInsensitive);

    QHash<QString, NetworkPolicy> policies;
    for (const NetworkPolicy &policy : PolicyStore::loadPolicies())
        policies.insert(policy.id, policy);

    int manual = 0;
    for (const QString &path : paths) {
        const int row = m_table->rowCount();
        m_table->insertRow(row);

        auto *pathItem = new QTableWidgetItem(QDir::toNativeSeparators(path));
        pathItem->setData(Qt::UserRole, path);
        pathItem->setToolTip(path);
        m_table->setItem(row, PathColumn, pathItem);

        m_table->setItem(row, LimitColumn, new QTableWidgetItem(limitText(path, m_manager)));

        auto *ownerItem = new QTableWidgetItem(ownerText(path, m_manager, policies));
        ownerItem->setToolTip(ownerItem->text());
        m_table->setItem(row, OwnerColumn, ownerItem);

        if (m_manager->policyAttribution().value(path).isEmpty()) ++manual;
    }

    if (paths.isEmpty()) {
        m_summary->setText(QStringLiteral("No bandwidth limit is enforced."));
    } else {
        const int owned = paths.size() - manual;
        m_summary->setText(QStringLiteral("%1 limit(s) enforced: %2 owned by a policy, %3 manual.")
                               .arg(static_cast<int>(paths.size()))
                               .arg(owned)
                               .arg(manual));
    }
    updateButtons();
}

int BandwidthLimitsDialog::selectedRow() const
{
    if (!m_table->selectionModel() || !m_table->selectionModel()->hasSelection()) return -1;
    return m_table->currentRow();
}

void BandwidthLimitsDialog::updateButtons()
{
    if (m_removeButton) m_removeButton->setEnabled(m_manager && selectedRow() >= 0);
}

void BandwidthLimitsDialog::removeSelected()
{
    const int row = selectedRow();
    if (!m_manager || row < 0) return;

    const QTableWidgetItem *pathItem = m_table->item(row, PathColumn);
    const QTableWidgetItem *ownerItem = m_table->item(row, OwnerColumn);
    if (!pathItem) return;

    const QString path = pathItem->data(Qt::UserRole).toString();
    const QString owner = ownerItem ? ownerItem->text()
                                    : QStringLiteral("Manual (applied outside a policy)");
    const QString prompt = QStringLiteral(
        "Remove the 50 KiB/s limit from:\n%1\n\nOwner: %2\n\n"
        "This is path-wide and affects every running and future instance of this "
        "executable. The policy itself is not changed.").arg(QDir::toNativeSeparators(path), owner);
    if (QMessageBox::question(this, QStringLiteral("Remove bandwidth limit"), prompt,
                              QMessageBox::Yes | QMessageBox::No,
                              QMessageBox::No) != QMessageBox::Yes) {
        return;
    }

    // The worker answers asynchronously; refresh() runs from throttleRemoved().
    m_summary->setText(QStringLiteral("Removing the limit for %1...")
                           .arg(QDir::toNativeSeparators(path)));
    m_manager->remove(path);
}
