/**
 * @file   policylistdialog.cpp
 * @brief  Saved policies at a glance, with edit and delete.
 * @author Codebuff
 */

#include "policylistdialog.h"

#include "policyschedule.h"
#include "policyeditordialog.h"
#include "policyscope.h"

#include <QAbstractItemView>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {

enum Column {
    StateColumn,
    ScopeColumn,
    TargetColumn,
    ActionColumn,
    DirectionColumn,
    RateColumn,
    WindowColumn,
    ExpiresColumn,
    EnforcementColumn,
    SourceColumn,
    ColumnCount
};

QString actionName(NetworkPolicy::Action action)
{
    switch (action) {
    case NetworkPolicy::Action::Allow: return QStringLiteral("Allow");
    case NetworkPolicy::Action::Notify: return QStringLiteral("Notify");
    case NetworkPolicy::Action::Ask: return QStringLiteral("Ask");
    case NetworkPolicy::Action::Throttle: return QStringLiteral("Throttle");
    case NetworkPolicy::Action::Block: return QStringLiteral("Block");
    case NetworkPolicy::Action::Schedule: return QStringLiteral("Schedule");
    case NetworkPolicy::Action::NoAction: return QStringLiteral("No action");
    }
    return QStringLiteral("Unknown");
}

QString directionName(NetworkDirection direction)
{
    switch (direction) {
    case NetworkDirection::Download: return QStringLiteral("Download");
    case NetworkDirection::Upload: return QStringLiteral("Upload");
    case NetworkDirection::Both: return QStringLiteral("Both");
    }
    return QStringLiteral("Unknown");
}

QString scopeName(const QString &key)
{
    const QString scope = key.trimmed().toLower();
    if (scope == QLatin1String("pid")) return QStringLiteral("This process (PID)");
    if (scope == QLatin1String("path") || scope == QLatin1String("executable"))
        return QStringLiteral("Executable path");
    if (scope == QLatin1String("publisher")) return QStringLiteral("Publisher");
    if (scope == QLatin1String("service")) return QStringLiteral("Windows service");
    if (scope == QLatin1String("group")) return QStringLiteral("Application group");
    if (scope == QLatin1String("package")) return QStringLiteral("Package");
    if (scope.isEmpty()) return QStringLiteral("—");
    return key;
}

bool editorSupportsScope(const QString &key)
{
    const QString scope = key.trimmed().toLower();
    return scope == QLatin1String("pid") || scope == QLatin1String("path") ||
           scope == QLatin1String("executable") || scope == QLatin1String("publisher") ||
           scope == QLatin1String("service") || scope == QLatin1String("group");
}

QString rateName(const NetworkPolicy &policy)
{
    if (policy.action != NetworkPolicy::Action::Throttle || policy.rateBitsPerSecond == 0)
        return QStringLiteral("—");
    return QStringLiteral("%1 Mbit/s")
        .arg(static_cast<double>(policy.rateBitsPerSecond) / 1000000.0, 0, 'f', 2);
}

} // namespace

PolicyListDialog::PolicyListDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Policies"));
    resize(900, 420);

    auto *layout = new QVBoxLayout(this);

    m_summary = new QLabel(this);
    m_summary->setWordWrap(true);
    layout->addWidget(m_summary);

    m_table = new QTableWidget(this);
    m_table->setColumnCount(ColumnCount);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("State"), QStringLiteral("Scope"), QStringLiteral("Target"),
        QStringLiteral("Action"), QStringLiteral("Direction"), QStringLiteral("Rate"),
        QStringLiteral("Window"), QStringLiteral("Expires"),
        QStringLiteral("Enforcement"), QStringLiteral("Source")
    });
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(TargetColumn, QHeaderView::Stretch);
    for (int column = 0; column < ColumnCount; ++column) {
        if (column != TargetColumn)
            m_table->horizontalHeader()->setSectionResizeMode(column, QHeaderView::ResizeToContents);
    }
    layout->addWidget(m_table, 1);

    auto *buttons = new QHBoxLayout;
    m_verifyButton = new QPushButton(QStringLiteral("Verify..."), this);
    m_verifyButton->setToolTip(
        QStringLiteral("Compare the stored policies with the rules and limits Windows is enforcing"));
    m_deleteButton = new QPushButton(QStringLiteral("Delete"), this);
    m_editButton = new QPushButton(QStringLiteral("Edit..."), this);
    auto *closeBox = new QDialogButtonBox(QDialogButtonBox::Close, this);

    buttons->addWidget(m_verifyButton);
    buttons->addWidget(m_deleteButton);
    buttons->addWidget(m_editButton);
    buttons->addStretch(1);
    buttons->addWidget(closeBox);
    layout->addLayout(buttons);

    connect(closeBox, &QDialogButtonBox::rejected, this, &PolicyListDialog::reject);
    connect(m_verifyButton, &QPushButton::clicked, this, &PolicyListDialog::verifyRequested);
    connect(m_editButton, &QPushButton::clicked, this, &PolicyListDialog::editSelected);
    connect(m_deleteButton, &QPushButton::clicked, this, &PolicyListDialog::deleteSelected);
    connect(m_table, &QTableWidget::itemSelectionChanged,
            this, &PolicyListDialog::updateButtons);
    connect(m_table, &QTableWidget::cellDoubleClicked, this,
            [this](int, int) { editSelected(); });

    refresh();
}

void PolicyListDialog::refresh()
{
    m_policies = PolicyStore::loadPolicies();
    m_table->setRowCount(m_policies.size());

    const QDateTime now = QDateTime::currentDateTime();
    int storedOnly = 0;
    for (int row = 0; row < m_policies.size(); ++row) {
        const NetworkPolicy &policy = m_policies.at(row);
        const QString values[ColumnCount] = {
            policyActivationName(policyActivationAt(policy, now)),
            scopeName(policy.scope),
            policy.targetId,
            actionName(policy.action),
            directionName(policy.direction),
            rateName(policy),
            policy.schedule.isEmpty() ? QStringLiteral("—") : policy.schedule,
            policy.expiration.isValid()
                ? policyExpirationSummary(policy.expiration, now)
                : QStringLiteral("—"),
            policyEnforcementSummary(policy),
            policy.source.isEmpty() ? QStringLiteral("unknown") : policy.source
        };

        if (values[EnforcementColumn].startsWith(QStringLiteral("Stored only")))
            ++storedOnly;

        const QString activationReason = policy.enabled
            ? QString() : QStringLiteral("Disabled by the user");
        const QString expiryTip = policy.expiration.isValid()
            ? policyExpirationSummary(policy.expiration, now)
            : QStringLiteral("This policy has no expiration");

        for (int column = 0; column < ColumnCount; ++column) {
            auto *item = new QTableWidgetItem(values[column]);
            if (column == StateColumn && !activationReason.isEmpty())
                item->setToolTip(activationReason);
            if (column == ExpiresColumn)
                item->setToolTip(expiryTip);
            if (column == EnforcementColumn)
                item->setToolTip(values[EnforcementColumn].startsWith(
                                     QStringLiteral("Stored only"))
                    ? QStringLiteral("The policy is saved and listed, but this build "
                                     "does not resolve its scope, so nothing is "
                                     "blocked, allowed, or shaped by it.")
                    : QStringLiteral("This policy's effect is applied by this build"));
            m_table->setItem(row, column, item);
        }
    }

    m_table->resizeColumnsToContents();
    if (m_policies.isEmpty()) {
        m_summary->setText(
            QStringLiteral("No policies are stored. Create one from a process row."));
    } else {
        QString summary = QStringLiteral("%1 stored %2. Changes are saved immediately.")
            .arg(m_policies.size())
            .arg(m_policies.size() == 1 ? QStringLiteral("policy")
                                        : QStringLiteral("policies"));
        if (storedOnly > 0) {
            summary += QStringLiteral(" %1 %2 only listed, not enforced: this build "
                                      "cannot resolve PID, publisher, or service "
                                      "scopes yet.")
                           .arg(storedOnly)
                           .arg(storedOnly == 1 ? QStringLiteral("policy is")
                                                : QStringLiteral("policies are"));
        }
        m_summary->setText(summary);
    }

    updateButtons();
}

int PolicyListDialog::selectedRow() const
{
    const QModelIndexList selected = m_table->selectionModel()->selectedRows();
    if (selected.isEmpty()) return -1;
    return selected.first().row();
}

void PolicyListDialog::updateButtons()
{
    const bool hasSelection = selectedRow() >= 0;
    m_editButton->setEnabled(hasSelection);
    m_deleteButton->setEnabled(hasSelection);
}

void PolicyListDialog::editSelected()
{
    const int row = selectedRow();
    if (row < 0 || row >= m_policies.size()) return;

    const NetworkPolicy &selected = m_policies.at(row);
    if (!editorSupportsScope(selected.scope)) {
        QMessageBox::information(
            this, QStringLiteral("Policies"),
            QStringLiteral("A policy with the scope \"%1\" cannot be edited in this "
                           "build. Delete it and create a replacement instead.")
                .arg(selected.scope));
        return;
    }

    PolicyEditorDialog dialog(selected, this);
    if (dialog.exec() != QDialog::Accepted) return;

    QList<NetworkPolicy> updated = m_policies;
    updated[row] = dialog.policy();
    if (!PolicyStore::savePolicies(updated)) {
        QMessageBox::warning(this, QStringLiteral("Policies"),
                             QStringLiteral("The edited policy could not be saved."));
        refresh();
        return;
    }

    m_changed = true;
    refresh();
    if (row < m_table->rowCount()) m_table->selectRow(row);
}

void PolicyListDialog::deleteSelected()
{
    const int row = selectedRow();
    if (row < 0 || row >= m_policies.size()) return;

    const NetworkPolicy policy = m_policies.at(row);
    const QString target = policy.targetId.isEmpty()
        ? policy.id
        : policy.targetId;
    const QMessageBox::StandardButton answer = QMessageBox::question(
        this, QStringLiteral("Delete policy"),
        QStringLiteral("Delete the %1 policy for %2?\n\nThis cannot be undone.")
            .arg(actionName(policy.action).toLower(), target),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) return;

    QList<NetworkPolicy> updated = m_policies;
    updated.removeAt(row);
    if (!PolicyStore::savePolicies(updated)) {
        QMessageBox::warning(this, QStringLiteral("Policies"),
                             QStringLiteral("The policy could not be deleted."));
        refresh();
        return;
    }

    m_changed = true;
    refresh();
}
