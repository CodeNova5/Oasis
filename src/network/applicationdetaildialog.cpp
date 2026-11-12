/**
 * @file    applicationdetaildialog.cpp
 * @brief   One-window application detail view (NG-052).
 */
#include "applicationdetaildialog.h"

#include "stylemanager.h"
#include "apptheme.h"

#include <QAbstractItemView>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QStyle>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {

const int kVisibleDestinationRows = 4;
const int kVisibleRelatedRows = 4;
const int kVisiblePolicyRows = 3;
const int kVisibleAuditRows = 5;

QTableWidget *makeTable(QWidget *parent, const QString &objectName,
                        const QStringList &headers)
{
    auto *table = new QTableWidget(0, headers.size(), parent);
    table->setObjectName(objectName);
    table->setHorizontalHeaderLabels(headers);
    table->verticalHeader()->setVisible(false);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setAlternatingRowColors(true);
    table->setWordWrap(false);
    table->horizontalHeader()->setStretchLastSection(true);
    return table;
}

QTableWidgetItem *item(const QString &text, const QString &tooltip = QString())
{
    auto *entry = new QTableWidgetItem(text);
    if (!tooltip.isEmpty()) entry->setToolTip(tooltip);
    return entry;
}

// A table that shows whole rows up to a cap and scrolls beyond it, so an empty
// section never leaves a cavern of grid behind.
void sizeTable(QTableWidget *table, int visibleRows)
{
    const int headerHeight = table->horizontalHeader()->sizeHint().height();
    const int rowHeight = qMax(table->verticalHeader()->defaultSectionSize(), 20);
    const int rows = qBound(1, table->rowCount(), visibleRows);
    table->setMinimumHeight(headerHeight + rows * rowHeight + 2 * table->frameWidth() + 4);
}

QString expiresText(const QDateTime &at)
{
    if (!at.isValid()) return QStringLiteral("until removed");
    return at.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm"));
}

QString destinationLabel(const ApplicationDetail::Destination &destination)
{
    if (!destination.name.trimmed().isEmpty()) return destination.name;
    return QStringLiteral("(direct address)");
}

} // namespace

ApplicationDetailDialog::ApplicationDetailDialog(const QString &executablePath,
                                                 const ApplicationDetail::Input &input,
                                                 QWidget *parent)
    : QDialog(parent), m_input(input)
{
    setWindowTitle(executablePath.isEmpty()
                       ? QStringLiteral("Application details")
                       : QStringLiteral("Application details — ")
                             + QFileInfo(executablePath).fileName());
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    setMinimumSize(820, 640);
    resize(900, 720);

    // The same palette handling as the group and recommendation dialogs, so the
    // window follows the theme instead of inventing its own colours.
    const bool isDark = (StyleManager::instance().currentMode() == AppTheme::Dark);
    const QString bg        = isDark ? QStringLiteral("#1F2328") : QStringLiteral("#F6F8FA");
    const QString fg        = isDark ? QStringLiteral("#E6EDF3") : QStringLiteral("#24292E");
    const QString border    = isDark ? QStringLiteral("#30363D") : QStringLiteral("#D0D7DE");
    const QString btnBg     = isDark ? QStringLiteral("#21262D") : QStringLiteral("#EBECF0");
    const QString btnHover  = isDark ? QStringLiteral("#30363D") : QStringLiteral("#F3F4F6");
    const QString textMuted = isDark ? QStringLiteral("#8B949E") : QStringLiteral("#57606A");
    const QString selectBg  = isDark ? QStringLiteral("#1F6FEB") : QStringLiteral("#0969DA");

    setStyleSheet(QString(
                      "QDialog { background-color: %1; color: %2; }"
                      "QLabel { color: %2; font-size: 10pt; }"
                      "QLabel#lblDetailTitle { font-size: 15pt; font-weight: bold; }"
                      "QLabel#lblDetailSubtitle, QLabel#lblDetailSummary,"
                      " QLabel#lblDetailStatus { color: %6; }"
                      "QLabel#lblDetailActivity { font-size: 11pt; font-weight: bold; }"
                      "QPushButton { background-color: %4; border: 1px solid %3; border-radius: 6px;"
                      " padding: 6px 14px; color: %2; font-weight: bold; }"
                      "QPushButton:hover { background-color: %5; }"
                      "QPushButton:disabled { color: %6; background-color: %1; }"
                      "QTableWidget { background-color: %1; alternate-background-color: %4;"
                      " gridline-color: %3; border: 1px solid %3; border-radius: 6px; }"
                      "QHeaderView::section { background-color: %4; color: %2; border: none;"
                      " border-bottom: 1px solid %3; padding: 5px; font-weight: bold; }"
                      "QGroupBox { border: 1px solid %3; border-radius: 6px; margin-top: 12px;"
                      " font-weight: bold; color: %2; }"
                      "QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left;"
                      " left: 10px; }"
                      "QScrollArea { border: none; background: transparent; }"
                      ).arg(bg, fg, border, btnBg, btnHover, textMuted, selectBg));

    QVBoxLayout *root = new QVBoxLayout(this);
    root->setSpacing(10);
    root->setContentsMargins(20, 18, 20, 16);

    // ── Header ──
    m_title = new QLabel(this);
    m_title->setObjectName(QStringLiteral("lblDetailTitle"));
    m_title->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_title->setWordWrap(true);
    root->addWidget(m_title);

    m_subtitle = new QLabel(this);
    m_subtitle->setObjectName(QStringLiteral("lblDetailSubtitle"));
    m_subtitle->setWordWrap(true);
    root->addWidget(m_subtitle);

    // ── Scrollable evidence sections ──
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto *content = new QWidget(scroll);
    auto *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(0, 0, 6, 0);
    contentLayout->setSpacing(6);

    // Activity and usage: why this application is classified the way it is.
    QGroupBox *activityBox = new QGroupBox(QStringLiteral("Activity and usage"), content);
    QVBoxLayout *activityLayout = new QVBoxLayout(activityBox);
    m_activity = new QLabel(activityBox);
    m_activity->setObjectName(QStringLiteral("lblDetailActivity"));
    m_activity->setWordWrap(true);
    m_activityWhy = new QLabel(activityBox);
    m_activityWhy->setObjectName(QStringLiteral("lblDetailSummary"));
    m_activityWhy->setWordWrap(true);
    m_evidence = new QLabel(activityBox);
    m_evidence->setObjectName(QStringLiteral("lblDetailStatus"));
    m_evidence->setWordWrap(true);
    m_evidence->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_usage = new QLabel(activityBox);
    m_usage->setWordWrap(true);
    m_foreground = new QLabel(activityBox);
    m_foreground->setObjectName(QStringLiteral("lblDetailSummary"));
    m_foreground->setWordWrap(true);
    activityLayout->addWidget(m_activity);
    activityLayout->addWidget(m_activityWhy);
    activityLayout->addWidget(m_evidence);
    activityLayout->addWidget(m_usage);
    activityLayout->addWidget(m_foreground);
    contentLayout->addWidget(activityBox);

    // Identity evidence.
    QGroupBox *identityBox = new QGroupBox(QStringLiteral("Identity"), content);
    QVBoxLayout *identityLayout = new QVBoxLayout(identityBox);
    m_identity = new QLabel(identityBox);
    m_identity->setWordWrap(true);
    m_identity->setTextFormat(Qt::RichText);
    m_identity->setTextInteractionFlags(Qt::TextSelectableByMouse);
    identityLayout->addWidget(m_identity);
    contentLayout->addWidget(identityBox);

    // Destinations.
    QGroupBox *destBox = new QGroupBox(QStringLiteral("Destinations"), content);
    QVBoxLayout *destLayout = new QVBoxLayout(destBox);
    m_destSummary = new QLabel(destBox);
    m_destSummary->setObjectName(QStringLiteral("lblDetailSummary"));
    m_destSummary->setWordWrap(true);
    destLayout->addWidget(m_destSummary);
    m_destTable = makeTable(destBox, QStringLiteral("tableDetailDestinations"),
                            {QStringLiteral("Name"), QStringLiteral("Address"),
                             QStringLiteral("Attributed by"), QStringLiteral("Confidence"),
                             QStringLiteral("Expires")});
    m_destTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_destTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_destTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_destTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_destTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    destLayout->addWidget(m_destTable);
    contentLayout->addWidget(destBox);

    // Related processes.
    QGroupBox *relatedBox = new QGroupBox(QStringLiteral("Related processes"), content);
    QVBoxLayout *relatedLayout = new QVBoxLayout(relatedBox);
    m_relatedSummary = new QLabel(relatedBox);
    m_relatedSummary->setObjectName(QStringLiteral("lblDetailSummary"));
    m_relatedSummary->setWordWrap(true);
    relatedLayout->addWidget(m_relatedSummary);
    m_relatedTable = makeTable(relatedBox, QStringLiteral("tableDetailRelated"),
                               {QStringLiteral("Process"), QStringLiteral("PID"),
                                QStringLiteral("Why it is related")});
    m_relatedTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_relatedTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_relatedTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    relatedLayout->addWidget(m_relatedTable);
    contentLayout->addWidget(relatedBox);

    // Policies and controls.
    QGroupBox *policyBox = new QGroupBox(QStringLiteral("Policies and controls"), content);
    QVBoxLayout *policyLayout = new QVBoxLayout(policyBox);
    m_policySummary = new QLabel(policyBox);
    m_policySummary->setObjectName(QStringLiteral("lblDetailSummary"));
    m_policySummary->setWordWrap(true);
    policyLayout->addWidget(m_policySummary);
    m_policyTable = makeTable(policyBox, QStringLiteral("tableDetailPolicies"),
                              {QStringLiteral("Policy"), QStringLiteral("Scope"),
                               QStringLiteral("Action"), QStringLiteral("Direction"),
                               QStringLiteral("State"), QStringLiteral("Origin"),
                               QStringLiteral("Expires")});
    m_policyTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    for (int column = 1; column < 6; ++column)
        m_policyTable->horizontalHeader()->setSectionResizeMode(column, QHeaderView::ResizeToContents);
    policyLayout->addWidget(m_policyTable);
    contentLayout->addWidget(policyBox);

    // Audit history.
    QGroupBox *auditBox = new QGroupBox(QStringLiteral("Audit history"), content);
    QVBoxLayout *auditLayout = new QVBoxLayout(auditBox);
    m_auditSummary = new QLabel(auditBox);
    m_auditSummary->setObjectName(QStringLiteral("lblDetailSummary"));
    m_auditSummary->setWordWrap(true);
    auditLayout->addWidget(m_auditSummary);
    m_auditTable = makeTable(auditBox, QStringLiteral("tableDetailAudit"),
                             {QStringLiteral("When"), QStringLiteral("Type"),
                              QStringLiteral("Event"), QStringLiteral("Result")});
    m_auditTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_auditTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_auditTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_auditTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    auditLayout->addWidget(m_auditTable);
    contentLayout->addWidget(auditBox);
    contentLayout->addStretch(1);

    scroll->setWidget(content);
    root->addWidget(scroll, 1);

    m_status = new QLabel(this);
    m_status->setObjectName(QStringLiteral("lblDetailStatus"));
    m_status->setWordWrap(true);
    root->addWidget(m_status);

    // ── Actions: the same reversible controls the rest of the product offers ──
    QHBoxLayout *actions = new QHBoxLayout();
    actions->setSpacing(8);
    for (const ApplicationDetail::ActionState &action : ApplicationDetail::buildActions(m_input)) {
        auto *button = new QPushButton(action.label, this);
        button->setObjectName(QStringLiteral("btnDetail_") + action.key);
        button->setProperty("actionKey", action.key);
        button->setEnabled(action.enabled);
        if (!action.reason.isEmpty()) button->setToolTip(action.reason);
        connect(button, &QPushButton::clicked, this, &ApplicationDetailDialog::onActionButtonClicked);
        actions->addWidget(button);
        m_actionKeys << action.key;
    }
    actions->addStretch(1);

    QPushButton *refresh = new QPushButton(QStringLiteral("Refresh"), this);
    refresh->setObjectName(QStringLiteral("btnDetailRefresh"));
    actions->addWidget(refresh);
    connect(refresh, &QPushButton::clicked, this, &ApplicationDetailDialog::onRefresh);

    QPushButton *close = new QPushButton(QStringLiteral("Close"), this);
    close->setObjectName(QStringLiteral("btnDetailClose"));
    actions->addWidget(close);
    connect(close, &QPushButton::clicked, this, &QDialog::accept);

    root->addLayout(actions);

    render();
}

void ApplicationDetailDialog::setInput(const ApplicationDetail::Input &input)
{
    m_input = input;
    render();
}

void ApplicationDetailDialog::render()
{
    m_snapshot = ApplicationDetail::build(m_input);

    m_title->setText(m_snapshot.title);
    m_subtitle->setText(m_snapshot.subtitle);

    m_activity->setText(m_snapshot.activitySummary);
    m_activityWhy->setText(m_snapshot.activityDetail);
    m_evidence->setText(m_snapshot.evidence.isEmpty()
                            ? QStringLiteral("No classification evidence yet.")
                            : QStringLiteral("Evidence: ")
                                  + m_snapshot.evidence.join(QStringLiteral(" · ")));
    m_usage->setText(m_snapshot.usageText);
    m_foreground->setText(m_snapshot.foregroundText);

    renderIdentity(m_snapshot);
    renderDestinations(m_snapshot);
    renderRelated(m_snapshot);
    renderPolicies(m_snapshot);
    renderAudit(m_snapshot);

    // Buttons follow the snapshot, so a block that just applied now offers
    // "Restore internet access" and a new limit offers removal.
    const QList<QPushButton *> buttons = findChildren<QPushButton *>();
    QHash<QString, ApplicationDetail::ActionState> states;
    for (const ApplicationDetail::ActionState &action : m_snapshot.actions)
        states.insert(action.key, action);
    for (QPushButton *button : buttons) {
        const QString key = button->property("actionKey").toString();
        if (key.isEmpty() || !states.contains(key)) continue;
        const ApplicationDetail::ActionState &state = states.value(key);
        button->setText(state.label);
        button->setEnabled(state.enabled);
        button->setToolTip(state.reason);
    }

    // Say why anything is unavailable instead of leaving a greyed-out button to
    // explain itself through a tooltip the user may never hover.
    QStringList unavailable;
    for (const ApplicationDetail::ActionState &action : m_snapshot.actions) {
        if (!action.enabled && !action.reason.isEmpty()) unavailable << action.reason;
    }
    m_status->setText(unavailable.join(QLatin1Char(' ')));
}

void ApplicationDetailDialog::renderIdentity(const ApplicationDetail::Snapshot &snapshot)
{
    QStringList rows;
    for (const QPair<QString, QString> &fact : snapshot.facts) {
        rows << QStringLiteral("<b>%1:</b> %2")
                    .arg(fact.first.toHtmlEscaped(), fact.second.toHtmlEscaped());
    }
    m_identity->setText(rows.join(QStringLiteral("<br>")));
}

void ApplicationDetailDialog::renderDestinations(const ApplicationDetail::Snapshot &snapshot)
{
    m_destSummary->setText(snapshot.destinationSummary);

    m_destTable->setRowCount(0);
    for (const ApplicationDetail::Destination &destination : snapshot.destinations) {
        const int row = m_destTable->rowCount();
        m_destTable->insertRow(row);

        QStringList tooltip;
        tooltip << QStringLiteral("Address: ") + destination.address;
        if (!destination.name.isEmpty())
            tooltip << QStringLiteral("Name: ") + destination.name;
        tooltip << QStringLiteral("Attribution: ") + destination.source;
        tooltip << QStringLiteral("Confidence: ")
                       + AttributionConfidenceModel::displayName(destination.confidence);
        for (const QString &line : destination.evidence)
            tooltip << QStringLiteral("Evidence: ") + line;
        if (destination.expiresAt.isValid()) {
            tooltip << QStringLiteral("Expires: ")
                           + destination.expiresAt.toLocalTime().toString(
                                 QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        }
        const QString tip = tooltip.join(QLatin1Char('\n'));

        m_destTable->setItem(row, 0, item(destinationLabel(destination), tip));
        m_destTable->setItem(row, 1, item(destination.address, tip));
        m_destTable->setItem(row, 2, item(destination.source, tip));
        m_destTable->setItem(row, 3, item(AttributionConfidenceModel::displayName(
                                             destination.confidence), tip));
        m_destTable->setItem(row, 4, item(expiresText(destination.expiresAt), tip));
    }
    sizeTable(m_destTable, kVisibleDestinationRows);
}

void ApplicationDetailDialog::renderRelated(const ApplicationDetail::Snapshot &snapshot)
{
    m_relatedSummary->setText(snapshot.relatedSummary);

    m_relatedTable->setRowCount(0);
    for (const ApplicationDetail::RelatedProcess &related : snapshot.related) {
        const int row = m_relatedTable->rowCount();
        m_relatedTable->insertRow(row);
        m_relatedTable->setItem(row, 0, item(related.name));
        auto *pidItem = item(related.pid != 0 ? QString::number(related.pid)
                                              : QStringLiteral("—"));
        pidItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        m_relatedTable->setItem(row, 1, pidItem);
        m_relatedTable->setItem(row, 2, item(related.role));
    }
    sizeTable(m_relatedTable, kVisibleRelatedRows);
}

void ApplicationDetailDialog::renderPolicies(const ApplicationDetail::Snapshot &snapshot)
{
    m_policySummary->setText(snapshot.policySummary);

    m_policyTable->setRowCount(0);
    for (const ApplicationDetail::PolicyEntry &policy : snapshot.policies) {
        const int row = m_policyTable->rowCount();
        m_policyTable->insertRow(row);

        const QString where = QStringLiteral("%1: %2").arg(policy.scope, policy.targetId);
        auto *summary = item(policy.summary, where);
        if (policy.inForce)
            summary->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
        m_policyTable->setItem(row, 0, summary);
        m_policyTable->setItem(row, 1, item(policy.scope, where));
        m_policyTable->setItem(row, 2, item(policy.action));
        m_policyTable->setItem(row, 3, item(policy.direction));
        m_policyTable->setItem(row, 4, item(policy.state));
        m_policyTable->setItem(row, 5, item(policy.origin));
        m_policyTable->setItem(row, 6, item(expiresText(policy.expiration)));
    }
    sizeTable(m_policyTable, kVisiblePolicyRows);
}

void ApplicationDetailDialog::renderAudit(const ApplicationDetail::Snapshot &snapshot)
{
    m_auditSummary->setText(snapshot.auditSummary);

    m_auditTable->setRowCount(0);
    for (const ApplicationDetail::AuditEntry &entry : snapshot.audit) {
        const int row = m_auditTable->rowCount();
        m_auditTable->insertRow(row);
        m_auditTable->setItem(row, 0, item(entry.at.isValid()
                                               ? entry.at.toLocalTime().toString(
                                                     QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                                               : QStringLiteral("—")));
        m_auditTable->setItem(row, 1, item(entry.type));
        m_auditTable->setItem(row, 2, item(entry.summary));
        m_auditTable->setItem(row, 3, item(entry.result));
    }
    sizeTable(m_auditTable, kVisibleAuditRows);
}

void ApplicationDetailDialog::onActionButtonClicked()
{
    const auto *button = qobject_cast<QPushButton *>(sender());
    if (!button) return;
    const QString key = button->property("actionKey").toString();
    if (key.isEmpty()) return;
    emit actionRequested(key);
}

void ApplicationDetailDialog::onRefresh()
{
    emit refreshRequested();
}
