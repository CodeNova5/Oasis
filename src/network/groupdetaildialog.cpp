/**
 * @file    groupdetaildialog.cpp
 * @brief   Identity and activity group detail view (NG-016).
 */
#include "groupdetaildialog.h"
#include "bandwidthguard.h"
#include "networkmonitor.h"
#include "attribution/attributionconfidence.h"

#include "ui/theme/thememanager.h"

#include <QAbstractItemView>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {

// At most this many member rows are shown without scrolling; the rest scroll so
// the evidence pane keeps the room it needs.
const int kMaxVisibleMemberRows = 5;

enum MemberColumn : int {
    ColMember = 0,
    ColType,
    ColEvidence,
    ColConfidence,
    ColPid,
    ColCount
};

QString pidText(const Oasis::GroupMember &member)
{
    return member.observedPid != 0 ? QString::number(member.observedPid)
                                   : QStringLiteral("—");
}

// The member is named after the application it belongs to, with the executable
// file or service key next to it: "Google Chrome (chrome.exe)" is recognisable
// while two binaries shipped by the same product stay distinguishable.
QString memberLabel(const Oasis::GroupMember &member)
{
    const QString fileName = member.type == Oasis::GroupMemberType::ExecutablePath
                                 ? QFileInfo(member.value).fileName()
                                 : member.value;
    const QString appName = member.displayName.trimmed();
    if (appName.isEmpty()) return fileName.isEmpty() ? member.value : fileName;
    if (fileName.isEmpty() || appName.compare(fileName, Qt::CaseInsensitive) == 0)
        return appName;
    return QStringLiteral("%1 (%2)").arg(appName, fileName);
}

} // namespace

GroupDetailDialog::GroupDetailDialog(NetworkMonitor *monitor, const QString &groupId,
                                     BandwidthGuard *bandwidthGuard, QWidget *parent)
    : QDialog(parent), m_monitor(monitor), m_bandwidthGuard(bandwidthGuard),
      m_groupId(groupId)
{
    setWindowTitle(QStringLiteral("Activity Group"));
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    setMinimumSize(760, 520);

    // Same palette handling as the other dialogs so the window follows the
    // current theme instead of inventing its own colours.
    const bool isDark = ThemeManager::instance().isDark();
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
                      "QLabel#lblGroupSummary, QLabel#lblGroupStatus { color: %6; }"
                      "QLineEdit { background: transparent; border: 1px solid %3; border-radius: 4px;"
                      " color: %2; font-size: 13pt; font-weight: bold; padding: 4px 6px;"
                      " selection-background-color: %7; selection-color: #FFFFFF; }"
                      "QPushButton { background-color: %4; border: 1px solid %3; border-radius: 6px;"
                      " padding: 6px 16px; color: %2; font-weight: bold; }"
                      "QPushButton:hover { background-color: %5; }"
                      "QPushButton:disabled { color: %6; background-color: %1; }"
                      "QTableWidget { background-color: %1; alternate-background-color: %4;"
                      " gridline-color: %3; border: 1px solid %3; border-radius: 6px; }"
                      "QHeaderView::section { background-color: %4; color: %2; border: none;"
                      " border-bottom: 1px solid %3; padding: 6px; font-weight: bold; }"
                      "QGroupBox { border: 1px solid %3; border-radius: 6px; margin-top: 12px;"
                      " font-weight: bold; color: %2; }"
                      "QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left;"
                      " left: 10px; }"
                      ).arg(bg, fg, border, btnBg, btnHover, textMuted, selectBg));

    QVBoxLayout *root = new QVBoxLayout(this);
    root->setSpacing(12);
    root->setContentsMargins(20, 20, 20, 20);

    // ── Header: editable group name and the action that persists it ──
    QHBoxLayout *header = new QHBoxLayout();
    m_nameEdit = new QLineEdit(this);
    m_nameEdit->setObjectName(QStringLiteral("editGroupName"));
    m_nameEdit->setPlaceholderText(QStringLiteral("Group name"));
    header->addWidget(m_nameEdit, 1);

    m_btnRename = new QPushButton(QStringLiteral("Rename"), this);
    m_btnRename->setObjectName(QStringLiteral("btnRenameGroup"));
    header->addWidget(m_btnRename);
    root->addLayout(header);

    m_summary = new QLabel(this);
    m_summary->setObjectName(QStringLiteral("lblGroupSummary"));
    m_summary->setWordWrap(true);
    root->addWidget(m_summary);

    // ── Members: one row per executable or service, with its evidence ──
    m_table = new QTableWidget(0, ColCount, this);
    m_table->setObjectName(QStringLiteral("tableGroupMembers"));
    m_table->setHorizontalHeaderLabels({QStringLiteral("Member"),
                                        QStringLiteral("Type"),
                                        QStringLiteral("Evidence"),
                                        QStringLiteral("Confidence"),
                                        QStringLiteral("PID")});
    m_table->verticalHeader()->setVisible(false);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->horizontalHeader()->setSectionResizeMode(ColMember, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(ColType, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(ColEvidence, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(ColConfidence, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(ColPid, QHeaderView::ResizeToContents);
    // The member list is as tall as its rows (up to a cap) so the evidence pane
    // below gets the remaining room instead of staring at empty table space.
    m_table->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_table->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    root->addWidget(m_table);

    // ── Selected member: the identity evidence behind the membership ──
    QGroupBox *detailBox = new QGroupBox(QStringLiteral("Why this member belongs"), this);
    QVBoxLayout *detailLayout = new QVBoxLayout(detailBox);
    m_detail = new QLabel(this);
    m_detail->setObjectName(QStringLiteral("lblGroupMemberDetail"));
    m_detail->setWordWrap(true);
    m_detail->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_detail->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    m_detail->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    detailLayout->addWidget(m_detail);
    root->addWidget(detailBox, 1);

    m_status = new QLabel(this);
    m_status->setObjectName(QStringLiteral("lblGroupStatus"));
    m_status->setWordWrap(true);
    root->addWidget(m_status);

    // ── Actions ──
    QHBoxLayout *actions = new QHBoxLayout();
    m_btnAdd = new QPushButton(QStringLiteral("Add executable…"), this);
    m_btnAdd->setObjectName(QStringLiteral("btnAddGroupMember"));
    actions->addWidget(m_btnAdd);

    m_btnRemove = new QPushButton(QStringLiteral("Remove member"), this);
    m_btnRemove->setObjectName(QStringLiteral("btnRemoveGroupMember"));
    m_btnRemove->setEnabled(false);
    actions->addWidget(m_btnRemove);

    actions->addStretch(1);

    QPushButton *close = new QPushButton(QStringLiteral("Close"), this);
    close->setObjectName(QStringLiteral("btnCloseGroupDetail"));
    actions->addWidget(close);
    root->addLayout(actions);

    connect(close, &QPushButton::clicked, this, &QDialog::accept);
    connect(m_btnRemove, &QPushButton::clicked, this, &GroupDetailDialog::onRemoveSelected);
    connect(m_btnAdd, &QPushButton::clicked, this, &GroupDetailDialog::onAddExecutable);
    connect(m_btnRename, &QPushButton::clicked, this, &GroupDetailDialog::onRename);
    connect(m_nameEdit, &QLineEdit::returnPressed, this, &GroupDetailDialog::onRename);
    connect(m_table, &QTableWidget::itemSelectionChanged,
            this, &GroupDetailDialog::onMemberSelectionChanged);
    if (m_monitor)
        connect(m_monitor, &NetworkMonitor::groupSnapshotReady,
                this, &GroupDetailDialog::onSnapshot);

    // Start from the latest published snapshot; the group may already be gone
    // (traffic stopped) but the dialog still shows what is known.
    if (m_monitor) {
        const QList<Oasis::ProcessGroup> groups = m_monitor->processGroups();
        for (const Oasis::ProcessGroup &group : groups) {
            if (group.id != m_groupId) continue;
            applyGroup(group);
            break;
        }
    }
    if (!m_group.isValid()) {
        // The group id is not in the published set (traffic stopped, or the
        // group was removed): keep the window informative but read-only.
        m_active = false;
        m_nameEdit->setText(QString());
        m_nameEdit->setPlaceholderText(QStringLiteral("Group not active"));
        m_btnRename->setEnabled(false);
        m_btnAdd->setEnabled(false);
    }
    refreshTable();
}

void GroupDetailDialog::onSnapshot(const QList<Oasis::ProcessGroup> &groups)
{
    for (const Oasis::ProcessGroup &group : groups) {
        if (group.id != m_groupId) continue;
        applyGroup(group);
        refreshTable();
        return;
    }

    // Gone from the live set: keep the last known members visible, but explain
    // that nothing is running under this group at the moment.
    m_active = false;
    refreshSummary();
}

void GroupDetailDialog::applyGroup(const Oasis::ProcessGroup &group)
{
    m_group = group;
    m_active = true;

    if (!m_nameEdit->hasFocus())
        m_nameEdit->setText(group.name);
    m_btnRename->setEnabled(true);
    m_btnAdd->setEnabled(true);
}

void GroupDetailDialog::refreshTable()
{
    // Keep the selected member selected across a live snapshot refresh.
    const QString previousKey = m_table->currentRow() >= 0
                                    ? m_table->item(m_table->currentRow(), ColMember)
                                          ->data(Qt::UserRole).toString()
                                    : QString();

    m_table->blockSignals(true);
    m_table->setRowCount(0);

    for (const Oasis::GroupMember &member : m_group.members) {
        const int row = m_table->rowCount();
        m_table->insertRow(row);

        auto *nameItem = new QTableWidgetItem(memberLabel(member));
        nameItem->setData(Qt::UserRole, Oasis::groupMemberKey(member.type, member.value));
        nameItem->setToolTip(member.value);

        auto *typeItem = new QTableWidgetItem(Oasis::groupMemberTypeName(member.type));
        auto *evidenceItem = new QTableWidgetItem(Oasis::groupEvidenceName(member.evidence));
        auto *confidenceItem = new QTableWidgetItem(
            Oasis::groupConfidenceName(member.confidence));
        auto *pidItem = new QTableWidgetItem(pidText(member));
        pidItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);

        m_table->setItem(row, ColMember, nameItem);
        m_table->setItem(row, ColType, typeItem);
        m_table->setItem(row, ColEvidence, evidenceItem);
        m_table->setItem(row, ColConfidence, confidenceItem);
        m_table->setItem(row, ColPid, pidItem);

        if (!previousKey.isEmpty()
            && Oasis::groupMemberKey(member.type, member.value) == previousKey)
            m_table->selectRow(row);
    }

    m_table->blockSignals(false);
    sizeTableToMembers();
    refreshSummary();
    showMemberDetail();
}

void GroupDetailDialog::sizeTableToMembers()
{
    // A short membership list must not leave a cavern of empty grid behind it,
    // and a long one must not push the evidence pane out of the window: the
    // table shows whole rows up to a cap and scrolls beyond that.
    const int headerHeight = m_table->horizontalHeader()->sizeHint().height();
    const int rowHeight    = qMax(m_table->verticalHeader()->defaultSectionSize(), 20);
    const int rows         = qBound(1, m_table->rowCount(), kMaxVisibleMemberRows);
    const int height       = headerHeight + rows * rowHeight + 2 * m_table->frameWidth();
    m_table->setFixedHeight(height);
}

void GroupDetailDialog::refreshSummary()
{
    const int members = m_group.members.size();
    if (members == 0) {
        m_summary->setText(m_active
                               ? QStringLiteral("No members yet. Add an executable, or wait for the "
                                                "process evidence to fill the group in.")
                               : QStringLiteral("This group has no active member right now."));
        if (m_active) m_status->setText(QString());
        return;
    }

    const QString origin = m_group.manual ? QStringLiteral("created by you")
                                          : QStringLiteral("derived from process evidence");
    // NG-015: what the group's traffic is classified as, so the Data Saver
    // decision behind these members is visible where the members are explained.
    const ProcessCategory category = m_bandwidthGuard
        ? m_bandwidthGuard->groupCategory(m_groupId)
        : ProcessCategory::Unknown;
    // A category learned from group activity is only a possibility, never a
    // confirmed fact, so the summary labels it as such (NG-035).
    const QString categoryText = category == ProcessCategory::Unknown
        ? QStringLiteral("not classified (Unknown)")
        : AttributionConfidenceModel::qualifiedText(
              BandwidthGuard::categoryDisplayName(category),
              ApplicationIdentity::Confidence::WeakInference)
              + QStringLiteral(" (learned from group activity)");
    m_summary->setText(QStringLiteral("%1 %2 · %3 running now · %4 · %5 · Data Saver: %6")
                           .arg(members)
                           .arg(members == 1 ? QStringLiteral("member")
                                             : QStringLiteral("members"))
                           .arg(m_group.liveProcessCount())
                           .arg(Oasis::groupConfidenceName(m_group.confidence))
                           .arg(origin)
                           .arg(categoryText));
    if (!m_active)
        m_status->setText(QStringLiteral("This group is not active right now; the members below "
                                         "are the last known ones."));
}

void GroupDetailDialog::showMemberDetail()
{
    const int row = selectedRow();
    if (row < 0 || row >= m_group.members.size()) {
        m_detail->setText(QStringLiteral("Select a member to see the identity evidence behind it."));
        m_btnRemove->setEnabled(false);
        return;
    }

    const Oasis::GroupMember &member = m_group.members.at(row);
    m_btnRemove->setEnabled(true);

    QStringList lines;
    if (!member.displayName.trimmed().isEmpty())
        lines << QStringLiteral("Application: ") + member.displayName.trimmed();
    lines << (member.type == Oasis::GroupMemberType::ExecutablePath
                  ? QStringLiteral("Executable: ") + member.value
                  : QStringLiteral("Service key: ") + member.value);
    lines << QStringLiteral("Evidence: %1 (%2)")
                 .arg(Oasis::groupEvidenceName(member.evidence),
                      Oasis::groupConfidenceName(member.confidence));
    lines << QStringLiteral("Identity: %1")
                 .arg(member.identityId.isEmpty() ? QStringLiteral("not resolved")
                                                  : member.identityId);
    if (!member.publisher.isEmpty())
        lines << QStringLiteral("Publisher: ") + member.publisher;
    lines << QStringLiteral("Data Saver: ") + memberCategoryText(member);
    if (member.observedPid != 0)
        lines << QStringLiteral("Running as PID %1").arg(member.observedPid);
    if (member.manual)
        lines << QStringLiteral("Membership is manual");
    lines << QStringLiteral("Why: ") + member.explanation;

    m_detail->setText(lines.join(QLatin1Char('\n')));
}

// NG-015: the category this member is acted on as — its own name and publisher
// rules first, otherwise the one its group has learned from the members that
// have already crossed the bandwidth threshold.
QString GroupDetailDialog::memberCategoryText(const Oasis::GroupMember &member) const
{
    ClassificationEvidence evidence;
    evidence.processName = member.type == Oasis::GroupMemberType::ExecutablePath
                               ? QFileInfo(member.value).fileName()
                               : member.value;
    evidence.executablePath = member.value;
    evidence.displayName = member.displayName;
    evidence.publisher = member.publisher;
    evidence.signerStatus = member.publisher.isEmpty()
                                ? ApplicationIdentity::SignerStatus::Unknown
                                : ApplicationIdentity::SignerStatus::Signed;
    evidence.groupId = m_groupId;
    evidence.isService = member.type == Oasis::GroupMemberType::Service;

    const ProcessCategory own = BandwidthGuard::classifyProcess(evidence);
    const ProcessClassification classification = m_bandwidthGuard
        ? m_bandwidthGuard->memberClassification(evidence)
        : BandwidthGuard::classifyWithEvidence(evidence);
    if (classification.category == ProcessCategory::Unknown)
        return QStringLiteral("not classified (Unknown)");

    QString text = AttributionConfidenceModel::qualifiedText(
        BandwidthGuard::categoryDisplayName(classification.category),
        classification.confidence);
    // Say so when the category came from the group rather than from this file,
    // because that is what makes an unnamed helper actionable.
    if (own == ProcessCategory::Unknown)
        text += QStringLiteral(" (learned from this group)");
    if (!classification.evidence.isEmpty())
        text += QStringLiteral(" — ") + classification.evidence.join(QStringLiteral("; "));
    return text;
}

void GroupDetailDialog::onMemberSelectionChanged()
{
    showMemberDetail();
}

void GroupDetailDialog::onRemoveSelected()
{
    const int row = selectedRow();
    if (row < 0 || row >= m_group.members.size() || !m_monitor) return;

    const Oasis::GroupMember member = m_group.members.at(row);
    const QString label = member.displayName.isEmpty() ? member.value : member.displayName;
    const bool autoRemoved = !member.manual;

    if (!m_monitor->removeProcessGroupMember(m_groupId, member.type, member.value)) {
        setStatus(QStringLiteral("The member could not be removed. It may already be gone."));
        return;
    }

    setStatus(autoRemoved
                  ? QStringLiteral("Removed %1. The automatic evidence will not add it back.").arg(label)
                  : QStringLiteral("Removed %1 from this group.").arg(label));
}

void GroupDetailDialog::onAddExecutable()
{
    if (!m_monitor) return;

    const QString path = QFileDialog::getOpenFileName(
        this, QStringLiteral("Add executable to this group"),
        QStringLiteral("C:\\Program Files"), QStringLiteral("Executables (*.exe)"));
    if (path.isEmpty()) return;

    QString error;
    if (!m_monitor->addProcessGroupMember(m_groupId, Oasis::GroupMemberType::ExecutablePath,
                                          path, &error)) {
        setStatus(error.isEmpty() ? QStringLiteral("The executable could not be added.") : error);
        return;
    }
    setStatus(QStringLiteral("Added %1. It joins the group whenever it runs.").arg(path));
}

void GroupDetailDialog::onRename()
{
    if (!m_monitor) return;

    const QString name = m_nameEdit->text().trimmed();
    if (name.isEmpty()) {
        setStatus(QStringLiteral("A group needs a name."));
        return;
    }
    if (name == m_group.name) {
        setStatus(QStringLiteral("The name is unchanged."));
        return;
    }
    if (!m_monitor->renameProcessGroup(m_groupId, name)) {
        setStatus(QStringLiteral("The group could not be renamed. Another group may already use that name."));
        return;
    }
    setStatus(QStringLiteral("Renamed to %1. The new name is saved and survives a restart.").arg(name));
}

void GroupDetailDialog::setStatus(const QString &message)
{
    m_status->setText(message);
}

int GroupDetailDialog::selectedRow() const
{
    return m_table->currentRow();
}

void GroupDetailDialog::showEvent(QShowEvent *event)
{
    QDialog::showEvent(event);
    // Center the dialog on its parent widget so it is always visible.
    if (parentWidget()) {
        QRect parentGeo = parentWidget()->geometry();
        int w = qMin(width(), parentGeo.width() * 3 / 4);
        int h = qMin(height(), parentGeo.height() * 3 / 4);
        resize(w, h);
        move(parentGeo.center() - rect().center());
    }
}

