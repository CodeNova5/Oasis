/**
 * @file    groupdetaildialog.h
 * @brief   Identity and activity group detail view (NG-016).
 *
 * Shows one activity group: its name and confidence, the Data Saver category its
 * members have earned (NG-015), every executable and service member with the
 * evidence behind it, and the identity evidence of the selected member (path,
 * NG-010 identity id, NG-011 publisher, the category it is acted on as, and the
 * sentence explaining why it belongs). Members can be removed and the group
 * renamed here, so no configuration file has to be edited by hand.
 *
 * The dialog follows the monitor's published group snapshots, so a live
 * membership change is reflected while it is open.
 */
#pragma once

#include <QDialog>
#include <QList>
#include <QString>

#include "identity/processgroupmanager.h"

class BandwidthGuard;
class NetworkMonitor;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class GroupDetailDialog : public QDialog
{
    Q_OBJECT
public:
    // bandwidthGuard may be null: the group is then shown without the category
    // its members have earned.
    GroupDetailDialog(NetworkMonitor *monitor, const QString &groupId,
                      BandwidthGuard *bandwidthGuard, QWidget *parent = nullptr);

    QString groupId() const { return m_groupId; }

private slots:
    void onSnapshot(const QList<Oasis::ProcessGroup> &groups);
    void onRemoveSelected();
    void onAddExecutable();
    void onRename();
    void onMemberSelectionChanged();

protected:
    void showEvent(QShowEvent *event) override;

private:
    void applyGroup(const Oasis::ProcessGroup &group);
    void refreshTable();
    void sizeTableToMembers();
    void refreshSummary();
    void showMemberDetail();
    QString memberCategoryText(const Oasis::GroupMember &member) const;
    void setStatus(const QString &message);
    int  selectedRow() const;

    NetworkMonitor *m_monitor = nullptr;
    BandwidthGuard *m_bandwidthGuard = nullptr;
    QString         m_groupId;
    Oasis::ProcessGroup m_group;
    bool            m_active = true;

    QLineEdit    *m_nameEdit   = nullptr;
    QPushButton  *m_btnRename  = nullptr;
    QLabel       *m_summary    = nullptr;
    QLabel       *m_detail     = nullptr;
    QLabel       *m_status     = nullptr;
    QTableWidget *m_table      = nullptr;
    QPushButton  *m_btnRemove  = nullptr;
    QPushButton  *m_btnAdd     = nullptr;
};
