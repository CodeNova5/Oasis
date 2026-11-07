/**
 * @file    groupdetaildialog.h
 * @brief   Identity and activity group detail view (NG-016).
 *
 * Shows one activity group: its name and confidence, every executable and
 * service member with the evidence behind it, and the identity evidence of the
 * selected member (path, NG-010 identity id, NG-011 publisher, and the sentence
 * explaining why it belongs). Members can be removed and the group renamed
 * here, so no configuration file has to be edited by hand.
 *
 * The dialog follows the monitor's published group snapshots, so a live
 * membership change is reflected while it is open.
 */
#pragma once

#include <QDialog>
#include <QList>
#include <QString>

#include "identity/processgroupmanager.h"

class NetworkMonitor;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class GroupDetailDialog : public QDialog
{
    Q_OBJECT
public:
    GroupDetailDialog(NetworkMonitor *monitor, const QString &groupId,
                      QWidget *parent = nullptr);

    QString groupId() const { return m_groupId; }

private slots:
    void onSnapshot(const QList<NetGuard::ProcessGroup> &groups);
    void onRemoveSelected();
    void onAddExecutable();
    void onRename();
    void onMemberSelectionChanged();

private:
    void applyGroup(const NetGuard::ProcessGroup &group);
    void refreshTable();
    void refreshSummary();
    void showMemberDetail();
    void setStatus(const QString &message);
    int  selectedRow() const;

    NetworkMonitor *m_monitor = nullptr;
    QString         m_groupId;
    NetGuard::ProcessGroup m_group;
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
