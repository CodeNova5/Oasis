/**
 * @file    applicationdetaildialog.h
 * @brief   One-window application detail view with evidence and reversible
 *          actions (NG-052).
 *
 * The dialog shows identity, activity classification with its evidence, current
 * usage, attributed destinations, related processes, the policies that target
 * the application, and its audit history. Every action it offers already exists
 * elsewhere in the product, so this view never becomes a second enforcement
 * path: it asks the owning widget, which performs the action and then hands the
 * dialog a fresh snapshot.
 */
#pragma once

#include <QDialog>

#include "network/applicationdetail.h"

class QLabel;
class QPushButton;
class QTableWidget;

class ApplicationDetailDialog : public QDialog
{
    Q_OBJECT
public:
    // `executablePath` seeds the title before the first snapshot is rendered.
    ApplicationDetailDialog(const QString &executablePath,
                            const ApplicationDetail::Input &input,
                            QWidget *parent = nullptr);

    // Replaces every section. Called after an action so the user sees the new
    // policy, limit, or audit entry without reopening the window.
    void setInput(const ApplicationDetail::Input &input);
    const ApplicationDetail::Input &input() const { return m_input; }

    // Stable action keys: "policy", "recommendation", "approval", "internet",
    // "throttle", "verify", "group".
    QStringList actionKeys() const { return m_actionKeys; }

signals:
    // The host performs the action and then calls setInput() with fresh
    // evidence; the dialog itself never writes a policy or a firewall rule.
    void actionRequested(const QString &key);
    // "Refresh" was pressed: re-read the live evidence.
    void refreshRequested();

private slots:
    void onActionButtonClicked();
    void onRefresh();

private:
    void render();
    void renderIdentity(const ApplicationDetail::Snapshot &snapshot);
    void renderDestinations(const ApplicationDetail::Snapshot &snapshot);
    void renderRelated(const ApplicationDetail::Snapshot &snapshot);
    void renderPolicies(const ApplicationDetail::Snapshot &snapshot);
    void renderAudit(const ApplicationDetail::Snapshot &snapshot);

    ApplicationDetail::Input   m_input;
    ApplicationDetail::Snapshot m_snapshot;
    QStringList                m_actionKeys;

    QLabel       *m_title       = nullptr;
    QLabel       *m_subtitle    = nullptr;
    QLabel       *m_activity    = nullptr;
    QLabel       *m_activityWhy = nullptr;
    QLabel       *m_evidence    = nullptr;
    QLabel       *m_usage       = nullptr;
    QLabel       *m_foreground  = nullptr;
    QLabel       *m_identity    = nullptr;
    QLabel       *m_destSummary = nullptr;
    QLabel       *m_relatedSummary = nullptr;
    QLabel       *m_policySummary  = nullptr;
    QLabel       *m_auditSummary   = nullptr;
    QLabel       *m_status      = nullptr;
    QTableWidget *m_destTable   = nullptr;
    QTableWidget *m_relatedTable = nullptr;
    QTableWidget *m_policyTable = nullptr;
    QTableWidget *m_auditTable  = nullptr;
};
