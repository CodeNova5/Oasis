/**
 * @file    networkwidget.h
 * @author  Oasis
 */
#pragma once

#include <QHash>
#include <QWidget>
#include <QSortFilterProxyModel>
#include <QDialog>
#include <QEvent>
#include <memory>
#include "networkmonitor.h"
#include "networkmodel.h"
#include "bandwidthguard.h"
#include "throttlepolicymanager.h"
#include "diagnostics.h"
#include "enforcementrestore.h"
#include "policyschedule.h"
#include "policyreconcile.h"
#include "auditeventstore.h"
#include "applicationdetail.h"
#include "policyeditordialog.h"
#include "topconsumers.h"
#include "attribution/recommendationengine.h"
#include "attribution/recommendationfeedback.h"
#include "attribution/aiprovider.h"

class FirewallManager;
class DashboardPanel;
class OpenAiCompatibleProvider;
class EnforcementCoordinator;
class PolicyReconciler;

namespace Ui { class NetworkWidget; }

// ── Professional Process Properties Dialog ──
class ProcessInfoDialog : public QDialog
{
    Q_OBJECT
public:
    ProcessInfoDialog(const QString &name, quint32 pid, const QString &path,
                      const QString &rx, const QString &tx, const QString &total, const QString &pkts,
                      const QIcon &icon, QWidget *parent = nullptr);
private slots:
    void onOpenLocation();
private:
    QString m_path;
};

class NetworkWidget : public QWidget
{
    Q_OBJECT
public:
    explicit NetworkWidget(QWidget *parent = nullptr);
    ~NetworkWidget() override;

    void autoStart();
    // Start capture if it is stopped and an adapter is available. Used by the
    // redesigned Overview screen's "Start monitoring" action, which may be
    // pressed before the first automatic start has happened.
    void startMonitoring();
    void setDataSaverMode(int mode);
    // Takes back the controls the product applied on its own (NG-026) and
    // reports which policies were removed, which were kept, and what failed.
    void restoreAllDataSaverPolicies();
    void requestThrottlePath(const QString &path);
    void exemptProcess(const QString &processName, int durationSeconds);
    void toggleInternetAccess(const QString &procName, const QString &path);

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

signals:
    void speedUpdated(quint64 rxBps, quint64 txBps);
    // Emitted once per second with the recalculated first-view summary, so a
    // host screen can follow the same beat without a timer of its own.
    void dashboardUpdated(const TopConsumers::Summary &summary);
    void bandwidthAlert(const BandwidthEvent &event);
    // NG-051: a policy channel reported a failure. Critical, so the
    // notification coordinator never rate-limits it away.
    void enforcementFailed(const QString &policyId, const QString &executablePath,
                           const QString &message);

private slots:
    void onAdapterChanged(int idx);
    void onStartStop();
    void onClearTable();
    void onExpandAll();
    void onFilterChanged(const QString &text);

    void onPacketsCapturedBatch(const QList<CapturedPacketInfo> &batch);
    void onSpeedUpdated(quint64 rxBps, quint64 txBps);
    void onCaptureError(const QString &msg);
    void onCaptureStarted();
    void onCaptureStopped();

    void onBandwidthDetected(const BandwidthEvent &event);
    void onThrottleApplied(const QString &executablePath, const ThrottleResult &result);
    void onThrottleRemoved(const QString &executablePath, const ThrottleResult &result);
    void onThrottlesRestored(const ThrottleResult &result);

    void onTreeViewContextMenu(const QPoint &pos);

    // NG-023: a policy entered or left its window. Entry is applied at once;
    // leaving is reported but not withdrawn (see the implementation note).
    void onPolicyActivationChanged(const NetworkPolicy &policy,
                                   PolicyActivationState state,
                                   const QString &reason);

    // NG-024: a queued verification finished on the reconciler's thread.
    void onPolicyReconciliationFinished(const ReconciliationReport &report);

public:
    QString getExactProcessPath(quint32 pid, const QString &procName);
    // Context-menu label for the throttle action: names the owning policy when
    // the executable already has a limit, so removal is not anonymous.
    QString throttleActionText(const QString &path) const;
    void selectAdapterByIPOrAuto(const QString &ipOrAuto);
    QList<AdapterInfo> getAdapterList() const { return m_adapters; }
    // Description of the adapter currently selected in the capture combo, for
    // the shell status bar. Empty until the adapter list is populated.
    QString activeAdapterDescription() const;
    DiagnosticsModel *diagnosticsModel() const { return m_diagnostics; }
    // The first-view summary as of the last one-second beat. The Overview page
    // renders this snapshot; it never queries the process model itself.
    TopConsumers::Summary dashboardSummary() const { return m_dashboardSummary; }
    bool isCapturing() const { return m_capturing; }
    // NG-050: the persisted audit log behind the audit view and its export.
    AuditEventStore *auditStore() { return &m_auditStore; }
    // NG-036: attribution privacy controls and the history they bound.
    NetworkMonitor *networkMonitor() const { return m_monitor; }
    // NG-041: the latest foreground sample. It is advisory, and its
    // associationFor() refuses a sample older than its freshness window.
    Oasis::ForegroundSnapshot foregroundSnapshot() const { return m_foregroundSnapshot; }
    // NG-045/NG-046: re-read the provider settings saved from the Settings tab
    // so the approval dialog uses them without a restart.
    void reloadAiProviderSettings();
    // NG-052: open the application detail view for one process, or for an
    // executable the capture no longer shows. This is also the entry point a
    // notification uses, so a warning can be followed by its evidence.
    void showApplicationDetails(quint32 pid, const QString &executablePath,
                                const QString &processName = QString());

private:
    void populateAdapterCombo();
    // Queues one reconciliation instead of running it inline, so a burst of
    // activation changes or a dialog close does not enumerate rules per event.
    void schedulePolicyReconciliation();
    // NG-054: rebuilds the first-view panel from the current rows, in-force
    // policies, and the recommendations for the current top consumers.
    void refreshDashboard();
    QIcon getIconByPid(quint32 pid, const QString &procName);
    void requestThrottle(quint32 pid, const QString &procName);
    // Evidence snapshot for the recommendation and approval views, taken while
    // the context menu's row is still valid.
    RecommendationContext recommendationContextFor(const ActivityQuery &query,
                                                    quint32 pid,
                                                    const QString &processName) const;
    // NG-052: the assembled detail snapshot (identity, usage, destinations,
    // related processes, policies, audit history) for one process or path.
    ApplicationDetail::Input detailInputFor(quint32 pid, const QString &executablePath,
                                            const QString &processName);
    // Policy target for a row or a notification, with the group's publisher and
    // service evidence filled in when they are available.
    PolicyTarget policyTargetFor(quint32 pid, const QString &processName,
                                 const QString &executablePath,
                                 const QString &groupId = QString()) const;
    // The row's evidence when the process is still in the model, otherwise the
    // path/name the caller knows.
    ActivityQuery queryAndActivityFor(quint32 pid, const QString &processName,
                                      const QString &executablePath,
                                      ActivityClassification *activity) const;
    void createPolicyForTarget(const PolicyTarget &target);
    void showRecommendationFor(quint32 pid, const QString &processName,
                               const QString &executablePath);
    void showApprovalFor(quint32 pid, const QString &processName,
                         const QString &executablePath);

    Ui::NetworkWidget       *ui = nullptr;
    // NG-054: the first-view panel, inserted above the process tree.
    DashboardPanel          *m_dashboard = nullptr;
    NetworkMonitor          *m_monitor = nullptr;
    DiagnosticsModel        *m_diagnostics = nullptr;
    NetworkTreeModel        *m_model = nullptr;
    BandwidthGuard          *m_bandwidthGuard = nullptr;
    ThrottlePolicyManager   *m_throttlePolicies = nullptr;
    EnforcementCoordinator  *m_enforcement = nullptr;
    PolicyScheduler         *m_policyScheduler = nullptr;
    PolicyReconciler        *m_policyReconciler = nullptr;
    FirewallManager         *m_firewall = nullptr;
    QSortFilterProxyModel   *m_proxy = nullptr;

    QList<AdapterInfo>      m_adapters;
    bool                    m_capturing = false;
    quint64                 m_totalPkts = 0;
    int                     m_dataSaverMode = 1;

    QHash<QString, QIcon>   m_iconCache;
    // NG-054: paths resolved once per (pid, start time) for the dashboard, so a
    // refresh does not open a process handle for every row every second.
    QHash<QString, QString> m_dashboardPathCache;
    // Last published first-view summary, readable by a host screen between beats.
    TopConsumers::Summary m_dashboardSummary;
    // Auto-throttle alerts waiting for the worker thread to report back.
    QHash<QString, BandwidthEvent> m_pendingThrottleEvents;
    // Emergency restore result waiting for the throttle worker's outcome, so
    // the user sees one report covering both the policy store and the shaping.
    EmergencyRestoreReport  m_restoreReport;
    bool                    m_restoreReportPending = false;
    bool                    m_reconcileScheduled = false;
    // The Policies dialog is open and waiting for a verification result. The
    // report arrives asynchronously while the dialog's event loop runs.
    QDialog                 *m_verifyDialog = nullptr;
    // Executables currently running in each activity group, kept from the last
    // group snapshot so a scheduled window can re-apply a group policy to them.
    QHash<QString, QStringList> m_runningGroupPaths;
    // NG-041: latest advisory foreground sample, kept for the classifier and
    // future recommendation/detail views. Never an enforcement input.
    Oasis::ForegroundSnapshot m_foregroundSnapshot;
    // NG-042/NG-043: the deterministic engine and the local-only feedback it
    // consults. Feedback changes future suggestions, never a policy.
    RecommendationEngine        m_recommendationEngine;
    RecommendationFeedbackStore m_recommendationFeedback;
    // NG-045/NG-046: the opt-in provider and coordinator behind the approval
    // flow. The assistant is loaded from persisted settings and stays disabled
    // until the user configures it.
    std::unique_ptr<OpenAiCompatibleProvider> m_aiProvider;
    AiAssistant                 m_aiAssistant;
    // NG-050: bounded local audit trail of detections, decisions, policy
    // changes, enforcement outcomes, and attribution changes. It is persisted
    // by the store itself; nothing here uploads it.
    AuditEventStore             m_auditStore;
};
