/**
 * @file    networkwidget.h
 * @author  Oasis
 */
#pragma once

#include <QHash>
#include <QSet>
#include <QWidget>
#include <QSortFilterProxyModel>
#include <QDialog>
#include <QEvent>
#include <QElapsedTimer>
#include <memory>
#include "networkmonitor.h"
#include "networkmodel.h"
#include "bandwidthguard.h"
#include "datasavercache.h"
#include "datasaverdecision.h"
#include "datasaverenforcement.h"
#include "datasavermode.h"
#include "flowobservation.h"
#include "volumemilestone.h"
#include "throttlepolicymanager.h"
#include "diagnostics.h"
#include "enforcementrestore.h"
#include "policyschedule.h"
#include "policyreconcile.h"
#include "auditeventstore.h"
#include "applicationdetail.h"
#include "applicationsnapshot.h"
#include "connectionsnapshot.h"
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
    void setDataSaverMode(DataSaverMode::Mode mode);
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
    // Screen — Policies: a write through this widget changed the stored set, so
    // a host screen can re-read it instead of guessing what happened.
    void policiesChanged();
    // Screen — Policies: one reconciliation pass finished, whether it was asked
    // for (Verify) or triggered by a policy change.
    void policyReconciliationFinished(const ReconciliationReport &report);
    // DS-004: a volume milestone was accepted after dedupe. This is an
    // evaluation trigger only; nothing is enforced from this signal.
    void flowMilestoneReached(const MilestoneCrossing &crossing);
    // DS-008: the resolver produced one validated decision for a milestone
    // crossing, using the DS-007 evidence cache. DS-009 applies it; this widget
    // does not enforce from the signal.
    void dataSaverDecisionResolved(const DataSaverDecision::PolicyDecision &decision);

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
    // Screen 03: one plain row per process, including the publisher, activity
    // state and policy state the first-view summary does not carry. Read from
    // the last beat, so the Applications page adds no capture work of its own.
    QList<Applications::Snapshot> applicationSnapshots() const;
    // Screen 05: every observed socket grouped by owning process and
    // destination. The page only renders this snapshot; it never reads the
    // capture model or re-resolves evidence itself.
    QList<Connections::Row> connectionGroups() const;
    // Re-resolve destination names and rebuild the one-second beat, so a manual
    // refresh shows current evidence instead of a cached answer.
    void refreshConnectionEvidence();
    // Screen 03 details drawer: read on open, so static executable metadata is
    // not resolved for every row on every beat.
    Applications::Details applicationDetails(quint32 pid, const QString &executablePath,
                                             const QString &processName = QString());
    // The shell icon for an executable path, resolved once and cached by
    // normalized path. A target that is not a real file (a service name, a
    // group id) resolves to the generic application icon. Used by screens that
    // list stored policies, whose executables are often not running.
    QIcon executableIcon(const QString &executablePath);
    bool isCapturing() const { return m_capturing; }
    // The two enforceable modes from the automation contract (DS-001). Loaded
    // from versioned settings at construction; the legacy Monitor state no
    // longer exists and a stored one migrates to Off.
    DataSaverMode::Mode dataSaverMode() const { return m_dataSaverMode; }
    // DS-003: the current canonical evaluation inputs, aggregated from the
    // capture batch. They are never persisted; DS-004 consumes them at
    // milestone crossings.
    QList<FlowObservation> currentFlowObservations() const;
    // Normalized paths the throttle manager is currently shaping, so a status
    // reader reports what is actually limited rather than what was requested.
    QStringList throttledPaths() const { return m_throttlePolicies ? m_throttlePolicies->activePaths() : QStringList(); }
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
    // Screen 03: "Manage traffic" opens the existing bandwidth-limit flow for
    // the executable, offering removal when a limit is already in force.
    void showTrafficControlsFor(quint32 pid, const QString &executablePath,
                                const QString &processName = QString());
    // Screen 03 rule control: Allow and Block drive the firewall directly;
    // Ask stores an advisory per-path policy so the choice survives a restart.
    void applyApplicationRule(quint32 pid, const QString &executablePath,
                              const QString &processName, const QString &rule);
    // Activity actions route through the existing policy editor and list, so the
    // feed never becomes a second enforcement path.
    void showPolicyEditorFor(quint32 pid, const QString &executablePath,
                             const QString &processName = QString());
    void showPolicies();

    // Screen — Policies (docs/POLICIES_PAGE_PLAN.md, Phase 4). Every write the
    // page performs goes through one of these, so the store, audit log,
    // scheduler and reconciliation stay the only path a policy change takes.
    void createPolicy();
    // Compares the stored policies with what Windows enforces. A session whose
    // firewall is unavailable gets a failure report rather than a silent no-op.
    void verifyPolicies();
    // Enables or pauses one stored policy. Emits policiesChanged() even when the
    // write fails, so a screen renders the state that was actually saved.
    void setPolicyEnabled(const QString &policyId, bool enabled);
    // Confirms, then deletes one stored policy and schedules the withdrawal of
    // the rules attributed to it.
    void deletePolicy(const QString &policyId);
    // Opens the policy editor for one stored policy and saves the result through
    // the same store/scheduler/reconciliation path as every other write, so the
    // Policies screen and the legacy list do not each own an edit path. Returns
    // true when the policy was saved; `dialogParent` only selects the window the
    // editor is centred on. Scopes the editor cannot represent are refused with
    // an explanation instead of being silently narrowed.
    bool editPolicy(const QString &policyId, QWidget *dialogParent = nullptr);
    // Most recent DNS/SNI name observed for the process, when one exists. The
    // out parameter receives its plain confidence label (Confirmed/Likely/...).
    QString primaryDestinationForPid(quint32 pid,
                                     QString *confidence = nullptr) const;

private:
    // DS-003: converts one capture batch into bounded FlowCaptureSamples. The
    // conversion is CPU-only and never touches disk, HTTP, AI, or a dialog.
    void ingestFlowObservations(const QList<CapturedPacketInfo> &batch);
    void populateAdapterCombo();
    // Queues one reconciliation instead of running it inline, so a burst of
    // activation changes or a dialog close does not enumerate rules per event.
    void schedulePolicyReconciliation();
    // NG-054: rebuilds the first-view panel from the current rows, in-force
    // policies, and the recommendations for the current top consumers.
    void refreshDashboard();
    QIcon getIconByPid(quint32 pid, const QString &procName);
    // The shell's generic application icon, for rows whose executable icon has
    // not been resolved (or that have no executable of their own).
    QIcon genericExecutableIcon() const;
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
    // DS-008: resolve one accepted milestone crossing through the evidence
    // cache and route the result to DS-009 enforcement.
    void evaluateDataSaverCrossing(const FlowObservation &observation,
                                   const MilestoneCrossing &crossing);
    // DS-009: audit an automatic-control outcome and surface a failure.
    void recordEnforcementOutcome(const DataSaverEnforcement::EnforcementOutcome &outcome);
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
    DataSaverMode::Mode     m_dataSaverMode = DataSaverMode::Mode::Off;
    // Batches arrive several times a second; the destination resolver behind it
    // shares a mutex with the capture thread, so it runs at most once per
    // kDomainRefreshMs from the batch path.
    QElapsedTimer           m_domainRefreshClock;
    // DS-003: flow observations are monotonically timed and bounded, so a wall
    // clock adjustment cannot stretch a duration or a rate window.
    QElapsedTimer           m_flowClock;
    FlowObservationBuilder  m_flowObservationBuilder;
    VolumeMilestoneEvaluator m_milestoneEvaluator;
    // DS-007/DS-008: the evidence cache is keyed by metadata only, loaded once
    // at start, and consulted/populated on accepted milestone crossings.
    DataSaverDecision::DecisionResolver m_decisionResolver;
    DecisionCache m_decisionCache;
    CacheContext m_decisionCacheContext;
    // DS-009: the ownership layer over the shipped throttle and firewall
    // channels. Only controls recorded here are ever withdrawn.
    DataSaverEnforcer m_dataSaverEnforcer;
    DataSaverEnforcementBackend *m_dataSaverEnforcementBackend = nullptr;
    // DS-009: a foreground-change lease ends when this pid changes.
    quint32 m_lastDataSaverForegroundPid = 0;

    QHash<QString, QIcon>   m_iconCache;
    // Normalized executable path -> shell icon. Kept apart from m_iconCache,
    // which is keyed by process name and filled while processes are captured.
    QHash<QString, QIcon>   m_executableIconCache;
    mutable QIcon           m_genericExecutableIcon;
    // NG-054: paths resolved once per (pid, start time) for the dashboard, so a
    // refresh does not open a process handle for every row every second.
    QHash<QString, QString> m_dashboardPathCache;
    // Last published first-view summary, readable by a host screen between beats.
    TopConsumers::Summary m_dashboardSummary;
    // Auto-throttle alerts waiting for the worker thread to report back.
    QHash<QString, BandwidthEvent> m_pendingThrottleEvents;
    // Paths the user explicitly limited, so their result is confirmed with a
    // dialog. Anything else that applies a limit is background work and reports
    // through the status line and the audit feed instead.
    QSet<QString> m_pendingManualThrottles;
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
