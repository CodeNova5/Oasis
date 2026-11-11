/**
 * @file    networkwidget.h
 * @author  Ali Sakkaf
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
#include "attribution/recommendationengine.h"
#include "attribution/recommendationfeedback.h"
#include "attribution/aiprovider.h"

class FirewallManager;
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
    void bandwidthAlert(const BandwidthEvent &event);

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
    DiagnosticsModel *diagnosticsModel() const { return m_diagnostics; }
    // NG-036: attribution privacy controls and the history they bound.
    NetworkMonitor *networkMonitor() const { return m_monitor; }
    // NG-041: the latest foreground sample. It is advisory, and its
    // associationFor() refuses a sample older than its freshness window.
    NetGuard::ForegroundSnapshot foregroundSnapshot() const { return m_foregroundSnapshot; }
    // NG-045/NG-046: re-read the provider settings saved from the Settings tab
    // so the approval dialog uses them without a restart.
    void reloadAiProviderSettings();

private:
    void populateAdapterCombo();
    // Queues one reconciliation instead of running it inline, so a burst of
    // activation changes or a dialog close does not enumerate rules per event.
    void schedulePolicyReconciliation();
    QIcon getIconByPid(quint32 pid, const QString &procName);
    void requestThrottle(quint32 pid, const QString &procName);
    // Evidence snapshot for the recommendation and approval views, taken while
    // the context menu's row is still valid.
    RecommendationContext recommendationContextFor(const ActivityQuery &query,
                                                    quint32 pid,
                                                    const QString &processName) const;

    Ui::NetworkWidget       *ui = nullptr;
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
    NetGuard::ForegroundSnapshot m_foregroundSnapshot;
    // NG-042/NG-043: the deterministic engine and the local-only feedback it
    // consults. Feedback changes future suggestions, never a policy.
    RecommendationEngine        m_recommendationEngine;
    RecommendationFeedbackStore m_recommendationFeedback;
    // NG-045/NG-046: the opt-in provider and coordinator behind the approval
    // flow. The assistant is loaded from persisted settings and stays disabled
    // until the user configures it.
    std::unique_ptr<OpenAiCompatibleProvider> m_aiProvider;
    AiAssistant                 m_aiAssistant;
};
