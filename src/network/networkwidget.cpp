/**
 * @file    networkwidget.cpp
 * @author  Oasis
 *
 * NetworkWidget core: construction, capture lifecycle and adapter control.
 * The process table lives in networkwidgettable.cpp, policy and throttle
 * actions in networkwidgetpolicies.cpp, and the dashboard/read-only
 * snapshots in networkwidgetinsights.cpp.
 */
#include "networkwidget_p.h"

namespace {

// NG-050: audit records use plain words so they stay readable after export.
QString enforcementStatusName(EnforcementResult::Status status)
{
    switch (status) {
    case EnforcementResult::Status::NotApplied: return QStringLiteral("not applied");
    case EnforcementResult::Status::Requested:  return QStringLiteral("requested");
    case EnforcementResult::Status::Applied:    return QStringLiteral("applied");
    case EnforcementResult::Status::Partial:    return QStringLiteral("partial");
    case EnforcementResult::Status::Failed:     return QStringLiteral("failed");
    }
    return QStringLiteral("unknown");
}

// OASIS_DEBUG_TIMING: one capture batch's work — model insert, destination
// resolution, and the icon lookups it queues.
Oasis::GuiTiming::Probe batchProbe("NetworkWidget::onPacketsCapturedBatch");

} // namespace

// ============================================================================
// ── Elevate Permissions to allow reading Process Paths (Crucial for Icons) ──
// ============================================================================
static void EnableDebugPrivilege() {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
        }
        CloseHandle(hToken);
    }
}

// ============================================================================
// ── NetworkWidget Implementation ──
// ============================================================================
NetworkWidget::NetworkWidget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::NetworkWidget)
{
    ui->setupUi(this);
    // ── Ensure Windows Firewall Inbound Rule for Application Traffic ──
    QString appPath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
    QProcess::execute("netsh", {"advfirewall", "firewall", "add", "rule", "name=Oasis", "dir=in", "action=allow", "program=" + appPath, "enable=yes"});

    qRegisterMetaType<QList<CapturedPacketInfo>>("QList<CapturedPacketInfo>");
    qRegisterMetaType<Oasis::ServicePidMap>("Oasis::ServicePidMap");
    qRegisterMetaType<QList<Oasis::ProcessGroup>>("QList<Oasis::ProcessGroup>");
    qRegisterMetaType<Oasis::ForegroundSnapshot>("Oasis::ForegroundSnapshot");

    m_model = new NetworkTreeModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    m_proxy->setRecursiveFilteringEnabled(true);

    // ── FIX: Set the custom SortRole for precise numeric sorting ──
    m_proxy->setSortRole(Qt::UserRole + 5);

    // A dynamic proxy re-sorts and re-filters on every dataChanged, and a tick
    // republishes every row whose numbers moved. The model publishes one
    // tickRefreshed at the end of the tick, so the tree is re-sorted and
    // re-filtered once per second instead of once per row.
    m_proxy->setDynamicSortFilter(false);
    connect(m_model, &NetworkTreeModel::tickRefreshed, this, [this]() {
        m_proxy->invalidate();
    });

    ui->treeView->setModel(m_proxy);
    ui->treeView->setUniformRowHeights(true);
    ui->treeView->setAnimated(true);
    ui->treeView->setExpandsOnDoubleClick(true);
    ui->treeView->setRootIsDecorated(true);
    ui->treeView->setAlternatingRowColors(false);
    ui->treeView->setIconSize(QSize(18, 18));
    ui->treeView->setIndentation(24);
    ui->treeView->setItemsExpandable(true);
    ui->treeView->setSortingEnabled(true);
    ui->treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    ui->treeView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->treeView, &QTreeView::customContextMenuRequested, this, &NetworkWidget::onTreeViewContextMenu);

    QHeaderView *hv = ui->treeView->header();
    hv->setMinimumSectionSize(50);
    // ResizeToContents measures rows to find the widest cell. Sampling a handful
    // is enough for a stable width and keeps five measured columns off the
    // per-tick path.
    hv->setResizeContentsPrecision(10);
    hv->setSectionResizeMode(0, QHeaderView::Interactive);       // COL_NAME
    hv->setSectionResizeMode(1, QHeaderView::ResizeToContents);  // COL_SRC
    hv->setSectionResizeMode(2, QHeaderView::ResizeToContents);  // COL_DST
    hv->setSectionResizeMode(3, QHeaderView::Interactive);       // COL_DOMAIN
    hv->setSectionResizeMode(4, QHeaderView::Interactive);       // COL_ACTIVITY
    hv->setSectionResizeMode(5, QHeaderView::ResizeToContents);  // COL_SERVICE
    hv->setSectionResizeMode(6, QHeaderView::Fixed);             // COL_RX
    hv->setSectionResizeMode(7, QHeaderView::Fixed);             // COL_TX
    hv->setSectionResizeMode(8, QHeaderView::ResizeToContents);  // COL_BYTES
    hv->setSectionResizeMode(9, QHeaderView::Stretch);           // COL_PKTS

    hv->resizeSection(0, 260); // COL_NAME
    hv->resizeSection(3, 200); // COL_DOMAIN
    hv->resizeSection(4, 170); // COL_ACTIVITY
    hv->resizeSection(6, 110); // COL_RX
    hv->resizeSection(7, 110); // COL_TX
    hv->setHighlightSections(false);
    hv->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);

    // NG-054: the first view answers "what is using the network, what controls
    // it, what is unexplained, and what is suggested" before the tree. The
    // panel renders; every action it offers routes back through this widget,
    // so it never becomes a second enforcement path.
    m_dashboard = new DashboardPanel(this);
    if (ui->rootLayout->indexOf(ui->treeView) >= 0) {
        ui->rootLayout->insertWidget(ui->rootLayout->indexOf(ui->treeView), m_dashboard);
    } else {
        ui->rootLayout->addWidget(m_dashboard);
    }
    connect(m_dashboard, &DashboardPanel::detailsRequested,
            this, &NetworkWidget::showApplicationDetails);
    connect(m_dashboard, &DashboardPanel::recommendationRequested, this,
            [this](quint32 pid, const QString &path, const QString &name) {
        showRecommendationFor(pid, name, path);
    });
    connect(m_dashboard, &DashboardPanel::policiesRequested, this,
            [this]() { ui->btnPolicies->click(); });

    m_monitor = new NetworkMonitor(this);
    // NG-031/NG-032: connection rows ask the destination correlator for the
    // remote endpoint's DNS and TLS SNI names; the lookup filters expired
    // records, so the UI never shows stale attribution.
    m_model->setDomainResolver([this](const QString &address) {
        return m_monitor->attributionsForAddress(address);
    });
    m_diagnostics = new DiagnosticsModel(this);
        m_bandwidthGuard = new BandwidthGuard(this);
    // NG-043: feedback the user gives a recommendation is read by the engine on
    // every later recommendation, so a verdict changes future local advice.
    m_recommendationEngine.setFeedbackStore(&m_recommendationFeedback);
    // NG-045/NG-046: AI is opt-in and disabled until provider settings are
    // saved; the adapter never applies a policy by itself.
    m_aiProvider = std::make_unique<OpenAiCompatibleProvider>();
    m_aiAssistant.setProvider(m_aiProvider.get());
    m_throttlePolicies = new ThrottlePolicyManager(this);
    // QoS changes run on a worker thread, so results arrive asynchronously.
    connect(m_throttlePolicies, &ThrottlePolicyManager::throttleApplied,
            this, &NetworkWidget::onThrottleApplied);
    connect(m_throttlePolicies, &ThrottlePolicyManager::throttleRemoved,
            this, &NetworkWidget::onThrottleRemoved);
    connect(m_throttlePolicies, &ThrottlePolicyManager::throttlesRestored,
            this, &NetworkWidget::onThrottlesRestored);
    connect(m_throttlePolicies, &ThrottlePolicyManager::downloadLimiterError,
            this, [this](const QString &message) {
                ui->lblStatus->setText("⚠ Download shaping: " + message);
            });
    // The WinDivert probe runs on the shaper thread; surface a result that
    // arrived before the connection above existed.
    const QString downloadStatus = m_throttlePolicies->downloadLimiterStatus();
    if (!downloadStatus.isEmpty())
        ui->lblStatus->setText("⚠ Download shaping: " + downloadStatus);
    m_firewall = new FirewallManager(this);
    m_firewall->initialize();
    // Shares the managers above, so a throttle result the worker posts reaches
    // this widget, and emergency restore can take back only automatic controls.
    m_enforcement = new EnforcementCoordinator(m_throttlePolicies, m_firewall, this);
    // NG-050: every enforcement outcome the coordinator reports becomes an
    // audit event, including a channel that could not act, so a policy's real
    // effect is explainable later.
    connect(m_enforcement, &EnforcementCoordinator::policyApplied, this,
            [this](const QString &policyId, const QString &executablePath,
                   const EnforcementResult &result) {
        AuditEvent event;
        event.type = AuditEvent::EventType::EnforcementResult;
        event.scope = executablePath;
        event.reason = QStringLiteral("policy channel reported an outcome");
        event.result = enforcementStatusName(result.status);
        if (result.status == EnforcementResult::Status::Failed)
            event.errorInfo = result.message;
        event.relatedPolicyId = policyId;
        event.details = QStringLiteral("channels: %1; upload limited: %2; download limited: %3")
                            .arg(result.channels.isEmpty()
                                     ? QStringLiteral("(none)")
                                     : result.channels)
                            .arg(result.uploadLimited ? QStringLiteral("yes")
                                                      : QStringLiteral("no"))
                            .arg(result.downloadLimited ? QStringLiteral("yes")
                                                        : QStringLiteral("no"));
        m_auditStore.append(event);

        // NG-051: a failed channel is the one outcome the user must not miss,
        // so it is surfaced even while packet activity is flooding alerts.
        if (result.status == EnforcementResult::Status::Failed) {
            emit enforcementFailed(policyId, executablePath,
                                   result.message.isEmpty()
                                       ? QStringLiteral("The enforcement channel reported a failure.")
                                       : result.message);
        }
    });

    // NG-023: evaluate the stored policies at startup (which is how a boundary
    // missed while the application was closed is recovered) and then on a
    // timer, so a window opening takes effect without a restart.
    m_policyScheduler = new PolicyScheduler(this);
    connect(m_policyScheduler, &PolicyScheduler::activationChanged,
            this, &NetworkWidget::onPolicyActivationChanged);
    m_policyScheduler->start();

    // NG-024: compare stored policies with what Windows enforces. The startup
    // pass runs only when the firewall is usable; a non-elevated session should
    // not warn on every launch. Group-scoped policies are re-applied from the
    // first group snapshot, and the Policies dialog verifies everything on
    // demand.
    m_policyReconciler = new PolicyReconciler(m_throttlePolicies, this);
    connect(m_policyReconciler, &PolicyReconciler::reconciliationFinished,
            this, &NetworkWidget::onPolicyReconciliationFinished);
    if (m_firewall->isInitialized()) {
        QTimer::singleShot(8000, this, [this]() {
            m_policyReconciler->requestReconciliation(m_runningGroupPaths);
        });
    }

        qRegisterMetaType<BandwidthEvent>("BandwidthEvent");
        connect(m_bandwidthGuard, &BandwidthGuard::sustainedBandwidthExceeded,
            this, &NetworkWidget::onBandwidthDetected, Qt::QueuedConnection);

    connect(m_monitor, &NetworkMonitor::packetsCapturedBatch, this, &NetworkWidget::onPacketsCapturedBatch, Qt::QueuedConnection);
    connect(m_monitor, &NetworkMonitor::speedUpdated, this, &NetworkWidget::onSpeedUpdated, Qt::QueuedConnection);
    connect(m_monitor, &NetworkMonitor::captureError, this, &NetworkWidget::onCaptureError, Qt::QueuedConnection);
    connect(m_monitor, &NetworkMonitor::captureStarted, this, &NetworkWidget::onCaptureStarted, Qt::QueuedConnection);
    connect(m_monitor, &NetworkMonitor::captureStopped, this, &NetworkWidget::onCaptureStopped, Qt::QueuedConnection);
    // NG-041: the foreground sample is advisory and stamped with its sample
    // time; it is kept for the classifier and future recommendation views.
    connect(m_monitor, &NetworkMonitor::foregroundSnapshotReady, this,
            [this](const Oasis::ForegroundSnapshot &snapshot) {
        m_foregroundSnapshot = snapshot;
    }, Qt::QueuedConnection);

    // NG-003: capture gaps are reported on the GUI thread so the support view
    // and export only ever touch the model from one thread.
    connect(m_monitor, &NetworkMonitor::captureGapDetected, this,
            [this](int dropped, int unresolved, int unknownDirection, const QString &adapter) {
        if (dropped > 0)
            m_diagnostics->reportDroppedPackets(dropped, adapter, QStringLiteral("capture loop"));
        if (unresolved > 0)
            m_diagnostics->reportUnresolvedPid(0, QStringLiteral("System Services / Network Overhead"),
                                              QStringLiteral("capture loop"));
        if (unknownDirection > 0)
            m_diagnostics->reportUnknownDirection(
                QStringLiteral("%1 packets with ambiguous direction").arg(unknownDirection),
                QStringLiteral("capture loop"));
    }, Qt::QueuedConnection);
    connect(m_monitor, &NetworkMonitor::staleMappingDetected, this,
            [this](quint32 pid, const QString &expected, const QString &actual) {
        m_diagnostics->reportStaleMapping(pid, expected, actual, QStringLiteral("connection cache"));
    }, Qt::QueuedConnection);
    connect(m_monitor, &NetworkMonitor::adapterDiagnostic, this,
            [this](const QString &adapter, const QString &reason) {
        m_diagnostics->reportAdapterUnavailable(adapter, reason);
    }, Qt::QueuedConnection);
    connect(m_monitor, &NetworkMonitor::identityResolutionFailed, this,
            [this](quint32 pid, const QString &status, const QString &message) {
        m_diagnostics->reportUnresolvedPid(pid, status, message);
    }, Qt::QueuedConnection);

    // NG-012: service rows come from a separate snapshot; without it the tree
    // still shows service-hosted traffic under the host process.
    connect(m_monitor, &NetworkMonitor::serviceSnapshotReady, m_model,
            &NetworkTreeModel::applyServiceSnapshot, Qt::QueuedConnection);
    connect(m_monitor, &NetworkMonitor::serviceLookupFailed, this,
            [this](const QString &reason) {
        m_diagnostics->reportServiceLookupFailed(0, QString(), reason);
    }, Qt::QueuedConnection);

    // NG-013: a recycled PID is a security-relevant event; cached attributions
    // were already dropped by the monitor before this arrives.
    connect(m_monitor, &NetworkMonitor::pidReuseDetected, this,
            [this](quint32 pid, const QString &previousExe, const QString &currentExe,
                   qint64 previousStartMs, qint64 currentStartMs) {
        m_diagnostics->reportPidReuse(pid, previousExe, currentExe,
                                     previousStartMs, currentStartMs);
    }, Qt::QueuedConnection);

    // NG-025: a group's live membership changes when an updater or worker exits
    // and a replacement appears with traffic. Re-apply that group's stored
    // policies to whatever is running now; the coordinator skips pairs it has
    // already applied, so a PID-only refresh does not churn firewall or QoS.
    connect(m_monitor, &NetworkMonitor::groupSnapshotReady, this,
            [this](const QList<Oasis::ProcessGroup> &groups) {
        // Remember what is running in each group: scheduled activation needs the
        // paths later, when no group snapshot is being delivered.
        m_runningGroupPaths.clear();
        for (const Oasis::ProcessGroup &group : groups) {
            QStringList running;
            for (const Oasis::GroupMember &member : group.members) {
                if (member.type == Oasis::GroupMemberType::ExecutablePath &&
                    member.observedPid != 0) {
                    running << member.value;
                }
            }
            if (!running.isEmpty()) m_runningGroupPaths.insert(group.id, running);
        }

        // Only group policies that are in force now: a policy outside its
        // scheduled window must not be re-applied because a member appeared.
        const QList<NetworkPolicy> policies = PolicyStore::loadPolicies();
        const QDateTime now = QDateTime::currentDateTime();
        QList<NetworkPolicy> activeGroupPolicies;
        for (const NetworkPolicy &policy : policies) {
            if (policy.scope.trimmed().compare(QStringLiteral("group"), Qt::CaseInsensitive) != 0)
                continue;
            if (policyActivationAt(policy, now) != PolicyActivationState::Active)
                continue;
            activeGroupPolicies << policy;
        }
        if (activeGroupPolicies.isEmpty()) return;

        for (auto it = m_runningGroupPaths.constBegin();
             it != m_runningGroupPaths.constEnd(); ++it) {
            const QList<EnforcementResult> reapplied =
                m_enforcement->reapplyGroupPolicies(it.key(), it.value(),
                                                    activeGroupPolicies);
            // NG-050: a replacement process that inherited a durable group
            // policy is exactly the "respawn caught" event the Activity feed
            // explains. Only newly applied pairs are reported, so a refresh
            // does not repeat the same card.
            for (const EnforcementResult &result : reapplied) {
                AuditEvent audit;
                audit.type = AuditEvent::EventType::ProcessGroupMembershipChange;
                audit.scope = result.executablePath;
                audit.reason = QStringLiteral(
                    "durable policy re-applied to a respawned process");
                audit.result = enforcementStatusName(result.status);
                audit.relatedPolicyId = result.policyId;
                audit.details = QStringLiteral("group: %1; channels: %2")
                                    .arg(it.key(), result.channels);
                if (result.status == EnforcementResult::Status::Failed)
                    audit.errorInfo = result.message;
                m_auditStore.append(audit);
            }
        }
    }, Qt::QueuedConnection);

    connect(ui->cmbAdapter, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &NetworkWidget::onAdapterChanged);
    connect(ui->btnStartStop, &QPushButton::clicked, this, &NetworkWidget::onStartStop);
    connect(ui->btnClear, &QPushButton::clicked, this, &NetworkWidget::onClearTable);
    connect(ui->btnExpandAll, &QPushButton::clicked, this, &NetworkWidget::onExpandAll);
    // The list edits and deletes stored policies; after a change the scheduler
    // must see the new set and the re-application memory must be forgotten so a
    // later group snapshot does not assume the old pairs are still applied.
    connect(ui->btnPolicies, &QPushButton::clicked, this, [this]() {
        PolicyListDialog dlg(this);
        connect(&dlg, &PolicyListDialog::verifyRequested, this, [this, &dlg]() {
            if (m_policyReconciler->isBusy()) {
                QMessageBox::information(&dlg, QStringLiteral("Verify policies"),
                                         QStringLiteral("A policy verification is already running."));
                return;
            }
            // The pass runs on the reconciler's thread; the report is shown by
            // onPolicyReconciliationFinished while this dialog's loop runs.
            m_verifyDialog = &dlg;
            m_policyReconciler->requestReconciliation(m_runningGroupPaths);
        });
        dlg.exec();
        m_verifyDialog = nullptr;
        if (!dlg.changed()) return;
        AuditEvent audit;
        audit.type = AuditEvent::EventType::PolicyChange;
        audit.scope = QStringLiteral("policy store");
        audit.reason = QStringLiteral("user edited or deleted stored policies");
        audit.result = QStringLiteral("saved");
        m_auditStore.append(audit);
        m_enforcement->forgetReappliedPolicies();
        m_policyScheduler->evaluateNow();
        schedulePolicyReconciliation();
        // NG-054: the controls section lists what is in force, so a policy edit
        // is visible in the first view without waiting for the next beat.
        refreshDashboard();
        ui->lblStatus->setText(QStringLiteral("Policies updated."));
    });
    connect(ui->btnLimits, &QPushButton::clicked, this, [this]() {
        BandwidthLimitsDialog dlg(m_throttlePolicies, this);
        dlg.exec();
    });
    connect(ui->edtFilter, &QLineEdit::textChanged, this, &NetworkWidget::onFilterChanged);

    // ── Auto-refresh adapters when the ComboBox dropdown is opened ──
    ui->cmbAdapter->installEventFilter(this);

    populateAdapterCombo();
}

NetworkWidget::~NetworkWidget()
{
    m_monitor->stopCapture();
    m_monitor->wait(1500);
    delete m_throttlePolicies;
    delete ui;
}


void NetworkWidget::autoStart() {
    if (m_adapters.isEmpty()) populateAdapterCombo();
    if (m_adapters.isEmpty()) return;
    ui->cmbAdapter->setCurrentIndex(0); // Smart Auto-Detect
    onAdapterChanged(0);
    m_monitor->startCapture();
}

void NetworkWidget::startMonitoring() {
    if (m_capturing) return;
    if (m_adapters.isEmpty()) populateAdapterCombo();
    if (m_adapters.isEmpty()) {
        ui->lblStatus->setText("⚠ No network adapter available.");
        return;
    }
    m_monitor->startCapture();
}
void NetworkWidget::populateAdapterCombo() {
    QString prevIP;
    if (ui->cmbAdapter->currentIndex() >= 0)
        prevIP = ui->cmbAdapter->currentData().toString();

    m_adapters = NetworkMonitor::enumerateAdapters();
    ui->cmbAdapter->blockSignals(true);
    ui->cmbAdapter->clear();

    // ── Smart Auto-Detect option at Index 0 ──
    ui->cmbAdapter->addItem("⚡ Smart Auto-Detect (Auto)", "AUTO");

    for (const auto &ai : m_adapters)
        ui->cmbAdapter->addItem(ai.description, ai.ip);
    ui->cmbAdapter->blockSignals(false);

    int restoreIdx = 0; // Default to Auto
    if (!prevIP.isEmpty() && prevIP != "AUTO") {
        for (int i = 0; i < ui->cmbAdapter->count(); ++i) {
            if (ui->cmbAdapter->itemData(i).toString() == prevIP) { restoreIdx = i; break; }
        }
    }

    ui->cmbAdapter->setCurrentIndex(restoreIdx);
    onAdapterChanged(restoreIdx);
}

QString NetworkWidget::activeAdapterDescription() const
{
    if (!ui || !ui->cmbAdapter)
        return QString();
    return ui->cmbAdapter->currentText();
}

void NetworkWidget::selectAdapterByIPOrAuto(const QString &ipOrAuto)
{
    for (int i = 0; i < ui->cmbAdapter->count(); ++i) {
        if (ui->cmbAdapter->itemData(i).toString() == ipOrAuto) {
            ui->cmbAdapter->setCurrentIndex(i);
            break;
        }
    }
}

// ── Event filter: refresh adapters when ComboBox dropdown is opened ──
bool NetworkWidget::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == ui->cmbAdapter && event->type() == QEvent::MouseButtonPress) {
        populateAdapterCombo();
    }
    return QWidget::eventFilter(obj, event);
}

void NetworkWidget::onAdapterChanged(int idx) {
    if (idx < 0 || idx >= ui->cmbAdapter->count()) return;

    QString selectedData = ui->cmbAdapter->itemData(idx).toString();
    QString targetIP;

    if (selectedData == "AUTO") {
        int bestIdx = NetworkMonitor::recommendedAdapterIndex(m_adapters);
        if (bestIdx >= 0 && bestIdx < m_adapters.size()) {
            targetIP = m_adapters[bestIdx].ip;
            ui->lblStatus->setText("⚡ Auto-Detecting: " + m_adapters[bestIdx].description);
        }
    } else {
        targetIP = selectedData;
        ui->lblStatus->setText("Selected Adapter: " + ui->cmbAdapter->currentText());
    }

    if (!targetIP.isEmpty()) {
        bool wasCapturing = m_capturing;
        if (wasCapturing) {
            m_monitor->stopCapture();
            m_monitor->wait(1000);
        }
        m_monitor->setAdapterIP(targetIP);
        if (wasCapturing) {
            m_monitor->startCapture();
        }
    }
}

void NetworkWidget::onStartStop()
{
    if (!m_capturing) {
        if (m_adapters.isEmpty()) return;
        m_monitor->startCapture();
    } else {
        // ── Force stop: try graceful first, then terminate ──
        m_monitor->stopCapture();
        if (!m_monitor->wait(2000)) {
            // Thread didn't stop in 2s → force terminate
            m_monitor->terminate();
            m_monitor->wait(1000);
        }
        onCaptureStopped();
    }
}

void NetworkWidget::onCaptureStarted() {
    m_capturing = true;
    ui->btnStartStop->setText("⏹  Stop");
    ui->cmbAdapter->setEnabled(false);
    ui->lblStatus->setText("● Live capture…");
    refreshDashboard();
}
void NetworkWidget::onCaptureStopped() {
    m_capturing = false;
    ui->btnStartStop->setText("▶  Start");
    ui->cmbAdapter->setEnabled(true);
    ui->lblStatus->setText("Stopped.");
    refreshDashboard();
}

void NetworkWidget::onPacketsCapturedBatch(const QList<CapturedPacketInfo> &batch)
{
    Oasis::GuiTiming::Scope timing(batchProbe);
    m_bandwidthGuard->observe(batch);
    m_model->addPackets(batch);
    // Destination names come from the correlator the capture thread writes
    // through, so resolving them holds a lock that thread needs. This ran on
    // every batch; once per second keeps the Domain column current without
    // taking that lock several times a second. The explicit refresh
    // (refreshConnectionEvidence) stays unthrottled.
    constexpr qint64 kDomainRefreshMs = 900;
    if (!m_domainRefreshClock.isValid()
        || m_domainRefreshClock.elapsed() >= kDomainRefreshMs) {
        m_domainRefreshClock.start();
        m_model->refreshDomains();
    }
    m_totalPkts += batch.size();
    ui->lblPackets->setText(QString::number(m_totalPkts));

    for (const auto &info : batch) {
        if (!info.proc.isEmpty() && !m_iconCache.contains(info.proc)) {
            if (info.pid == 4 || info.pid == 0 || info.isService) {
                QIcon svcIcon = style()->standardIcon(QStyle::SP_ComputerIcon);
                m_iconCache.insert(info.proc, svcIcon);
                m_model->setProcessIcon(info.proc, svcIcon);
            } else {
                m_iconCache.insert(info.proc, QIcon());
                QMetaObject::invokeMethod(this, [this, pid = info.pid, proc = info.proc]() {
                    QIcon icon = getIconByPid(pid, proc);
                    if (!icon.isNull()) m_model->setProcessIcon(proc, icon);
                }, Qt::QueuedConnection);
            }
        }
    }
}

void NetworkWidget::onSpeedUpdated(quint64 rxBps, quint64 txBps) {
    ui->lblRxVal->setText(NetworkTreeModel::formatSpeed(rxBps));
    ui->lblTxVal->setText(NetworkTreeModel::formatSpeed(txBps));
    emit speedUpdated(rxBps, txBps);
    // The panel follows the same once-a-second beat as the counters, so it never
    // needs a timer of its own.
    refreshDashboard();
}


// void NetworkWidget::onCaptureError(const QString &msg) { ui->lblStatus->setText("⚠ " + msg); QMessageBox::critical(this, "Capture Error", msg); onCaptureStopped(); }

void NetworkWidget::onCaptureError(const QString &msg) {
    ui->lblStatus->setText("⚠ " + msg);
    onCaptureStopped();
    // ── If there are low-level socket bind errors, don't show annoying popups.
    // Force a complete app restart silently to clean up lingering raw sockets.
    if (msg.contains("bind", Qt::CaseInsensitive)) {
        QProcess::startDetached(QCoreApplication::applicationFilePath(), QStringList());
        QCoreApplication::quit();
    }
}
