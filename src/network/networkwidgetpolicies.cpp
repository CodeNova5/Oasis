/**
 * @file    networkwidgetpolicies.cpp
 * @author  Oasis
 *
 * Policy and throttle actions for NetworkWidget: target resolution, the
 * policy editor/approval flows, firewall rules, bandwidth limits, the data
 * saver, and scheduled-window reconciliation.
 */
#include "networkwidget_p.h"

#include <QSettings>

namespace {

static QString bandwidthUsageText(const BandwidthEvent &event)
{
    return QString("%1 used %2 in this capture session")
        .arg(event.processName)
        .arg(NetworkTreeModel::formatBytes(event.totalBytes));
}

// NG-043: an explicit user policy already covering the row means the
// recommendation view must not suggest something the user has decided.
static bool explicitPolicyCovers(const ActivityQuery &query, quint32 pid)
{
    const QDateTime now = QDateTime::currentDateTimeUtc();

    for (const NetworkPolicy &policy : PolicyStore::loadPolicies()) {
        if (!policy.enabled) continue;
        if (policy.expiration.isValid() && policy.expiration <= now) continue;
        // NG-052: target matching lives in the detail view's pure rules, so the
        // recommendation and detail views cannot disagree about coverage.
        if (ApplicationDetail::policyTargets(policy, query, pid)) return true;
    }
    return false;
}

// Scopes the policy editor can represent. A stored policy in any other scope
// has no field the form could populate, so editing it would silently rewrite
// its scope; it is refused with an explanation instead.
static bool editorSupportsScope(const QString &key)
{
    const QString scope = key.trimmed().toLower();
    return scope == QLatin1String("pid") || scope == QLatin1String("path") ||
           scope == QLatin1String("executable") || scope == QLatin1String("publisher") ||
           scope == QLatin1String("service") || scope == QLatin1String("group");
}

// NG-052: the identity and path searches overlap (an event may be stored with
// both), so identical records are folded before the view sees them.
static QList<AuditEvent> mergeAuditEvents(const QList<AuditEvent> &first,
                                          const QList<AuditEvent> &second)
{
    QList<AuditEvent> merged = first;
    for (const AuditEvent &event : second) {
        bool duplicate = false;
        for (const AuditEvent &existing : merged) {
            if (existing.timestamp == event.timestamp && existing.type == event.type
                && existing.reason == event.reason && existing.result == event.result) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) merged.append(event);
    }
    return merged;
}

} // namespace

// NG-042/NG-046: the evidence snapshot shared by the recommendation and
// approval views. Callers add the classification they captured with the row.
void NetworkWidget::reloadAiProviderSettings()
{
    m_aiAssistant.setSettings(AiProviderSettingsStore().load());
}

RecommendationContext NetworkWidget::recommendationContextFor(const ActivityQuery &query,
                                                             quint32 pid,
                                                             const QString &processName) const
{
    RecommendationContext context;
    context.observation = query;
    context.bytesPerSecond = query.bytesPerSecond;
    context.foreground = query.foreground;
    context.exempt = m_bandwidthGuard->isExempt(processName);
    context.explicitPolicyCovers = explicitPolicyCovers(query, pid);
    return context;
}

// NG-052: the row's own evidence when the process is still in the model. A
// notification can arrive after the process exited, in which case the caller's
// path and name are all there is.
ActivityQuery NetworkWidget::queryAndActivityFor(quint32 pid, const QString &processName,
                                                 const QString &executablePath,
                                                 ActivityClassification *activity) const
{
    ActivityQuery query;
    const int row = (m_model && pid != 0) ? m_model->rowForPid(pid) : -1;
    if (row >= 0) {
        query = m_model->activityQueryForRow(row);
        if (activity) *activity = m_model->activityForRow(row);
    }
    if (query.executableName.trimmed().isEmpty()) query.executableName = processName;
    if (query.executablePath.trimmed().isEmpty()) query.executablePath = executablePath;
    return query;
}

PolicyTarget NetworkWidget::policyTargetFor(quint32 pid, const QString &processName,
                                            const QString &executablePath,
                                            const QString &groupId) const
{
    PolicyTarget target;
    target.pid = pid;
    target.processName = processName;
    target.executablePath = executablePath;

    // Prefer the passed group; otherwise find the group whose membership
    // contains this executable, which is how a notification without a model row
    // still gets a group-scoped option.
    QString effectiveGroup = groupId;
    if (effectiveGroup.isEmpty() && m_monitor && !executablePath.isEmpty()) {
        for (const Oasis::ProcessGroup &group : m_monitor->processGroups()) {
            if (group.contains(Oasis::GroupMemberType::ExecutablePath, executablePath)) {
                effectiveGroup = group.id;
                break;
            }
        }
    }
    target.groupId = effectiveGroup;

    if (!effectiveGroup.isEmpty() && m_monitor) {
        for (const Oasis::ProcessGroup &group : m_monitor->processGroups()) {
            if (group.id != effectiveGroup) continue;
            target.groupName = group.name;
            for (const Oasis::GroupMember &member : group.members) {
                if (member.type == Oasis::GroupMemberType::ExecutablePath &&
                    member.value.compare(executablePath, Qt::CaseInsensitive) == 0) {
                    target.publisher = member.publisher;
                    if (target.processName.isEmpty() && !member.displayName.isEmpty())
                        target.processName = member.displayName;
                } else if (member.type == Oasis::GroupMemberType::Service &&
                           target.serviceName.isEmpty()) {
                    target.serviceName = member.value;
                }
            }
            break;
        }
    }

    return target;
}

void NetworkWidget::createPolicyForTarget(const PolicyTarget &target)
{
    PolicyEditorDialog dlg(target, this);
    if (dlg.exec() != QDialog::Accepted) return;

    QList<NetworkPolicy> policies = PolicyStore::loadPolicies();
    policies.append(dlg.policy());
    if (!PolicyStore::savePolicies(policies)) {
        QMessageBox::warning(this, QStringLiteral("Create policy"),
                             QStringLiteral("The policy could not be saved."));
        return;
    }

    AuditEvent audit;
    audit.type = AuditEvent::EventType::PolicyChange;
    audit.scope = dlg.policy().scope;
    audit.reason = QStringLiteral("user created a policy");
    audit.result = QStringLiteral("saved");
    audit.relatedPolicyId = dlg.policy().id;
    audit.details = dlg.policy().description;
    m_auditStore.append(audit);

    ui->lblStatus->setText(QStringLiteral("Policy saved."));
    // The scheduler has not seen this policy yet, so this counts as an
    // activation change and applies it now when it is in force.
    m_policyScheduler->evaluateNow();
    emit policiesChanged();
}

void NetworkWidget::createPolicy()
{
    // No prefill: the editor's target field is where the user types or pastes
    // the executable path. The Policies page uses this, its own rows already
    // describe the policies that exist.
    createPolicyForTarget(PolicyTarget());
}

void NetworkWidget::verifyPolicies()
{
    if (!m_policyReconciler)
        return;

    if (!m_firewall || !m_firewall->isInitialized()) {
        // Verification needs the COM rule collection. Reporting the failure is
        // better than a button that appears to do nothing.
        ReconciliationReport report;
        ++report.failed;
        ReconciliationAction action;
        action.kind = ReconciliationAction::Kind::Report;
        action.message = QStringLiteral(
            "Windows Firewall is not available in this session, so the stored "
            "policies were not verified. Run Oasis elevated and try again.");
        report.actions << action;
        ui->lblStatus->setText(report.summary());
        emit policyReconciliationFinished(report);
        return;
    }

    ui->lblStatus->setText(QStringLiteral("Verifying policy rules..."));
    m_policyReconciler->requestReconciliation(m_runningGroupPaths);
}

void NetworkWidget::setPolicyEnabled(const QString &policyId, bool enabled)
{
    if (policyId.isEmpty())
        return;

    QList<NetworkPolicy> policies = PolicyStore::loadPolicies();
    int index = -1;
    for (int i = 0; i < policies.size(); ++i) {
        if (policies.at(i).id == policyId) {
            index = i;
            break;
        }
    }
    if (index < 0) {
        emit policiesChanged();
        return;
    }
    if (policies.at(index).enabled == enabled) {
        // Already in that state (a stale row, most likely); re-read so the
        // screen shows what the store actually holds.
        emit policiesChanged();
        return;
    }

    policies[index].enabled = enabled;
    if (!PolicyStore::savePolicies(policies)) {
        QMessageBox::warning(this, QStringLiteral("Policies"),
                             QStringLiteral("The policy could not be %1.")
                                 .arg(enabled ? QStringLiteral("enabled")
                                              : QStringLiteral("paused")));
        emit policiesChanged();
        return;
    }

    const NetworkPolicy &policy = policies.at(index);
    AuditEvent audit;
    audit.type = AuditEvent::EventType::PolicyChange;
    audit.scope = policy.targetId;
    audit.reason = enabled ? QStringLiteral("user enabled a policy")
                           : QStringLiteral("user paused a policy");
    audit.result = QStringLiteral("saved");
    audit.relatedPolicyId = policy.id;
    audit.details = policy.description;
    m_auditStore.append(audit);

    ui->lblStatus->setText(enabled ? QStringLiteral("Policy enabled.")
                                   : QStringLiteral("Policy paused."));
    // Enabling applies the policy at once; pausing reports a left state, which
    // is what withdraws the rules attributed to it.
    m_policyScheduler->evaluateNow();
    schedulePolicyReconciliation();
    emit policiesChanged();
}

void NetworkWidget::deletePolicy(const QString &policyId)
{
    if (policyId.isEmpty())
        return;

    QList<NetworkPolicy> policies = PolicyStore::loadPolicies();
    int index = -1;
    for (int i = 0; i < policies.size(); ++i) {
        if (policies.at(i).id == policyId) {
            index = i;
            break;
        }
    }
    if (index < 0) {
        emit policiesChanged();
        return;
    }

    const NetworkPolicy policy = policies.at(index);
    const QString target = policy.targetId.trimmed().isEmpty()
        ? policy.id
        : policy.targetId;
    const QMessageBox::StandardButton answer = QMessageBox::question(
        this, QStringLiteral("Delete policy"),
        QStringLiteral("Delete this policy for %1?\n\nThe rules attributed to it "
                       "are withdrawn. This cannot be undone.")
            .arg(target),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes)
        return;

    policies.removeAt(index);
    if (!PolicyStore::savePolicies(policies)) {
        QMessageBox::warning(this, QStringLiteral("Policies"),
                             QStringLiteral("The policy could not be deleted."));
        emit policiesChanged();
        return;
    }

    AuditEvent audit;
    audit.type = AuditEvent::EventType::PolicyChange;
    audit.scope = policy.targetId;
    audit.reason = QStringLiteral("user deleted a policy");
    audit.result = QStringLiteral("removed");
    audit.relatedPolicyId = policy.id;
    audit.details = policy.description;
    m_auditStore.append(audit);

    ui->lblStatus->setText(QStringLiteral("Policy deleted."));
    m_policyScheduler->evaluateNow();
    // A deleted policy is no longer in the store, so no activation change is
    // emitted for it; the pass is what withdraws its rules.
    schedulePolicyReconciliation();
    emit policiesChanged();
}

bool NetworkWidget::editPolicy(const QString &policyId, QWidget *dialogParent)
{
    if (policyId.isEmpty())
        return false;

    QWidget *const parent = dialogParent ? dialogParent : this;
    QList<NetworkPolicy> policies = PolicyStore::loadPolicies();
    int index = -1;
    for (int i = 0; i < policies.size(); ++i) {
        if (policies.at(i).id == policyId) {
            index = i;
            break;
        }
    }
    if (index < 0) {
        // The row was stale; re-read so the screen shows what the store holds.
        emit policiesChanged();
        return false;
    }

    const NetworkPolicy stored = policies.at(index);
    if (!editorSupportsScope(stored.scope)) {
        QMessageBox::information(
            parent, QStringLiteral("Policies"),
            QStringLiteral("A policy with the scope \"%1\" cannot be edited in this "
                           "build. Delete it and create a replacement instead.")
                .arg(stored.scope));
        return false;
    }

    // The editor is handed the stored policy, not a copy of the form state, so
    // a field the editor does not show (a legacy schedule, say) round-trips.
    PolicyEditorDialog dialog(stored, parent);
    if (dialog.exec() != QDialog::Accepted)
        return false;

    policies[index] = dialog.policy();
    if (!PolicyStore::savePolicies(policies)) {
        QMessageBox::warning(parent, QStringLiteral("Policies"),
                             QStringLiteral("The edited policy could not be saved."));
        emit policiesChanged();
        return false;
    }

    const NetworkPolicy &policy = policies.at(index);
    AuditEvent audit;
    audit.type = AuditEvent::EventType::PolicyChange;
    audit.scope = policy.targetId;
    audit.reason = QStringLiteral("user edited a policy");
    audit.result = QStringLiteral("saved");
    audit.relatedPolicyId = policy.id;
    audit.details = policy.description;
    m_auditStore.append(audit);

    // The edited policy may now be inactive, shaped differently, or point at a
    // different rate, so the applied set has to be re-derived rather than
    // patched: forget what was re-applied, re-evaluate activation, and let the
    // reconciler withdraw or rewrite the rules attributed to this policy id.
    m_enforcement->forgetReappliedPolicies();
    m_policyScheduler->evaluateNow();
    schedulePolicyReconciliation();
    refreshDashboard();
    ui->lblStatus->setText(QStringLiteral("Policy updated."));
    emit policiesChanged();
    return true;
}

void NetworkWidget::showRecommendationFor(quint32 pid, const QString &processName,
                                          const QString &executablePath)
{
    ActivityClassification activity;
    ActivityQuery query = queryAndActivityFor(pid, processName, executablePath, &activity);

    RecommendationContext context = recommendationContextFor(query, pid, processName);
    context.activity = activity;

    RecommendationDialog dlg(context, m_recommendationEngine, &m_recommendationFeedback, this);
    dlg.exec();
}

void NetworkWidget::showApprovalFor(quint32 pid, const QString &processName,
                                    const QString &executablePath)
{
    ActivityClassification activity;
    ActivityQuery query = queryAndActivityFor(pid, processName, executablePath, &activity);

    RecommendationContext context = recommendationContextFor(query, pid, processName);
    context.activity = activity;

    AiApprovalDialog dlg(context, m_recommendationEngine, &m_aiAssistant, this);
    if (dlg.exec() != QDialog::Accepted) return;

    if (!aiApprovalApprove(dlg.approvedPolicy())) {
        QMessageBox::warning(this, QStringLiteral("Approve policy"),
                             QStringLiteral("The approved policy could not be saved."));
        return;
    }

    ui->lblStatus->setText(QStringLiteral("Policy approved and saved."));
    // The scheduler has not seen the approved policy yet, so this counts as an
    // activation change and applies it now when it is in force.
    m_policyScheduler->evaluateNow();
}

ApplicationDetail::Input NetworkWidget::detailInputFor(quint32 pid,
                                                       const QString &executablePath,
                                                       const QString &processName)
{
    ApplicationDetail::Input input;
    input.pid = pid;
    input.executableName = processName;
    input.executablePath = executablePath;
    input.now = QDateTime::currentDateTimeUtc();

    const int row = (m_model && pid != 0) ? m_model->rowForPid(pid) : -1;
    const ProcessRowSnapshot snapshot = row >= 0 ? m_model->snapshotForRow(row)
                                                 : ProcessRowSnapshot();

    if (snapshot.isValid()) {
        if (!snapshot.name.isEmpty()) input.executableName = snapshot.name;
        if (input.executablePath.isEmpty())
            input.executablePath = getExactProcessPath(snapshot.pid, snapshot.name);
        input.identityId = snapshot.identityId;
        input.displayName = snapshot.identityName;
        input.publisher = snapshot.publisher;
        input.signerStatus = snapshot.signerStatus;
        input.processStartMs = snapshot.processStartMs;
        input.groupId = snapshot.groupId;
        input.groupName = snapshot.groupName;
        input.services = snapshot.services;
        input.query = snapshot.query;
        input.activity = snapshot.activity;

        input.usage.rxBytes = snapshot.rxBytes;
        input.usage.txBytes = snapshot.txBytes;
        input.usage.rxBytesPerSecond = snapshot.rxBytesPerSecond;
        input.usage.txBytesPerSecond = snapshot.txBytesPerSecond;
        input.usage.packets = snapshot.packets;
        input.usage.foreground =
            snapshot.foreground == Oasis::ForegroundAssociation::ForegroundApp;
        input.usage.foregroundHelper =
            snapshot.foreground == Oasis::ForegroundAssociation::ForegroundChild;

        // NG-031/NG-032: the names behind each remote address the row is
        // connected to. Expired records are already filtered by the monitor.
        QStringList addresses;
        for (const ConnectionStat &connection : snapshot.connections) {
            const QString address = connection.remoteAddress.trimmed();
            if (!address.isEmpty() && !addresses.contains(address)) addresses << address;
        }
        for (const QString &address : addresses) {
            const DestinationNameSummary summary =
                summarizeDestinationNames(m_monitor->attributionsForAddress(address), address);
            input.destinations << ApplicationDetail::destinationFromSummary(summary);
        }

        if (snapshot.parentPid != 0) {
            ApplicationDetail::RelatedProcess parent;
            parent.pid = snapshot.parentPid;
            parent.name = snapshot.parentName;
            parent.role = QStringLiteral("Parent process");
            input.related << parent;
        }
    } else {
        input.query.executableName = processName;
        input.query.executablePath = executablePath;
    }

    // Other live members of the same activity group, which is how the user sees
    // the helpers and services that act on this application's behalf.
    if (!input.groupId.isEmpty() && m_monitor) {
        for (const Oasis::ProcessGroup &group : m_monitor->processGroups()) {
            if (group.id != input.groupId) continue;
            for (const Oasis::GroupMember &member : group.members) {
                if (member.observedPid == 0 || member.observedPid == input.pid) continue;
                ApplicationDetail::RelatedProcess related;
                related.pid = member.observedPid;
                related.name = member.displayName.trimmed().isEmpty()
                                   ? QFileInfo(member.value).fileName()
                                   : member.displayName;
                related.role = QStringLiteral("Live member of the activity group");
                input.related << related;
            }
            break;
        }
    }

    input.policies = PolicyStore::loadPolicies();

    // NG-050: the audit trail this application appears in. The identity is the
    // durable link; a path search covers events recorded before an identity was
    // resolved.
    QList<AuditEvent> events;
    if (!input.identityId.isEmpty()) {
        AuditQuery byIdentity;
        byIdentity.identityId = input.identityId;
        events = m_auditStore.query(byIdentity);
    }
    if (!input.executablePath.isEmpty()) {
        AuditQuery byPath;
        byPath.text = input.executablePath;
        events = mergeAuditEvents(events, m_auditStore.query(byPath));
    }
    input.audit = events;

    const QString path = input.executablePath.trimmed();
    input.internetBlocked = m_firewall && !path.isEmpty() && m_firewall->isBlocked(path);
    input.throttleApplied = m_throttlePolicies && !path.isEmpty()
                            && m_throttlePolicies->isThrottled(path);
    if (input.throttleApplied) {
        const QString ownerId = m_throttlePolicies->policyAttribution().value(
            ThrottlePolicyManager::normalizePath(path));
        for (const NetworkPolicy &policy : input.policies) {
            if (policy.id != ownerId) continue;
            input.throttleOwner = policy.description.trimmed().isEmpty()
                                      ? ApplicationDetail::policySummaryText(policy)
                                      : policy.description;
            break;
        }
    }

    return input;
}

void NetworkWidget::showApplicationDetails(quint32 pid, const QString &executablePath,
                                           const QString &processName)
{
    QString name = processName.trimmed();
    QString path = executablePath.trimmed();
    const int row = (m_model && pid != 0) ? m_model->rowForPid(pid) : -1;
    if (name.isEmpty() && row >= 0) name = m_model->snapshotForRow(row).name;
    if (path.isEmpty()) path = getExactProcessPath(pid, name);

    ApplicationDetailDialog dlg(path, detailInputFor(pid, path, name), this);

    // Every action is the existing one, performed by this widget; the dialog is
    // handed a fresh snapshot afterwards so the new limit, block, or policy is
    // visible without reopening the view.
    connect(&dlg, &ApplicationDetailDialog::refreshRequested, this, [&]() {
        dlg.setInput(detailInputFor(pid, path, name));
    });
    connect(&dlg, &ApplicationDetailDialog::actionRequested, this,
            [&](const QString &key) {
        if (key == QLatin1String("policy")) {
            createPolicyForTarget(policyTargetFor(pid, name, path));
        } else if (key == QLatin1String("recommendation")) {
            showRecommendationFor(pid, name, path);
        } else if (key == QLatin1String("approval")) {
            showApprovalFor(pid, name, path);
        } else if (key == QLatin1String("internet")) {
            toggleInternetAccess(name, path);
        } else if (key == QLatin1String("throttle")) {
            requestThrottlePath(path);
        } else if (key == QLatin1String("verify")) {
            schedulePolicyReconciliation();
            ui->lblStatus->setText(QStringLiteral("Verifying stored policies against the system…"));
        } else if (key == QLatin1String("group")) {
            const QString groupId = detailInputFor(pid, path, name).groupId;
            if (!groupId.isEmpty()) {
                GroupDetailDialog group(m_monitor, groupId, m_bandwidthGuard, this);
                group.exec();
            }
        }
        dlg.setInput(detailInputFor(pid, path, name));
    });

    dlg.exec();
}

void NetworkWidget::showTrafficControlsFor(quint32 pid, const QString &executablePath,
                                           const QString &processName)
{
    QString name = processName.trimmed();
    QString path = executablePath.trimmed();
    const int row = (m_model && pid != 0) ? m_model->rowForPid(pid) : -1;
    if (name.isEmpty() && row >= 0)
        name = m_model->snapshotForRow(row).name;
    if (path.isEmpty())
        path = getExactProcessPath(pid, name);
    requestThrottlePath(path);
}

void NetworkWidget::applyApplicationRule(quint32 pid, const QString &executablePath,
                                         const QString &processName, const QString &rule)
{
    const QString wanted = rule.trimmed().toLower();
    if (wanted != QLatin1String("allow") && wanted != QLatin1String("ask")
        && wanted != QLatin1String("block")) {
        return;
    }

    QString name = processName.trimmed();
    QString path = executablePath.trimmed();
    const int modelRow = (m_model && pid != 0) ? m_model->rowForPid(pid) : -1;
    if (name.isEmpty() && modelRow >= 0)
        name = m_model->snapshotForRow(modelRow).name;
    if (path.isEmpty())
        path = getExactProcessPath(pid, name);
    if (path.isEmpty() || !m_firewall)
        return;

    // Allow and Ask both lift a direct firewall block; Block applies one. A
    // wider stored Block policy is left alone: the per-row control reflects
    // it but does not silently delete the user's broader decision.
    const bool blocked = m_firewall && m_firewall->isBlocked(path);
    if (wanted == QLatin1String("block") && !blocked && m_firewall) {
        const QString prompt = QStringLiteral(
            "Block all internet access for this executable?\n\n%1\n\n"
            "This is path-wide and affects every running and future instance.").arg(path);
        if (QMessageBox::question(this, QStringLiteral("Block internet access"), prompt,
                                  QMessageBox::Yes | QMessageBox::No,
                                  QMessageBox::No) != QMessageBox::Yes) {
            return;
        }
        if (!m_firewall->blockApp(path)) {
            QMessageBox::warning(this, QStringLiteral("Firewall rule not applied"),
                                 m_firewall->lastError().isEmpty()
                                     ? QStringLiteral("The firewall rule could not be created.")
                                     : m_firewall->lastError());
            return;
        }
    } else if (wanted != QLatin1String("block") && blocked && m_firewall) {
        const QString prompt = QStringLiteral(
            "Allow internet access again for this executable?\n\n%1").arg(path);
        if (QMessageBox::question(this, QStringLiteral("Restore internet access"), prompt,
                                  QMessageBox::Yes | QMessageBox::No,
                                  QMessageBox::No) != QMessageBox::Yes) {
            return;
        }
        m_firewall->removeAppRules(path);
    }

    // Ask is advisory, so it is represented by a stored policy. One per-app
    // rule owns every path-scoped Ask policy for the executable: switching to
    // Allow or Block removes them rather than leaving a stale Ask behind.
    const QString absolute = QFileInfo(path).absoluteFilePath();
    QList<NetworkPolicy> policies = PolicyStore::loadPolicies();
    QList<NetworkPolicy> kept;
    kept.reserve(policies.size() + 1);
    bool hasAsk = false;
    for (const NetworkPolicy &policy : policies) {
        const QString scope = policy.scope.trimmed().toLower();
        const bool pathScoped = scope == QLatin1String("path")
                                || scope == QLatin1String("executable");
        const bool targetsPath = pathScoped && !policy.targetId.trimmed().isEmpty()
                                 && QFileInfo(policy.targetId).absoluteFilePath().compare(
                                        absolute, Qt::CaseInsensitive) == 0;
        if (targetsPath && policy.action == NetworkPolicy::Action::Ask) {
            if (wanted == QLatin1String("ask")) {
                hasAsk = true;
                kept.append(policy);
            }
            continue;
        }
        kept.append(policy);
    }
    if (wanted == QLatin1String("ask") && !hasAsk) {
        NetworkPolicy policy;
        policy.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        policy.scope = QStringLiteral("path");
        policy.targetId = absolute;
        policy.direction = NetworkDirection::Both;
        policy.action = NetworkPolicy::Action::Ask;
        policy.source = QStringLiteral("user");
        policy.enabled = true;
        policy.description = name.isEmpty()
            ? QStringLiteral("Ask before allowing network access")
            : QStringLiteral("Ask before allowing network access for %1").arg(name);
        kept.append(policy);
    }
    if (kept.size() != policies.size()
        || (wanted == QLatin1String("ask") && !hasAsk)) {
        PolicyStore::savePolicies(kept);
        if (m_policyScheduler)
            m_policyScheduler->evaluateNow();
    }

    AuditEvent audit;
    audit.type = AuditEvent::EventType::PolicyChange;
    audit.scope = absolute;
    audit.reason = QStringLiteral("application rule set to %1").arg(wanted);
    audit.result = wanted;
    audit.details = name;
    m_auditStore.append(audit);

    if (ui && ui->lblStatus)
        ui->lblStatus->setText(QStringLiteral("Rule set to %1 for %2")
                                   .arg(wanted, name.isEmpty() ? absolute : name));
    refreshDashboard();
}

void NetworkWidget::showPolicyEditorFor(quint32 pid, const QString &executablePath,
                                        const QString &processName)
{
    QString name = processName.trimmed();
    QString path = executablePath.trimmed();
    const int row = (m_model && pid != 0) ? m_model->rowForPid(pid) : -1;
    if (name.isEmpty() && row >= 0)
        name = m_model->snapshotForRow(row).name;
    if (path.isEmpty())
        path = getExactProcessPath(pid, name);
    createPolicyForTarget(policyTargetFor(pid, name, path));
}

void NetworkWidget::showPolicies()
{
    if (ui && ui->btnPolicies)
        ui->btnPolicies->click();
}

QString NetworkWidget::primaryDestinationForPid(quint32 pid, QString *confidence) const
{
    if (confidence)
        confidence->clear();
    if (!m_monitor || pid == 0)
        return QString();

    const QList<DomainAttribution> records = m_monitor->attributionRecords();
    for (const DomainAttribution &record : records) {
        if (record.pid != pid || record.name.isEmpty())
            continue;
        if (confidence)
            *confidence = AttributionConfidenceModel::displayName(record.confidence);
        return record.name;
    }
    return QString();
}


QString NetworkWidget::throttleActionText(const QString &path) const
{
    if (path.isEmpty() || !m_throttlePolicies->isThrottled(path))
        return QStringLiteral("Throttle this executable to 50 KiB/s...");

    const QString policyId = m_throttlePolicies->policyAttribution().value(
        ThrottlePolicyManager::normalizePath(path));
    if (policyId.isEmpty())
        return QStringLiteral("Remove bandwidth limit (manual)...");

    QString label;
    for (const NetworkPolicy &policy : PolicyStore::loadPolicies()) {
        if (policy.id != policyId) continue;
        label = policy.description.trimmed();
        if (label.isEmpty()) label = policy.targetId.trimmed();
        break;
    }
    if (label.isEmpty()) label = policyId;
    if (label.size() > 60) label = label.left(57) + QStringLiteral("...");

    return QStringLiteral("Remove bandwidth limit (policy: %1)...").arg(label);
}

void NetworkWidget::requestThrottle(quint32 pid, const QString &procName)
{
    const QString path = getExactProcessPath(pid, procName);
    if (path.isEmpty()) {
        QMessageBox::warning(this, "Throttle unavailable",
                             "The executable path could not be resolved for this process.");
        return;
    }

    requestThrottlePath(path);
}

void NetworkWidget::requestThrottlePath(const QString &path)
{
    if (path.isEmpty()) {
        QMessageBox::warning(this, "Throttle unavailable",
                             "The executable path could not be resolved for this process.");
        return;
    }

    if (m_throttlePolicies->isThrottled(path)) {
        if (QMessageBox::question(this, "Remove bandwidth limit",
                                  QString("Remove the 50 KiB/s limit from:\n%1?").arg(path)) == QMessageBox::Yes) {
            ui->lblStatus->setText("Removing the bandwidth limit...");
            m_throttlePolicies->remove(path);
        }
        return;
    }

    const QString prompt = QString(
        "Apply a 50 KiB/s limit to this executable?\n\n%1\n\n"
        "Downloads are shaped with WinDivert and uploads with Windows QoS.\n"
        "This is path-wide and affects every running and future instance of this executable.\n"
        "The limit will remain until you remove it.").arg(path);
    if (QMessageBox::question(this, "Confirm bandwidth limit", prompt,
                              QMessageBox::Yes | QMessageBox::No,
                              QMessageBox::No) != QMessageBox::Yes)
        return;

    ui->lblStatus->setText("Applying a 50 KiB/s limit...");
    m_pendingManualThrottles.insert(ThrottlePolicyManager::normalizePath(path));
    m_throttlePolicies->apply(path);
}

void NetworkWidget::exemptProcess(const QString &processName, int durationSeconds)
{
    m_bandwidthGuard->exemptProcess(processName, durationSeconds);
    ui->lblStatus->setText(QString("%1 exempted from Data Saver alerts.").arg(processName));
}

void NetworkWidget::onBandwidthDetected(const BandwidthEvent &event)
{
    if (m_dataSaverMode == DataSaverMode::Mode::Off) return;

    const QString usageText = bandwidthUsageText(event);

    // Only background updaters are acted on automatically. User-facing apps
    // remain notification-only until the user chooses a context-menu action.
    if (m_dataSaverMode != DataSaverMode::Mode::Enforce || event.category != ProcessCategory::AutoCandidate) {
        ui->lblStatus->setText("⚠ " + usageText);
        emit bandwidthAlert(event);
        return;
    }

    if (event.executablePath.isEmpty()) {
        BandwidthEvent alert = event;
        alert.throttleMessage = QStringLiteral(
            "The executable path could not be resolved, so no bandwidth limit was applied.");
        ui->lblStatus->setText("⚠ " + usageText + " - path unavailable");
        emit bandwidthAlert(alert);
        return;
    }

    BandwidthEvent alert = event;
    alert.throttleAttempted = true;
    if (m_throttlePolicies->isThrottled(event.executablePath)) {
        alert.throttled = true;
        alert.throttleMessage = QStringLiteral(
            "A 50 KiB/s limit was already active for this executable.");
        ui->lblStatus->setText("⚙ " + usageText + " - throttled to 50 KiB/s");
        emit bandwidthAlert(alert);
        return;
    }

    // The QoS call runs on the throttle worker; this alert is completed when the
    // result arrives in onThrottleApplied().
    m_pendingThrottleEvents.insert(ThrottlePolicyManager::normalizePath(event.executablePath), alert);
    ui->lblStatus->setText("⚙ " + usageText + " - applying a 50 KiB/s limit...");
    // Marked automatic so leaving enforce mode takes this limit back again.
    m_throttlePolicies->apply(event.executablePath, true);
}

void NetworkWidget::setDataSaverMode(DataSaverMode::Mode mode)
{
    if (mode == m_dataSaverMode)
        return;

    const bool leavingEnforceMode = m_dataSaverMode == DataSaverMode::Mode::Enforce;
    m_dataSaverMode = mode;

    // Persist before withdrawing anything. If the process exits during the
    // restore, the next start must not come back enforcing a mode the user
    // already left.
    QSettings settings;
    const bool persisted = DataSaverMode::save(settings, mode);

    if (leavingEnforceMode)
        restoreAllDataSaverPolicies();

    ui->lblStatus->setText(mode == DataSaverMode::Mode::Off
                               ? QStringLiteral("Data Saver is off.")
                               : QStringLiteral("Data Saver enforcement is enabled."));

    AuditEvent audit;
    audit.type = AuditEvent::EventType::PolicyChange;
    audit.scope = QStringLiteral("Data Saver mode");
    audit.reason = QStringLiteral("mode changed");
    audit.result = DataSaverMode::token(mode);
    if (!persisted)
        audit.errorInfo = QStringLiteral("the mode could not be written to settings");
    m_auditStore.append(audit);
}

void NetworkWidget::restoreAllDataSaverPolicies()
{
    // DS-009: withdraw the controls Data Saver itself owns before the guard
    // below, so turning Data Saver off still takes them back while a previous
    // policy-level restore is pending. This is targeted by the dsauto_ policy
    // id, so a user limit or a user-created firewall rule is never removed.
    const QList<DataSaverEnforcement::EnforcementOutcome> withdrawn =
        m_dataSaverEnforcer.withdrawAll(QStringLiteral("automatic controls were restored"));
    for (const DataSaverEnforcement::EnforcementOutcome &outcome : withdrawn)
        recordEnforcementOutcome(outcome);

    // The previous restore's policy report is still waiting for the throttle
    // worker; starting another would replace it before it was ever shown.
    if (m_restoreReportPending) {
        ui->lblStatus->setText("A restore is already in progress...");
        return;
    }

    m_pendingThrottleEvents.clear();
    ui->lblStatus->setText("Restoring automatic controls...");

    // Policy-level decisions first: which stored policies are the product's own
    // and which belong to the user. The throttle channel is asked to take back
    // its automatic limits as part of the same call, and answers asynchronously
    // through throttlesRestored().
    m_restoreReport = m_enforcement->emergencyRestore();
    m_restoreReportPending = m_restoreReport.throttleRestoreRequested;

    AuditEvent restoreAudit;
    restoreAudit.type = AuditEvent::EventType::UserDecision;
    restoreAudit.scope = QStringLiteral("automatic controls");
    restoreAudit.reason = QStringLiteral("user restored automatic controls");
    restoreAudit.result = m_restoreReport.ok() ? QStringLiteral("restored")
                                               : QStringLiteral("partial");
    restoreAudit.errorInfo = m_restoreReport.ok()
        ? QString()
        : QStringLiteral("%1 action(s) failed").arg(m_restoreReport.failed);
    restoreAudit.details = m_restoreReport.summary();
    m_auditStore.append(restoreAudit);

    ui->lblStatus->setText((m_restoreReport.ok() ? QString() : QStringLiteral("⚠ "))
                           + m_restoreReport.summary());

    if (!m_restoreReportPending) {
        // No throttle channel to wait for, so this report is already complete.
        const QString title = QStringLiteral("Restore automatic controls");
        const QString body = m_restoreReport.summary() + "\n\n"
                             + m_restoreReport.lines().join(QLatin1Char('\n'));
        if (m_restoreReport.ok())
            QMessageBox::information(this, title, body);
        else
            QMessageBox::warning(this, title, body);
    }
}

void NetworkWidget::onThrottleApplied(const QString &executablePath, const ThrottleResult &result)
{
    const bool applied = result.status == ThrottleStatus::Applied;
    // Clear the marker here rather than in one branch, so a result can never be
    // consumed twice and confirm a later apply the user did not request.
    const bool manual = m_pendingManualThrottles.remove(
                            ThrottlePolicyManager::normalizePath(executablePath)) > 0;

    const auto pending = m_pendingThrottleEvents.find(executablePath);
    if (pending != m_pendingThrottleEvents.end()) {
        BandwidthEvent alert = pending.value();
        m_pendingThrottleEvents.erase(pending);

        alert.throttled = applied;
        alert.throttleMessage = applied
            ? QStringLiteral("A 50 KiB/s limit was applied to this executable.")
            : result.message;

        // NG-050: the feed needs the automatic decision, not just the alert.
        AuditEvent audit;
        audit.type = AuditEvent::EventType::AutomaticDecision;
        audit.scope = alert.executablePath;
        audit.reason = QStringLiteral("Data Saver automatically limited sustained bandwidth");
        audit.result = applied ? QStringLiteral("applied") : QStringLiteral("failed");
        if (!applied)
            audit.errorInfo = result.message;
        audit.details = QStringLiteral("limit: 50 KiB/s; category: %1%2")
                            .arg(BandwidthGuard::categoryDisplayName(alert.category),
                                 alert.groupName.isEmpty()
                                     ? QString()
                                     : QStringLiteral("; group: %1").arg(alert.groupName));
        m_auditStore.append(audit);

        ui->lblStatus->setText(applied
            ? "⚙ " + bandwidthUsageText(alert) + " - throttled to 50 KiB/s"
            : "⚠ " + bandwidthUsageText(alert) + " - throttle not applied");

        refreshDashboard();
        emit bandwidthAlert(alert);
        return;
    }

    if (manual) {
        // The user asked for this limit, so the confirmation stays a dialog.
        if (applied) {
            ui->lblStatus->setText("Bandwidth limit applied.");
            QMessageBox::information(this, "Bandwidth limit applied",
                                     QString("The executable is now limited to 50 KiB/s.\n\n%1\n\n"
                                             "Use the process menu again to remove the limit.")
                                         .arg(result.message));
        } else {
            ui->lblStatus->setText("⚠ Bandwidth limit not applied.");
            QMessageBox::warning(this, "Bandwidth limit not applied", result.message);
        }
        refreshDashboard();
        return;
    }

    // Nobody is waiting for this result: reconciliation re-applied a stored
    // limit, or a stored policy supplied one. A dialog would interrupt the user
    // for work they did not ask for — typically seconds after an elevated launch
    // — so the outcome goes to the status line and the audit feed instead.
    AuditEvent backgroundAudit;
    backgroundAudit.type = AuditEvent::EventType::EnforcementResult;
    backgroundAudit.scope = executablePath;
    backgroundAudit.reason = applied
        ? QStringLiteral("a stored policy applied a bandwidth limit")
        : QStringLiteral("a stored policy could not apply a bandwidth limit");
    backgroundAudit.result = applied ? QStringLiteral("applied") : QStringLiteral("failed");
    if (!applied) backgroundAudit.errorInfo = result.message;
    // The stored policy behind the limit, when one is attributed; a limit nobody
    // claims keeps an empty link rather than pointing at the QoS policy name.
    backgroundAudit.relatedPolicyId = m_throttlePolicies->policyAttribution().value(
        ThrottlePolicyManager::normalizePath(executablePath));
    m_auditStore.append(backgroundAudit);

    ui->lblStatus->setText(applied
        ? QStringLiteral("Bandwidth limit applied by a stored policy.")
        : QStringLiteral("⚠ Bandwidth limit could not be applied: ") + result.message);
    refreshDashboard();
}

void NetworkWidget::onThrottleRemoved(const QString &executablePath, const ThrottleResult &result)
{
    Q_UNUSED(executablePath);

    if (result.status == ThrottleStatus::Removed || result.status == ThrottleStatus::NotApplied) {
        ui->lblStatus->setText("Bandwidth limit removed.");
        refreshDashboard();
        return;
    }

    ui->lblStatus->setText("⚠ Bandwidth limit could not be removed.");
    QMessageBox::warning(this, "Bandwidth limit", result.message);
    refreshDashboard();
}

void NetworkWidget::onThrottlesRestored(const ThrottleResult &result)
{
    const bool throttleOk = result.status == ThrottleStatus::Removed ||
                            result.status == ThrottleStatus::NotApplied;

    if (!m_restoreReportPending) {
        // A throttle restore that did not come from emergency restore.
        if (throttleOk) {
            ui->lblStatus->setText("Data Saver policies restored.");
            QMessageBox::information(this, "Data Saver", result.message);
        } else {
            ui->lblStatus->setText("⚠ Some Data Saver policies could not be restored.");
            QMessageBox::warning(this, "Data Saver", result.message);
        }
        return;
    }

    m_restoreReportPending = false;

    QStringList lines = m_restoreReport.lines();
    lines << QStringLiteral("%1 [throttle] — %2")
                 .arg(throttleOk ? QStringLiteral("done") : QStringLiteral("failed"),
                      result.message.isEmpty()
                          ? m_restoreReport.throttleMessage
                          : result.message);

    const bool ok = m_restoreReport.ok() && throttleOk;
    ui->lblStatus->setText((ok ? QString() : QStringLiteral("⚠ "))
                           + m_restoreReport.summary());

    const QString title = QStringLiteral("Restore automatic controls");
    const QString body = lines.join(QLatin1Char('\n'));
    if (ok)
        QMessageBox::information(this, title, m_restoreReport.summary() + "\n\n" + body);
    else
        QMessageBox::warning(this, title, m_restoreReport.summary() + "\n\n" + body);
}

void NetworkWidget::schedulePolicyReconciliation()
{
    if (m_reconcileScheduled) return;
    m_reconcileScheduled = true;
    QTimer::singleShot(0, this, [this]() {
        m_reconcileScheduled = false;
        if (!m_policyReconciler || !m_firewall || !m_firewall->isInitialized()) return;
        // Queued, not inline: rule enumeration and repair run on the
        // reconciler's own thread.
        m_policyReconciler->requestReconciliation(m_runningGroupPaths);
    });
}

void NetworkWidget::onPolicyReconciliationFinished(const ReconciliationReport &report)
{
    if (report.repaired > 0 || report.removed > 0 || !report.ok())
        ui->lblStatus->setText(report.summary());

    // The explicit Verify action and the background pass share this result; the
    // host decides whether an unprompted pass should interrupt the user.
    emit policyReconciliationFinished(report);

    if (!m_verifyDialog) return;

    QString body = report.summary();
    const QStringList details = report.lines();
    if (!details.isEmpty())
        body += QStringLiteral("\n\n") + details.join(QLatin1Char('\n'));
    if (report.ok())
        QMessageBox::information(m_verifyDialog, QStringLiteral("Verify policies"), body);
    else
        QMessageBox::warning(m_verifyDialog, QStringLiteral("Verify policies"), body);
}

void NetworkWidget::onPolicyActivationChanged(const NetworkPolicy &policy,
                                              PolicyActivationState state,
                                              const QString &reason)
{
    if (state != PolicyActivationState::Active) {
        // The policy left its window or expired. Firewall rules created by a
        // policy carry its id, so reconciliation can withdraw those safely; a
        // bandwidth limit cannot yet be attributed to a policy, so it is left
        // in place and reported.
        schedulePolicyReconciliation();
        Q_UNUSED(reason);
        return;
    }

    const QString scope = policy.scope.trimmed().toLower();
    if (scope == QStringLiteral("group")) {
        const QStringList running = m_runningGroupPaths.value(policy.targetId);
        if (!running.isEmpty()) {
            m_enforcement->reapplyGroupPolicies(policy.targetId, running,
                                                QList<NetworkPolicy>{policy});
        }
        return;
    }

    if (scope == QStringLiteral("path") || scope == QStringLiteral("executable")) {
        const QString path = policy.targetId.trimmed();
        if (!path.isEmpty()) m_enforcement->applyPolicy(policy, path);
        return;
    }

    // Publisher, service, and package scopes need the identity mapping, which
    // policy enforcement does not resolve yet.
}

void NetworkWidget::toggleInternetAccess(const QString &procName, const QString &path)
{
    if (path.isEmpty()) {
        QMessageBox::warning(this, "Firewall unavailable",
                             "The executable path could not be resolved for this process.");
        return;
    }

    if (m_firewall->isBlocked(path)) {
        if (QMessageBox::question(this, "Restore internet access",
                                  QString("Allow internet access again for:\n%1?").arg(path))
            != QMessageBox::Yes)
            return;

        m_firewall->removeAppRules(path);
        // Do not let the guard immediately re-block what the user just restored.
        m_bandwidthGuard->exemptProcess(procName, 2 * 60 * 60);
        refreshDashboard();
        return;
    }

    const QString prompt = QString(
        "Block all internet access for this executable?\n\n%1\n\n"
        "This is path-wide and affects every running and future instance.\n"
        "Restore it from this menu at any time.").arg(path);
    if (QMessageBox::question(this, "Block internet access", prompt,
                              QMessageBox::Yes | QMessageBox::No,
                              QMessageBox::No) != QMessageBox::Yes)
        return;

    if (!m_firewall->blockApp(path)) {
        QMessageBox::warning(this, "Firewall rule not applied",
                             m_firewall->lastError().isEmpty()
                                 ? "The firewall rule could not be created."
                                 : m_firewall->lastError());
        return;
    }
    refreshDashboard();
}
