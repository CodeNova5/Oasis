/**
 * @file    processgroupmanager_assign.cpp
 * @brief   Automatic grouping of identity evidence into durable activity
 *          groups (ProcessGroupManager::assign), split out of
 *          processgroupmanager.cpp. Definition only; the interface is
 *          unchanged.
 */
#include "processgroupmanager.h"
#include "processgroupmanager_p.h"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QString>
#include <QStringList>

#include <algorithm>

namespace Oasis {
namespace {

using namespace processgroupdetail;

QString directoryKey(const QString &path)
{
    if (path.trimmed().isEmpty()) return QString();
    const QFileInfo info(path);
    return normalised(QDir::toNativeSeparators(info.absolutePath()));
}

// A publisher is too broad to group on its own (every Windows binary is signed
// by Microsoft), so automatic grouping needs a narrower anchor for it.
bool isBroadPublisher(const QString &publisherKey)
{
    if (publisherKey.isEmpty()) return true;
    static const char *const broad[] = {
        "microsoft", "windows", "unknown", "microsoft windows"
    };
    for (const char *needle : broad)
        if (publisherKey.contains(QLatin1String(needle))) return true;
    return false;
}

// Automatic ids derive from the evidence anchor, so the same group survives a
// restart, an update, or a change of the running instance.
QString autoGroupId(const QString &anchor)
{
    return QStringLiteral("grp-") + QString::fromLatin1(shortDigest(anchor));
}

} // namespace

QHash<quint32, GroupBinding> ProcessGroupManager::assign(const QList<GroupEvidence> &processes)
{
    ensureLoaded();
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    QList<ProcessGroup> groups;
    QHash<QString, int> indexById;
    QHash<quint32, int> indexByPid;

    const auto groupById = [&](const QString &id) -> ProcessGroup * {
        const int index = indexById.value(id, -1);
        return index >= 0 ? &groups[index] : nullptr;
    };

    const auto ensureGroup = [&](const QString &id, const QString &anchor,
                                 const QString &suggestedName) {
        if (groupById(id)) return;
        ProcessGroup group;
        group.id    = id;
        group.anchor = anchor;
        group.name  = suggestedName;
        group.updatedAtMs = now;
        indexById.insert(id, groups.size());
        groups.append(group);
    };

    // Exclusions are the user's removals; they outrank the automatic evidence.
    const auto isExcluded = [&](const QString &groupId, const QString &key) {
        return m_persisted.value(groupId).exclusions.contains(key);
    };

    // Adds a member, keeping the strongest evidence and the live PID. A manual
    // membership is never downgraded by an automatic one.
    const auto addMember = [](ProcessGroup *group, const GroupMember &member) {
        if (!group || !member.isValid()) return;
        const QString key = groupMemberKey(member.type, member.value);
        for (GroupMember &existing : group->members) {
            if (groupMemberKey(existing.type, existing.value) != key) continue;

            const bool stronger = confidenceRank(member.confidence)
                                  > confidenceRank(existing.confidence);
            if (member.manual && !existing.manual) {
                const quint32 pid = existing.observedPid;
                const qint64 addedAt = existing.addedAtMs;
                existing = member;
                existing.manual = true;
                if (existing.observedPid == 0) existing.observedPid = pid;
                if (existing.addedAtMs == 0) existing.addedAtMs = addedAt;
            } else if (stronger) {
                const bool wasManual = existing.manual;
                const quint32 pid = member.observedPid ? member.observedPid : existing.observedPid;
                existing = member;
                existing.manual = wasManual || member.manual;
                existing.observedPid = pid;
            } else {
                if (existing.observedPid == 0) existing.observedPid = member.observedPid;
                if (existing.displayName.isEmpty()) existing.displayName = member.displayName;
                if (existing.explanation.isEmpty()) existing.explanation = member.explanation;
            }
            return;
        }
        group->members.append(member);
    };

    for (int i = 0; i < processes.size(); ++i)
        if (processes.at(i).pid != 0) indexByPid.insert(processes.at(i).pid, i);

    // ── 1. Evidence anchors ─────────────────────────────────────────────────
    // Automatic groups need evidence narrower than "signed by Microsoft":
    // either the service the process runs, its product metadata, or its install
    // directory combined with a specific publisher.
    for (const GroupEvidence &evidence : processes) {
        if (evidence.pid == 0 || evidence.executablePath.trimmed().isEmpty()) continue;

        const QString dirKey = directoryKey(evidence.executablePath);
        const QString publisher = evidence.publisher.trimmed();
        const QString publisherKey = normalised(publisher);
        const bool narrowPublisher = !isBroadPublisher(publisherKey);

        QString anchor;
        QString name;
        GroupEvidenceKind kind = GroupEvidenceKind::SharedProduct;
        QString reason;

        if (!evidence.serviceNames.isEmpty() && narrowPublisher) {
            anchor = QStringLiteral("svc:") + dirKey + QLatin1Char('|') + publisherKey;
            kind = GroupEvidenceKind::ServiceHost;
            name = evidence.serviceDisplayNames.value(0).trimmed();
            reason = QStringLiteral("Hosts the Windows service \"%1\"; signed by %2 and "
                                    "installed in %3, like the other members.")
                         .arg(evidence.serviceDisplayNames.value(0, evidence.serviceNames.first()),
                              publisher, dirKey);
        }

        const QString product = evidence.productName.trimmed();
        if (anchor.isEmpty() && narrowPublisher && !product.isEmpty()) {
            anchor = QStringLiteral("prod:") + publisherKey + QLatin1Char('|') + normalised(product);
            kind = GroupEvidenceKind::SharedProduct;
            name = product;
            reason = QStringLiteral("Signed by %1 and reports the product \"%2\".").arg(publisher, product);
        }

        if (anchor.isEmpty() && narrowPublisher) {
            anchor = QStringLiteral("dir:") + dirKey + QLatin1Char('|') + publisherKey;
            kind = GroupEvidenceKind::SharedInstallDirectory;
            name = leafName(dirKey);
            reason = QStringLiteral("Installed in %1 next to other members and signed by %2.")
                         .arg(dirKey, publisher);
        }

        // No defensible evidence: the process stays ungrouped rather than being
        // swept into a vendor- or OS-wide group.
        if (anchor.isEmpty()) continue;

        const QString id = autoGroupId(anchor);
        if (m_persisted.value(id).suppressed) continue;

        if (name.trimmed().isEmpty()) name = leafName(dirKey);
        if (name.trimmed().isEmpty()) name = publisher;
        if (name.trimmed().isEmpty()) name = QStringLiteral("Activity group");
        ensureGroup(id, anchor, name);
        ProcessGroup *group = groupById(id);
        if (!group) continue;

        GroupMember executable;
        executable.type        = GroupMemberType::ExecutablePath;
        executable.value       = evidence.executablePath;
        executable.displayName = evidence.displayName.isEmpty()
                                     ? evidence.processName
                                     : evidence.displayName;
        executable.evidence    = kind;
        executable.confidence  = kind == GroupEvidenceKind::SharedInstallDirectory
                                     ? ApplicationIdentity::Confidence::WeakInference
                                     : ApplicationIdentity::Confidence::StrongInference;
        executable.explanation = reason;
        executable.identityId  = evidence.identityId;
        executable.publisher   = publisher;
        executable.observedPid = evidence.pid;
        executable.addedAtMs   = now;
        if (!isExcluded(id, groupMemberKey(executable.type, executable.value)))
            addMember(group, executable);

        for (int s = 0; s < evidence.serviceNames.size(); ++s) {
            GroupMember service;
            service.type        = GroupMemberType::Service;
            service.value       = evidence.serviceNames.at(s);
            service.displayName = evidence.serviceDisplayNames.value(s, service.value);
            service.evidence    = GroupEvidenceKind::ServiceHost;
            // The SCM told us this process runs the service: confirmed.
            service.confidence  = ApplicationIdentity::Confidence::Confirmed;
            service.explanation = QStringLiteral("Windows service hosted by %1 (PID %2).")
                                      .arg(executable.displayName.isEmpty()
                                               ? evidence.processName
                                               : executable.displayName)
                                      .arg(evidence.pid);
            service.observedPid = evidence.pid;
            service.addedAtMs   = now;
            if (!isExcluded(id, groupMemberKey(service.type, service.value)))
                addMember(group, service);
        }
    }

    // ── 2. Co-installed companions ──────────────────────────────────────────
    // A second product shipped in the same install directory by the same
    // publisher (an updater, a crash handler) is part of the same activity, so
    // it joins the group anchored there instead of forming a group of its own.
    // Directory evidence is weaker than the service or product evidence that
    // established the group, so the moved member stays a weak inference.
    {
        auto anchorPriority = [](GroupEvidenceKind kind) {
            switch (kind) {
            case GroupEvidenceKind::ServiceHost:            return 0;
            case GroupEvidenceKind::SharedProduct:          return 1;
            case GroupEvidenceKind::SharedInstallDirectory: return 2;
            case GroupEvidenceKind::ParentProcess:          return 3;
            case GroupEvidenceKind::Manual:                 break;
            }
            return 4;
        };

        const auto dirKeyOf = [](const GroupEvidence &evidence) {
            return directoryKey(evidence.executablePath) + QLatin1Char('|')
                   + normalised(evidence.publisher);
        };

        const auto groupOfPid = [&](quint32 pid) -> QString {
            for (const ProcessGroup &group : groups)
                for (const GroupMember &member : group.members)
                    if (member.observedPid == pid
                        && member.type == GroupMemberType::ExecutablePath)
                        return group.id;
            return QString();
        };

        struct AnchorChoice { int priority = 99; QString groupId; };
        QHash<QString, AnchorChoice> anchorsByDirectory;
        QHash<quint32, AnchorChoice> observedAnchors;

        for (const GroupEvidence &evidence : processes) {
            if (evidence.pid == 0 || evidence.executablePath.isEmpty()) continue;
            if (isBroadPublisher(normalised(evidence.publisher))) continue;

            const QString groupId = groupOfPid(evidence.pid);
            if (groupId.isEmpty()) continue;
            const ProcessGroup *group = groupById(groupId);
            if (!group) continue;

            GroupEvidenceKind kind = GroupEvidenceKind::SharedInstallDirectory;
            QString anchor;
            for (const GroupMember &member : group->members) {
                if (member.type != GroupMemberType::ExecutablePath) continue;
                if (normalised(member.value) != normalised(evidence.executablePath)) continue;
                kind = member.evidence;
                anchor = group->anchor;
                break;
            }
            // Only an evidence-anchored group can pull in a companion; groups
            // built from a parent-process membership cannot.
            if (kind == GroupEvidenceKind::ParentProcess || kind == GroupEvidenceKind::Manual)
                continue;

            AnchorChoice choice;
            choice.priority = anchorPriority(kind);
            choice.groupId  = groupId;
            const QString dirKey = dirKeyOf(evidence);
            observedAnchors.insert(evidence.pid, choice);

            const auto existing = anchorsByDirectory.constFind(dirKey);
            if (existing == anchorsByDirectory.constEnd()
                || choice.priority < existing->priority
                || (choice.priority == existing->priority
                    && choice.groupId < existing->groupId))
                anchorsByDirectory.insert(dirKey, choice);
        }

        for (auto it = observedAnchors.constBegin(); it != observedAnchors.constEnd(); ++it) {
            const int index = indexByPid.value(it.key(), -1);
            if (index < 0) continue;
            const GroupEvidence &evidence = processes.at(index);

            const AnchorChoice target = anchorsByDirectory.value(dirKeyOf(evidence));
            if (target.groupId.isEmpty() || target.groupId == it->groupId) continue;

            ProcessGroup *destination = groupById(target.groupId);
            ProcessGroup *source = groupById(it->groupId);
            if (!destination || !source) continue;

            const QString key = groupMemberKey(GroupMemberType::ExecutablePath,
                                               evidence.executablePath);
            if (isExcluded(destination->id, key)) continue;

            for (int i = source->members.size() - 1; i >= 0; --i) {
                const GroupMember &member = source->members.at(i);
                if (member.type != GroupMemberType::ExecutablePath) continue;
                if (member.observedPid != evidence.pid) continue;
                source->members.removeAt(i);
            }

            GroupMember companion;
            companion.type        = GroupMemberType::ExecutablePath;
            companion.value       = evidence.executablePath;
            companion.displayName = evidence.displayName.isEmpty()
                                        ? evidence.processName
                                        : evidence.displayName;
            companion.evidence    = GroupEvidenceKind::SharedInstallDirectory;
            companion.confidence  = ApplicationIdentity::Confidence::WeakInference;
            companion.explanation = QStringLiteral("Installed in %1 next to the group's other "
                                                   "executables and signed by %2.")
                                        .arg(directoryKey(evidence.executablePath),
                                             evidence.publisher.trimmed());
            companion.identityId  = evidence.identityId;
            companion.publisher   = evidence.publisher.trimmed();
            companion.observedPid = evidence.pid;
            companion.addedAtMs   = now;
            addMember(destination, companion);
        }

        // A group that lost its only member to a co-installation is not useful.
        for (int i = groups.size() - 1; i >= 0; --i) {
            if (groups.at(i).members.isEmpty()) {
                indexById.remove(groups.at(i).id);
                groups.removeAt(i);
                for (auto it = indexById.begin(); it != indexById.end(); ++it)
                    if (it.value() > i) --it.value();
            }
        }
    }

    // ── 3. User-created groups ──────────────────────────────────────────────
    for (auto it = m_persisted.constBegin(); it != m_persisted.constEnd(); ++it) {
        const PersistedGroup &persisted = it.value();
        if (!persisted.manual || persisted.suppressed) continue;
        ensureGroup(persisted.id, persisted.anchor, persisted.name);
        ProcessGroup *group = groupById(persisted.id);
        if (group && !persisted.name.isEmpty()) group->name = persisted.name;
    }

    // ── 4. Manual members, and the live processes that match them ───────────
    for (const GroupEvidence &evidence : processes) {
        if (evidence.pid == 0) continue;
        for (auto it = m_persisted.constBegin(); it != m_persisted.constEnd(); ++it) {
            const PersistedGroup &persisted = it.value();
            if (persisted.manualMembers.isEmpty()) continue;

            if (persisted.suppressed) continue;

            ProcessGroup *group = groupById(persisted.id);
            if (!group) {
                ensureGroup(persisted.id, persisted.anchor, persisted.name);
                group = groupById(persisted.id);
                if (!group) continue;
            }

            for (const GroupMember &manualMember : persisted.manualMembers) {
                bool matches = false;
                if (manualMember.type == GroupMemberType::ExecutablePath) {
                    matches = normalised(QDir::toNativeSeparators(manualMember.value))
                              == normalised(QDir::toNativeSeparators(evidence.executablePath));
                } else if (manualMember.type == GroupMemberType::Service) {
                    matches = evidence.serviceNames.contains(manualMember.value,
                                                             Qt::CaseInsensitive);
                } else if (manualMember.type == GroupMemberType::Publisher) {
                    matches = !evidence.publisher.isEmpty()
                              && normalised(evidence.publisher) == normalised(manualMember.value);
                } else if (manualMember.type == GroupMemberType::Package) {
                    matches = !evidence.packageFamilyName.isEmpty()
                              && evidence.packageFamilyName.compare(manualMember.value,
                                                                    Qt::CaseInsensitive) == 0;
                }
                if (!matches) continue;

                GroupMember member = manualMember;
                member.manual       = true;
                member.evidence     = GroupEvidenceKind::Manual;
                member.confidence   = ApplicationIdentity::Confidence::Confirmed;
                member.explanation  = member.explanation.isEmpty()
                                          ? QStringLiteral("Added manually by the user.")
                                          : member.explanation;
                member.identityId   = evidence.identityId;
                if (member.publisher.isEmpty()) member.publisher = evidence.publisher.trimmed();
                member.observedPid  = evidence.pid;
                if (member.addedAtMs == 0) member.addedAtMs = now;
                if (member.displayName.isEmpty())
                    member.displayName = evidence.displayName.isEmpty()
                                             ? evidence.processName
                                             : evidence.displayName;
                addMember(group, member);
            }
        }
    }

    // ── 5. Names and renames from the user ──────────────────────────────────
    for (ProcessGroup &group : groups) {
        const PersistedGroup persisted = m_persisted.value(group.id);
        if (!persisted.name.trimmed().isEmpty()) group.name = persisted.name;
        group.manual = persisted.manual;
    }

    // ── 6. Bind PIDs to groups ──────────────────────────────────────────────
    const auto computeBindings = [&]() {
        QHash<quint32, GroupBinding> bindings;
        for (const ProcessGroup &group : groups) {
            for (const GroupMember &member : group.members) {
                if (member.observedPid == 0) continue;
                if (member.type != GroupMemberType::ExecutablePath
                    && member.type != GroupMemberType::Service)
                    continue;

                GroupBinding binding;
                binding.groupId     = group.id;
                binding.groupName   = group.name;
                binding.confidence  = member.confidence;
                binding.explanation = member.explanation;

                const auto existing = bindings.constFind(member.observedPid);
                if (existing == bindings.constEnd()) {
                    bindings.insert(member.observedPid, binding);
                    continue;
                }
                const bool existingManual = groupById(existing->groupId)
                                                ? groupById(existing->groupId)->manual
                                                : false;
                if ((group.manual && !existingManual)
                    || confidenceRank(binding.confidence) > confidenceRank(existing->confidence))
                    bindings.insert(member.observedPid, binding);
            }
        }
        return bindings;
    };

    QHash<quint32, GroupBinding> bindings = computeBindings();

    // ── 7. Helpers inherit from a parent that is already grouped ────────────
    // Only one level, only from established evidence, and only when the child
    // is installed alongside the parent or shares its publisher. This relates
    // "package manager and its helper processes" without swallowing everything
    // an arbitrary launcher starts.
    for (const GroupEvidence &evidence : processes) {
        if (evidence.pid == 0 || evidence.parentPid == 0) continue;
        if (bindings.contains(evidence.pid)) continue;

        const int parentIndex = indexByPid.value(evidence.parentPid, -1);
        if (parentIndex < 0) continue;
        const GroupEvidence &parent = processes.at(parentIndex);

        const GroupBinding parentBinding = bindings.value(evidence.parentPid);
        if (!parentBinding.isValid()) continue;

        ProcessGroup *group = groupById(parentBinding.groupId);
        if (!group) continue;

        bool established = false;
        for (const GroupMember &member : group->members) {
            if (member.evidence != GroupEvidenceKind::ParentProcess) {
                established = true;
                break;
            }
        }
        if (!established) continue;

        const QString dirKey      = directoryKey(evidence.executablePath);
        const QString parentDir   = directoryKey(parent.executablePath);
        const QString publisher   = normalised(evidence.publisher);
        const QString parentPub   = normalised(parent.publisher);
        const bool sameDirectory  = !dirKey.isEmpty() && dirKey == parentDir;
        const bool samePublisher  = !publisher.isEmpty() && publisher == parentPub;
        if (!sameDirectory && !samePublisher) continue;

        const QString key = groupMemberKey(GroupMemberType::ExecutablePath,
                                           evidence.executablePath);
        if (isExcluded(group->id, key)) continue;

        GroupMember helper;
        helper.type        = GroupMemberType::ExecutablePath;
        helper.value       = evidence.executablePath;
        helper.displayName = evidence.displayName.isEmpty()
                                 ? evidence.processName
                                 : evidence.displayName;
        helper.evidence    = GroupEvidenceKind::ParentProcess;
        helper.confidence  = ApplicationIdentity::Confidence::WeakInference;
        helper.explanation = QStringLiteral("Spawned by %1 (PID %2) from the same %3.")
                                 .arg(parent.displayName.isEmpty()
                                          ? parent.processName
                                          : parent.displayName)
                                 .arg(parent.pid)
                                 .arg(sameDirectory ? QStringLiteral("install directory")
                                                    : QStringLiteral("publisher"));
        if (evidence.generation > 1)
            helper.explanation += QStringLiteral(" Instance %1 of that PID.")
                                      .arg(evidence.generation);
        helper.identityId  = evidence.identityId;
        helper.publisher   = evidence.publisher.trimmed();
        helper.observedPid = evidence.pid;
        helper.addedAtMs   = now;
        addMember(group, helper);
    }

    bindings = computeBindings();

    // ── 8. Group confidence and ordering ────────────────────────────────────
    for (ProcessGroup &group : groups) {
        group.confidence = ApplicationIdentity::Confidence::Unknown;
        for (const GroupMember &member : group.members) {
            if (!member.isValid()) continue;
            group.confidence = strongestConfidence(group.confidence, member.confidence);
        }
        group.updatedAtMs = now;
    }

    std::stable_sort(groups.begin(), groups.end(),
                     [](const ProcessGroup &a, const ProcessGroup &b) {
                         if (a.manual != b.manual) return a.manual;
                         const int byName = QString::compare(a.name, b.name, Qt::CaseInsensitive);
                         if (byName != 0) return byName < 0;
                         return a.id < b.id;
                     });

    m_groups    = groups;
    m_bindings  = bindings;
    return bindings;
}

} // namespace Oasis
