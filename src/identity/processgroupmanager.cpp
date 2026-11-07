/**
 * @file    processgroupmanager.cpp
 * @brief   Durable activity groups from identity evidence (NG-014).
 */
#include "processgroupmanager.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>

#include <algorithm>

namespace NetGuard {
namespace {

const int    kSchemaVersion   = 1;
const char  *kSettingsGroup   = "ProcessGroups";
const char  *kSettingsGroups  = "groups";

QString normalised(const QString &value)
{
    return value.trimmed().toLower();
}

QString directoryKey(const QString &path)
{
    if (path.trimmed().isEmpty()) return QString();
    const QFileInfo info(path);
    return normalised(QDir::toNativeSeparators(info.absolutePath()));
}

QString leafName(const QString &path)
{
    if (path.trimmed().isEmpty()) return QString();
    const QFileInfo info(path);
    const QString leaf = info.fileName();
    return leaf.isEmpty() ? QDir::toNativeSeparators(info.absolutePath()) : leaf;
}

QString canonicalMemberPath(const QString &path)
{
    const QString trimmed = path.trimmed();
    if (trimmed.isEmpty()) return QString();
    const QFileInfo info(trimmed);
    const QString canonical = info.canonicalFilePath();
    const QString resolved = canonical.isEmpty() ? QDir::cleanPath(trimmed) : canonical;
    return QDir::toNativeSeparators(resolved);
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

QString memberTypeKey(GroupMemberType type)
{
    switch (type) {
    case GroupMemberType::Service:   return QStringLiteral("service");
    case GroupMemberType::Publisher: return QStringLiteral("publisher");
    case GroupMemberType::Package:   return QStringLiteral("package");
    case GroupMemberType::ExecutablePath: break;
    }
    return QStringLiteral("path");
}

GroupMemberType memberTypeFromKey(const QString &key)
{
    if (key == QLatin1String("service"))   return GroupMemberType::Service;
    if (key == QLatin1String("publisher")) return GroupMemberType::Publisher;
    if (key == QLatin1String("package"))   return GroupMemberType::Package;
    return GroupMemberType::ExecutablePath;
}

QString confidenceKey(ApplicationIdentity::Confidence confidence)
{
    switch (confidence) {
    case ApplicationIdentity::Confidence::Confirmed:        return QStringLiteral("confirmed");
    case ApplicationIdentity::Confidence::StrongInference:  return QStringLiteral("strong");
    case ApplicationIdentity::Confidence::WeakInference:    return QStringLiteral("weak");
    case ApplicationIdentity::Confidence::Unknown:          break;
    }
    return QStringLiteral("unknown");
}

ApplicationIdentity::Confidence confidenceFromKey(const QString &key)
{
    if (key == QLatin1String("confirmed")) return ApplicationIdentity::Confidence::Confirmed;
    if (key == QLatin1String("strong"))    return ApplicationIdentity::Confidence::StrongInference;
    if (key == QLatin1String("weak"))      return ApplicationIdentity::Confidence::WeakInference;
    return ApplicationIdentity::Confidence::Unknown;
}

QByteArray shortDigest(const QString &value)
{
    return QCryptographicHash::hash(value.toUtf8(), QCryptographicHash::Sha1).toHex().left(16);
}

// Automatic ids derive from the evidence anchor, so the same group survives a
// restart, an update, or a change of the running instance.
QString autoGroupId(const QString &anchor)
{
    return QStringLiteral("grp-") + QString::fromLatin1(shortDigest(anchor));
}

QString toPayload(const QString &id, const QString &name, const QString &anchor,
                  bool manual, bool suppressed,
                  const QList<GroupMember> &members, const QStringList &exclusions)
{
    QJsonObject object;
    object.insert(QStringLiteral("id"), id);
    object.insert(QStringLiteral("name"), name);
    object.insert(QStringLiteral("anchor"), anchor);
    object.insert(QStringLiteral("manual"), manual);
    object.insert(QStringLiteral("suppressed"), suppressed);

    QJsonArray memberArray;
    for (const GroupMember &member : members) {
        QJsonObject entry;
        entry.insert(QStringLiteral("type"), memberTypeKey(member.type));
        entry.insert(QStringLiteral("value"), member.value);
        entry.insert(QStringLiteral("displayName"), member.displayName);
        entry.insert(QStringLiteral("identityId"), member.identityId);
        entry.insert(QStringLiteral("publisher"), member.publisher);
        entry.insert(QStringLiteral("explanation"), member.explanation);
        entry.insert(QStringLiteral("confidence"), confidenceKey(member.confidence));
        entry.insert(QStringLiteral("addedAt"), static_cast<double>(member.addedAtMs));
        memberArray.append(entry);
    }
    object.insert(QStringLiteral("members"), memberArray);
    object.insert(QStringLiteral("exclusions"), QJsonArray::fromStringList(exclusions));
    return QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Compact));
}

} // namespace

QString groupMemberTypeName(GroupMemberType type)
{
    switch (type) {
    case GroupMemberType::ExecutablePath: return QStringLiteral("executable");
    case GroupMemberType::Service:        return QStringLiteral("service");
    case GroupMemberType::Publisher:      return QStringLiteral("publisher");
    case GroupMemberType::Package:        return QStringLiteral("package");
    }
    return QStringLiteral("executable");
}

QString groupEvidenceName(GroupEvidenceKind kind)
{
    switch (kind) {
    case GroupEvidenceKind::Manual:                 return QStringLiteral("manual");
    case GroupEvidenceKind::ServiceHost:            return QStringLiteral("service host");
    case GroupEvidenceKind::SharedProduct:          return QStringLiteral("shared product");
    case GroupEvidenceKind::SharedInstallDirectory: return QStringLiteral("shared install directory");
    case GroupEvidenceKind::ParentProcess:          return QStringLiteral("parent process");
    }
    return QStringLiteral("manual");
}

QString groupConfidenceName(ApplicationIdentity::Confidence confidence)
{
    switch (confidence) {
    case ApplicationIdentity::Confidence::Confirmed:       return QStringLiteral("confirmed");
    case ApplicationIdentity::Confidence::StrongInference: return QStringLiteral("strong inference");
    case ApplicationIdentity::Confidence::WeakInference:   return QStringLiteral("weak inference");
    case ApplicationIdentity::Confidence::Unknown:         break;
    }
    return QStringLiteral("unknown");
}

QString groupMemberKey(GroupMemberType type, const QString &value)
{
    // Paths may arrive with either separator (QFileDialog uses '/', the Win32
    // APIs use '\\'), so equality normalizes to the native form.
    if (type == GroupMemberType::ExecutablePath)
        return memberTypeKey(type) + QLatin1Char(':')
               + normalised(QDir::toNativeSeparators(QDir::cleanPath(value.trimmed())));
    return memberTypeKey(type) + QLatin1Char(':') + normalised(value);
}

int ProcessGroup::liveProcessCount() const
{
    int count = 0;
    for (const GroupMember &entry : members)
        if (entry.observedPid != 0 && entry.type == GroupMemberType::ExecutablePath) ++count;
    return count;
}

bool ProcessGroup::contains(GroupMemberType type, const QString &value) const
{
    return member(type, value).isValid();
}

GroupMember ProcessGroup::member(GroupMemberType type, const QString &value) const
{
    const QString key = groupMemberKey(type, value);
    for (const GroupMember &entry : members)
        if (!entry.value.isEmpty() && groupMemberKey(entry.type, entry.value) == key)
            return entry;
    return GroupMember();
}

// ─── Manager ────────────────────────────────────────────────────────────────
ProcessGroupManager::ProcessGroupManager() = default;

int ProcessGroupManager::confidenceRank(ApplicationIdentity::Confidence confidence)
{
    switch (confidence) {
    case ApplicationIdentity::Confidence::Confirmed:       return 3;
    case ApplicationIdentity::Confidence::StrongInference: return 2;
    case ApplicationIdentity::Confidence::WeakInference:   return 1;
    case ApplicationIdentity::Confidence::Unknown:         break;
    }
    return 0;
}

ApplicationIdentity::Confidence ProcessGroupManager::strongestConfidence(
    ApplicationIdentity::Confidence a, ApplicationIdentity::Confidence b)
{
    return confidenceRank(b) > confidenceRank(a) ? b : a;
}

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

ProcessGroup ProcessGroupManager::group(const QString &id) const
{
    ensureLoaded();
    for (const ProcessGroup &candidate : m_groups)
        if (candidate.id == id) return candidate;
    return ProcessGroup();
}

ProcessGroup ProcessGroupManager::createGroup(const QString &name)
{
    ensureLoaded();
    const QString trimmed = name.trimmed();
    if (trimmed.isEmpty()) return ProcessGroup();

    for (const ProcessGroup &existing : m_groups) {
        if (existing.name.compare(trimmed, Qt::CaseInsensitive) == 0) return existing;
    }

    PersistedGroup persisted;
    persisted.id = QStringLiteral("grp-") + QString::fromLatin1(
        shortDigest(QStringLiteral("manual|%1|%2").arg(normalised(trimmed))
                        .arg(QDateTime::currentMSecsSinceEpoch())));
    persisted.name   = trimmed;
    persisted.anchor = QStringLiteral("manual:") + normalised(trimmed);
    persisted.manual = true;
    persisted.manualMembers.clear();
    m_persisted.insert(persisted.id, persisted);
    save();

    ProcessGroup created;
    created.id       = persisted.id;
    created.name     = persisted.name;
    created.anchor   = persisted.anchor;
    created.manual   = true;
    created.updatedAtMs = QDateTime::currentMSecsSinceEpoch();
    m_groups.append(created);
    return created;
}

bool ProcessGroupManager::renameGroup(const QString &id, const QString &name)
{
    ensureLoaded();
    const QString trimmed = name.trimmed();
    if (id.isEmpty() || trimmed.isEmpty()) return false;

    const ProcessGroup existing = group(id);
    if (!existing.isValid()) return false;

    for (const ProcessGroup &other : m_groups) {
        if (other.id != id && other.name.compare(trimmed, Qt::CaseInsensitive) == 0)
            return false;
    }

    PersistedGroup &persisted = m_persisted[id];
    if (persisted.id.isEmpty()) {
        persisted.id     = id;
        persisted.anchor = existing.anchor;
    }
    persisted.name = trimmed;
    save();

    for (ProcessGroup &candidate : m_groups)
        if (candidate.id == id) candidate.name = trimmed;
    return true;
}

bool ProcessGroupManager::removeGroup(const QString &id)
{
    ensureLoaded();
    if (id.isEmpty()) return false;

    const bool known = m_persisted.contains(id)
                       || std::any_of(m_groups.constBegin(), m_groups.constEnd(),
                                      [&id](const ProcessGroup &g) { return g.id == id; });
    if (!known) return false;

    const ProcessGroup existing = group(id);
    bool manual = m_persisted.value(id).manual;
    if (m_persisted.contains(id) && !m_persisted.value(id).manual && existing.isValid())
        manual = false;

    if (manual) {
        m_persisted.remove(id);
    } else {
        // An automatic group cannot be deleted from its evidence, so it is
        // suppressed until the user restores it.
        PersistedGroup &persisted = m_persisted[id];
        if (persisted.id.isEmpty()) {
            persisted.id     = id;
            persisted.anchor = existing.anchor;
        }
        persisted.suppressed = true;
        persisted.name.clear();
        persisted.manualMembers.clear();
        persisted.exclusions.clear();
        persisted.manual = false;
    }
    save();

    for (int i = m_groups.size() - 1; i >= 0; --i)
        if (m_groups.at(i).id == id) m_groups.removeAt(i);

    for (auto it = m_bindings.begin(); it != m_bindings.end();) {
        if (it->groupId == id) it = m_bindings.erase(it);
        else ++it;
    }
    return true;
}

bool ProcessGroupManager::restoreGroup(const QString &id)
{
    ensureLoaded();
    if (!m_persisted.contains(id)) return false;
    if (!m_persisted[id].suppressed) return false;
    m_persisted[id].suppressed = false;
    save();
    return true;
}

bool ProcessGroupManager::addMember(const QString &groupId, GroupMemberType type,
                                    const QString &value, QString *error)
{
    ensureLoaded();
    const auto fail = [error](const QString &message) {
        if (error) *error = message;
        return false;
    };

    if (groupId.isEmpty()) return fail(QStringLiteral("No group was selected."));

    ProcessGroup existing = group(groupId);
    if (!existing.isValid()) return fail(QStringLiteral("That group no longer exists."));

    QString normalisedValue = value.trimmed();
    if (type == GroupMemberType::ExecutablePath) {
        normalisedValue = canonicalMemberPath(value);
        if (normalisedValue.isEmpty())
            return fail(QStringLiteral("That executable path is empty."));
        if (!QFileInfo::exists(normalisedValue))
            return fail(QStringLiteral("No file exists at %1.").arg(normalisedValue));
    } else if (normalisedValue.isEmpty()) {
        return fail(QStringLiteral("A service, publisher, or package name is required."));
    }

    const QString key = groupMemberKey(type, normalisedValue);
    if (existing.member(type, normalisedValue).isValid())
        return fail(QStringLiteral("That member is already in the group."));

    PersistedGroup &persisted = m_persisted[groupId];
    if (persisted.id.isEmpty()) persisted.id = groupId;
    if (persisted.anchor.isEmpty()) persisted.anchor = existing.anchor;

    GroupMember member;
    member.type        = type;
    member.value       = normalisedValue;
    member.displayName = type == GroupMemberType::ExecutablePath
                             ? leafName(normalisedValue)
                             : normalisedValue;
    member.manual      = true;
    // A path the user adds may already be resolved elsewhere in the group.
    for (const GroupMember &existing : existing.members) {
        if (existing.type != type || groupMemberKey(type, existing.value) != key) continue;
        member.publisher = existing.publisher;
        break;
    }
    member.evidence    = GroupEvidenceKind::Manual;
    member.confidence  = ApplicationIdentity::Confidence::Confirmed;
    member.explanation = QStringLiteral("Added manually by the user.");
    member.addedAtMs   = QDateTime::currentMSecsSinceEpoch();
    persisted.manualMembers.append(member);

    // Re-adding a member the user had removed clears the exclusion.
    persisted.exclusions.removeAll(key);
    save();

    for (ProcessGroup &candidate : m_groups) {
        if (candidate.id != groupId) continue;
        candidate.members.append(member);
        candidate.confidence = strongestConfidence(candidate.confidence, member.confidence);
        break;
    }
    if (error) error->clear();
    return true;
}

bool ProcessGroupManager::removeMember(const QString &groupId, GroupMemberType type,
                                       const QString &value)
{
    ensureLoaded();
    if (groupId.isEmpty()) return false;

    const QString key = groupMemberKey(type, value);
    bool removed = false;

    for (ProcessGroup &group : m_groups) {
        if (group.id != groupId) continue;
        for (int i = group.members.size() - 1; i >= 0; --i) {
            if (groupMemberKey(group.members.at(i).type, group.members.at(i).value) != key)
                continue;
            group.members.removeAt(i);
            removed = true;
        }
    }

    PersistedGroup &persisted = m_persisted[groupId];
    bool wasManual = false;
    if (persisted.id.isEmpty()) persisted.id = groupId;
    for (int i = persisted.manualMembers.size() - 1; i >= 0; --i) {
        if (groupMemberKey(persisted.manualMembers.at(i).type,
                           persisted.manualMembers.at(i).value) != key)
            continue;
        persisted.manualMembers.removeAt(i);
        wasManual = true;
    }

    // A member the evidence would re-add needs an exclusion; a manual member is
    // simply forgotten.
    if (!wasManual && !persisted.exclusions.contains(key))
        persisted.exclusions.append(key);

    // Bindings to the removed member must not survive.
    for (auto it = m_bindings.begin(); it != m_bindings.end();) {
        if (it->groupId == groupId) it = m_bindings.erase(it);
        else ++it;
    }

    save();
    return removed || wasManual;
}

void ProcessGroupManager::clear()
{
    m_persisted.clear();
    m_groups.clear();
    m_bindings.clear();
    m_loaded = true;

    QSettings settings;
    settings.remove(QLatin1String(kSettingsGroup));
}

int ProcessGroupManager::manualGroupCount() const
{
    ensureLoaded();
    int count = 0;
    for (auto it = m_persisted.constBegin(); it != m_persisted.constEnd(); ++it)
        if (it->manual && !it->suppressed) ++count;
    return count;
}

int ProcessGroupManager::suppressedGroupCount() const
{
    ensureLoaded();
    int count = 0;
    for (auto it = m_persisted.constBegin(); it != m_persisted.constEnd(); ++it)
        if (it->suppressed) ++count;
    return count;
}

// ─── Persistence ────────────────────────────────────────────────────────────
void ProcessGroupManager::ensureLoaded() const
{
    if (m_loaded) return;
    m_loaded = true;

    QSettings settings;
    settings.beginGroup(QLatin1String(kSettingsGroup));
    const int version = settings.value(QStringLiteral("schemaVersion"), 0).toInt();
    const QStringList payloads = settings.value(QLatin1String(kSettingsGroups)).toStringList();
    settings.endGroup();

    // Unknown or missing schema: start empty instead of guessing at old data.
    if (version != kSchemaVersion) return;

    for (const QString &payload : payloads) {
        const QJsonObject object = QJsonDocument::fromJson(payload.toUtf8()).object();
        const QString id = object.value(QStringLiteral("id")).toString();
        if (id.isEmpty()) continue;

        PersistedGroup persisted;
        persisted.id         = id;
        persisted.name       = object.value(QStringLiteral("name")).toString();
        persisted.anchor     = object.value(QStringLiteral("anchor")).toString();
        persisted.manual     = object.value(QStringLiteral("manual")).toBool();
        persisted.suppressed = object.value(QStringLiteral("suppressed")).toBool();

        const QJsonArray members = object.value(QStringLiteral("members")).toArray();
        for (const QJsonValue &value : members) {
            const QJsonObject entry = value.toObject();
            GroupMember member;
            member.type        = memberTypeFromKey(entry.value(QStringLiteral("type")).toString());
            member.value       = entry.value(QStringLiteral("value")).toString();
            if (member.value.isEmpty()) continue;
            member.displayName = entry.value(QStringLiteral("displayName")).toString();
            member.identityId  = entry.value(QStringLiteral("identityId")).toString();
            member.publisher   = entry.value(QStringLiteral("publisher")).toString();
            member.explanation = entry.value(QStringLiteral("explanation")).toString();
            member.confidence  = confidenceFromKey(
                entry.value(QStringLiteral("confidence")).toString());
            member.addedAtMs   = static_cast<qint64>(
                entry.value(QStringLiteral("addedAt")).toDouble());
            member.manual      = true;
            member.evidence    = GroupEvidenceKind::Manual;
            persisted.manualMembers.append(member);
        }

        for (const QJsonValue &value : object.value(QStringLiteral("exclusions")).toArray())
            persisted.exclusions.append(value.toString());

        m_persisted.insert(persisted.id, persisted);
    }
}

void ProcessGroupManager::save() const
{
    QStringList payloads;
    payloads.reserve(m_persisted.size());
    for (auto it = m_persisted.constBegin(); it != m_persisted.constEnd(); ++it) {
        const PersistedGroup &persisted = it.value();
        payloads.append(toPayload(persisted.id, persisted.name, persisted.anchor,
                                  persisted.manual, persisted.suppressed,
                                  persisted.manualMembers, persisted.exclusions));
    }

    QSettings settings;
    settings.beginGroup(QLatin1String(kSettingsGroup));
    settings.setValue(QStringLiteral("schemaVersion"), kSchemaVersion);
    settings.setValue(QLatin1String(kSettingsGroups), payloads);
    settings.endGroup();
}

} // namespace NetGuard
