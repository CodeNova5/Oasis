/**
 * @file    processgroupmanager.cpp
 * @brief   Durable activity groups from identity evidence (NG-014).
 */
#include "processgroupmanager.h"
#include "processgroupmanager_p.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>

#include <algorithm>

namespace Oasis {
namespace {

using namespace processgroupdetail;

const int    kSchemaVersion   = 1;
const char  *kSettingsGroup   = "ProcessGroups";
const char  *kSettingsGroups  = "groups";

QString canonicalMemberPath(const QString &path)
{
    const QString trimmed = path.trimmed();
    if (trimmed.isEmpty()) return QString();
    const QFileInfo info(trimmed);
    const QString canonical = info.canonicalFilePath();
    const QString resolved = canonical.isEmpty() ? QDir::cleanPath(trimmed) : canonical;
    return QDir::toNativeSeparators(resolved);
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

} // namespace Oasis
