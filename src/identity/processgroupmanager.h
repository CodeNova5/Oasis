/**
 * @file    processgroupmanager.h
 * @brief   Durable activity groups from identity evidence (NG-014).
 *
 * One activity group relates the executables and Windows services that belong
 * to the same thing: a launcher and its updater, a service host and its
 * workers, or a program and the helpers it spawns. Groups are derived from the
 * NG-010 identity, the NG-011 publisher, the NG-012 service map, and the NG-013
 * lineage graph; every member records the evidence behind it, a confidence, and
 * a sentence explaining why it belongs.
 *
 * Automatic groups get an id derived from their evidence anchor, so the same
 * group is recognised after a restart or an update. User edits (manual members,
 * renames, removals) are persisted in QSettings and always win over the
 * automatic derivation; an executable the user removed is not re-added.
 *
 * The manager is not thread-safe: it is owned and driven by the monitor's cache
 * thread, and copies of groups and bindings are what other threads see.
 */
#pragma once

#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>

#include "network/policy.h"

namespace NetGuard {

// ─── Membership types ───────────────────────────────────────────────────────
enum class GroupMemberType : int {
    ExecutablePath = 0, // canonical image path
    Service,            // SCM service name
    Publisher,          // Authenticode signer CN, when a whole vendor is grouped
    Package             // AppX package family name
};

QString groupMemberTypeName(GroupMemberType type);

// Why a member belongs to its group.
enum class GroupEvidenceKind : int {
    Manual = 0,           // the user put it there
    ServiceHost,          // the process runs this Windows service
    SharedProduct,        // same publisher and product metadata
    SharedInstallDirectory, // same install directory and publisher
    ParentProcess         // spawned by another member of the group
};

QString groupEvidenceName(GroupEvidenceKind kind);

// "confirmed", "strong inference", "weak inference", "unknown".
QString groupConfidenceName(ApplicationIdentity::Confidence confidence);

// ─── One member ─────────────────────────────────────────────────────────────
struct GroupMember
{
    GroupMemberType type = GroupMemberType::ExecutablePath;
    QString value;             // canonical path / service name / publisher / package
    QString displayName;
    GroupEvidenceKind evidence = GroupEvidenceKind::Manual;
    ApplicationIdentity::Confidence confidence = ApplicationIdentity::Confidence::Unknown;
    QString explanation;       // human-readable reason for the membership
    QString identityId;        // NG-010 identity, for executable members
    QString publisher;         // NG-011 Authenticode publisher, when signed
    quint32 observedPid  = 0;  // instance running now, 0 when not running
    qint64  addedAtMs    = 0;
    bool    manual       = false; // survives automatic re-derivation

    bool isValid() const { return !value.trimmed().isEmpty(); }
};

inline bool operator==(const GroupMember &a, const GroupMember &b)
{
    return a.type == b.type && a.value == b.value
        && a.displayName == b.displayName && a.evidence == b.evidence
        && a.confidence == b.confidence && a.explanation == b.explanation
        && a.identityId == b.identityId && a.publisher == b.publisher
        && a.observedPid == b.observedPid && a.manual == b.manual;
}
inline bool operator!=(const GroupMember &a, const GroupMember &b) { return !(a == b); }

// Stable key for de-duplicating members: "<type>:<lowercased value>".
QString groupMemberKey(GroupMemberType type, const QString &value);

// ─── One group ──────────────────────────────────────────────────────────────
struct ProcessGroup
{
    QString id;                // stable across restarts and updates
    QString name;              // display name, user rename wins
    QString anchor;            // evidence anchor behind an automatic group
    bool    manual      = false; // created or renamed by the user
    QList<GroupMember> members;
    ApplicationIdentity::Confidence confidence = ApplicationIdentity::Confidence::Unknown;
    qint64  updatedAtMs = 0;

    bool isValid() const { return !id.isEmpty(); }
    int  liveProcessCount() const;
    bool contains(GroupMemberType type, const QString &value) const;
    GroupMember member(GroupMemberType type, const QString &value) const;
};

// Snapshot equality: updatedAtMs is deliberately ignored so a refresh that
// changes nothing does not repaint the group detail view.
inline bool operator==(const ProcessGroup &a, const ProcessGroup &b)
{
    return a.id == b.id && a.name == b.name && a.anchor == b.anchor
        && a.manual == b.manual && a.confidence == b.confidence
        && a.members == b.members;
}
inline bool operator!=(const ProcessGroup &a, const ProcessGroup &b) { return !(a == b); }

// ─── One observed process, assembled by the caller ──────────────────────────
struct GroupEvidence
{
    quint32 pid        = 0;
    quint32 parentPid  = 0;
    quint32 generation = 0;       // NG-013 instance generation
    QString processName;
    QString executablePath;       // canonical form, used for display
    QString identityId;           // NG-010 identity id
    QString displayName;
    QString productName;
    QString companyName;
    QString publisher;            // NG-011, empty when unsigned or unverifiable
    QString packageFamilyName;
    QStringList serviceNames;     // NG-012 services hosted by this PID
    QStringList serviceDisplayNames;
    ApplicationIdentity::SignerStatus signerStatus =
        ApplicationIdentity::SignerStatus::Unknown;
};

// ─── What a PID resolves to ─────────────────────────────────────────────────
struct GroupBinding
{
    QString groupId;
    QString groupName;
    ApplicationIdentity::Confidence confidence = ApplicationIdentity::Confidence::Unknown;
    QString explanation;          // why this process is in the group

    bool isValid() const { return !groupId.isEmpty(); }
};

// ─── Manager ────────────────────────────────────────────────────────────────
class ProcessGroupManager
{
public:
    ProcessGroupManager();

    // Rebuild automatic groups from the current evidence and return the group
    // of every PID the caller passed in. Manual groups and manual members are
    // merged in and win over the automatic derivation.
    QHash<quint32, GroupBinding> assign(const QList<GroupEvidence> &processes);

    QList<ProcessGroup> groups() const { return m_groups; }
    ProcessGroup group(const QString &id) const;
    QHash<quint32, GroupBinding> bindings() const { return m_bindings; }
    int count() const { return m_groups.size(); }

    // ── Manual edits ────────────────────────────────────────────────────────
    // Empty name or a name only differing in case from an existing group is
    // rejected: id is left empty, or the existing id is returned.
    ProcessGroup createGroup(const QString &name);
    bool renameGroup(const QString &id, const QString &name);
    // Removing a manual group forgets it; removing an automatic group also
    // suppresses it so the evidence does not recreate it.
    bool removeGroup(const QString &id);
    bool restoreGroup(const QString &id);
    bool addMember(const QString &groupId, GroupMemberType type, const QString &value,
                   QString *error = nullptr);
    // Removing a member of an automatic group records an exclusion, so the
    // evidence cannot silently re-add it.
    bool removeMember(const QString &groupId, GroupMemberType type, const QString &value);

    // Test and maintenance hooks.
    void clear();
    int  manualGroupCount() const;
    int  suppressedGroupCount() const;

    static int confidenceRank(ApplicationIdentity::Confidence confidence);
    static ApplicationIdentity::Confidence strongestConfidence(
        ApplicationIdentity::Confidence a, ApplicationIdentity::Confidence b);

private:
    struct PersistedGroup
    {
        QString id;
        QString name;
        QString anchor;
        bool    manual     = false;
        bool    suppressed = false;
        QList<GroupMember> manualMembers;
        QStringList exclusions;   // groupMemberKey() values removed by the user
    };

    void ensureLoaded() const;
    void save() const;

    ProcessGroup buildGroup(const QString &id, const QString &anchor) const;
    void mergeManualEdits(ProcessGroup &group) const;

    mutable bool m_loaded = false;
    mutable QHash<QString, PersistedGroup> m_persisted;
    QList<ProcessGroup> m_groups;
    QHash<quint32, GroupBinding> m_bindings;
};

} // namespace NetGuard

Q_DECLARE_METATYPE(NetGuard::ProcessGroup)
Q_DECLARE_METATYPE(QList<NetGuard::ProcessGroup>)
