/**
 * @file   auditeventstore.h
 * @brief  Bounded, queryable audit event store for detections, decisions,
 *         policy changes, enforcement outcomes, and attribution changes
 *         (NG-050).
 * @author Codebuff
 *
 * The store keeps the `AuditEvent` contract (NG-002) in memory and mirrors it
 * to QSettings as versioned JSON, so an audit trail survives a restart without
 * adding a database dependency. Two settings bound it: a retention window and
 * a hard record cap. Both are clamped, and the oldest event is evicted first,
 * so neither a long-running session nor a burst of repeated events can grow
 * the log without limit.
 *
 * Only metadata is ever stored. `AuditEvent` has no payload field, and the
 * export below builds each object from the documented fields alone, so it can
 * never add a payload or an unknown key (free-text `details` is whatever the
 * caller supplied). Destination redaction (NG-036) is the job of the export UI
 * in NG-055.
 */

#pragma once

#include <QDateTime>
#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

#include "network/policy.h"

namespace AuditStore {
constexpr int kSchemaVersion = 1;
constexpr const char *kFormat = "oasis.audit-log";
constexpr int kDefaultRetentionDays = 30;
constexpr int kDefaultMaxEvents = 2000;
constexpr int kMinRetentionDays = 1;
constexpr int kMaxRetentionDays = 365;
constexpr int kMinEvents = 1;
constexpr int kMaxEvents = 20000;
} // namespace AuditStore

// ─── Retention settings ─────────────────────────────────────────────────────
// Both values are clamped when they are applied or loaded, so a hand-edited or
// malformed settings payload can never disable the bounds.
struct AuditRetentionSettings
{
    int retentionDays = AuditStore::kDefaultRetentionDays;
    int maxEvents = AuditStore::kDefaultMaxEvents;
};

// ─── Query filter ───────────────────────────────────────────────────────────
// An empty field means "do not filter on it". `limit` keeps the newest N
// matches (0 = every match); results are always returned oldest first.
struct AuditQuery
{
    QList<AuditEvent::EventType> types;
    QDateTime from;            // inclusive; invalid = unbounded
    QDateTime to;              // inclusive; invalid = unbounded
    QString identityId;        // exact match
    QString policyId;          // exact match
    QString scope;             // exact match
    QString text;              // case-insensitive substring of the scope and free-text fields
    int limit = 0;
};

// Plain names for the event types, used by the export so a reader does not
// need the enum order. Parsing is case-insensitive and rejects unknown names.
QString auditEventTypeName(AuditEvent::EventType type);
QStringList auditEventTypeNames();
bool auditEventTypeFromName(const QString &name, AuditEvent::EventType *type);

// One exported event object. Built field by field from the struct, so the
// result can never include a key the contract does not define.
QJsonObject auditEventToObject(const AuditEvent &event);

// Clamp a retention request to the documented bounds.
AuditRetentionSettings sanitizedAuditRetention(const AuditRetentionSettings &settings);

// ─── Store ──────────────────────────────────────────────────────────────────
class AuditEventStore : public QObject
{
    Q_OBJECT
public:
    // Loads the persisted log and retention settings. A newer store version, a
    // malformed payload, or an unreadable event is ignored as a whole rather
    // than half-applied; the store then starts empty with default bounds.
    explicit AuditEventStore(QObject *parent = nullptr);

    AuditRetentionSettings retention() const;
    // Applies clamped settings, prunes immediately, and persists. Shortening
    // the window forgets older events right away rather than on the next write.
    void setRetention(const AuditRetentionSettings &settings);

    // Adds one event. An invalid timestamp is stamped with the current time, so
    // every stored event is timestamped. The retention bounds are enforced and
    // the log is persisted after every append.
    void append(const AuditEvent &event);
    void appendAll(const QList<AuditEvent> &events);

    int count() const;
    // Every retained event, oldest first.
    QList<AuditEvent> events() const;
    QList<AuditEvent> query(const AuditQuery &filter) const;

    // Removes events outside the retention window and all but the newest
    // `maxEvents` entries. Called automatically by append() and setRetention().
    void prune();
    // Removes every event and persists the empty log; retention is preserved.
    void clear();

    // Versioned JSON for support or personal analysis: format marker, schema
    // version, export time, current bounds, count, and the events. No packet
    // payloads and no key outside the documented event fields. The overload
    // exports a caller-selected list (for example the currently filtered view)
    // with the same envelope.
    //
    // Destination addresses and host names in the free-text fields are redacted
    // by default (NG-055); `redacted` in the envelope records which form the
    // file is in. Pass false only for an explicit, user-requested verbatim
    // export.
    QString exportJson() const;
    QString exportJson(const QList<AuditEvent> &events, bool redactDestinations = true) const;

    // The same rows as CSV, for a spreadsheet: metadata lines carrying the
    // format, schema version, export time, and redaction state, one header row,
    // and one row per event. Fields are quoted only when they must be.
    QString exportCsv(const QList<AuditEvent> &events, bool redactDestinations = true) const;

    bool load();
    bool save() const;

signals:
    // Emitted after the retained set changes, so a view can re-query without
    // polling. Not emitted by save(), which only mirrors the current set.
    void changed();

private:
    QList<AuditEvent> m_events;   // sorted oldest first
    AuditRetentionSettings m_retention;
};
