/**
 * @file    activityevent.h
 * @brief   One notable activity event, its filters, and its exports.
 *
 * The Activity screen is an event stream, not a raw packet log. Everything here
 * is display-ready metadata: an event names what happened, which application it
 * belongs to, the numeric evidence behind it, and what the user can do next.
 * Packet payloads are never represented.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>

namespace Activity {

/// The four streams the Activity feed groups events into.
enum class Category {
    Spike,
    Unresolved,
    Policy,
    Respawn
};

/// QSS/color token for the category's accent. Warning, danger, success, info.
QString categoryTone(Category category);
QString categoryKey(Category category);
QString categoryLabel(Category category);
/// Short badge text used on an event card ("Spike", "Unresolved", ...).
QString categoryBadge(Category category);
bool categoryFromKey(const QString &key, Category *category);
QList<Category> allCategories();

/// One key/value pair in an event's metadata box.
struct MetaItem
{
    QString key;
    QString value;
};

/**
 * One entry in the feed.
 *
 * `volumeBytes` and `peakBytesPerSecond` are the numeric evidence; the page
 * formats them so units stay consistent with the rest of the product. `extra`
 * carries category-specific rows (a policy id, a PID, an enforcement channel).
 */
struct Event
{
    QString  id;
    QDateTime at;
    Category category = Category::Spike;
    QString  badge;          // "Bandwidth Spike", "Auto-Throttled", ...
    QString  title;
    QString  description;
    QString  appName;        // executable name or "Unrecognized traffic"
    QString  appPath;        // empty when unresolved
    quint32  pid = 0;
    QString  destination;    // domain or literal address, empty when unknown
    QString  attribution;    // "Confirmed (Valve Corp.)", "Unknown", empty
    quint64  volumeBytes = 0;
    quint64  peakBytesPerSecond = 0;
    QList<MetaItem> extra;
    bool     simulated = false; // only ever set by the debug control

    bool isValid() const { return !id.isEmpty() && at.isValid(); }
};

/// A stable id for a derived event. Callers add their own suffix when several
/// events can share a category and timestamp.
QString makeEventId(Category category, const QDateTime &at, const QString &subject,
                    const QString &suffix = QString());

/// Filtering happens in the page; the host never has to duplicate it.
struct EventFilter
{
    QDateTime from;             // inclusive; invalid = unbounded
    QDateTime to;               // inclusive; invalid = unbounded
    QString   app;              // empty = all applications
    QString   text;             // case-insensitive match over the visible fields
    bool      hasCategory = false;
    Category  category = Category::Spike;
};

QList<Event> filterEvents(const QList<Event> &events, const EventFilter &filter);

/// Counts per category after every filter except the category itself, so a pill
/// shows how many events selecting it would reveal.
QHash<int, int> categoryCounts(const QList<Event> &events, const EventFilter &filter);

/// Plain text used to decide a search match. Public so the harness can check
/// that a destination and the evidence rows are searchable.
QString searchableText(const Event &event);

/// Versioned JSON / CSV exports. Destinations are redacted by default, using
/// the same helpers as the audit and attribution exports.
QString exportJson(const QList<Event> &events, bool redactDestinations = true,
                   const QString &exportedAt = QString());
QString exportCsv(const QList<Event> &events, bool redactDestinations = true,
                  const QString &exportedAt = QString());

} // namespace Activity
