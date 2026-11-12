/**
 * @file   topconsumers.h
 * @brief  What the dashboard shows first: top consumers, active controls,
 *         unresolved traffic, and suggested actions (NG-054).
 *
 * The dashboard is a reading of evidence the other layers already produce, not
 * another enforcement path. It ranks the current consumers, names the one that
 * deserves attention, lists the policies that are in force right now, counts
 * the traffic this build cannot explain, and surfaces the NG-042 suggestions
 * that are worth acting on. Everything here is pure: the widget feeds it row
 * snapshots and the clock, and it returns display-ready sections, so ranking,
 * tie-breaking, and the "unresolved" arithmetic are checked without a GUI.
 *
 * @author Codebuff
 */

#pragma once

#include <QDateTime>
#include <QList>
#include <QString>

#include "network/policy.h"

namespace TopConsumers {

// The panel shows a handful: enough to see the shape of the traffic, small
// enough to stay usable next to the process tree.
constexpr int kDefaultTopCount = 5;
constexpr int kMaxRecommendations = 3;

// ─── One process as the dashboard sees it ───────────────────────────────────
struct Consumer
{
    quint32 pid = 0;
    QString name;               // "chrome.exe"
    QString identity;           // "Google Chrome" when resolved, else empty
    QString path;               // executable path, empty when unresolved
    quint64 rxBytes = 0;
    quint64 txBytes = 0;
    quint64 rxBytesPerSecond = 0;
    quint64 txBytesPerSecond = 0;
    QString activity;           // "Browser (Likely)", empty when nothing matched
    bool foreground = false;
    bool blocked = false;       // a firewall block covers this executable
    bool throttled = false;     // a shaping limit covers this executable
    QString controlOwner;       // policy summary behind the limit, when known
    QString recommendation;     // NG-042 title, empty when nothing is suggested
    QString recommendationReason;

    quint64 totalBytes() const { return rxBytes + txBytes; }
    quint64 totalBytesPerSecond() const { return rxBytesPerSecond + txBytesPerSecond; }
};

// ─── One dashboard row ──────────────────────────────────────────────────────
struct Row
{
    int rank = 0;
    quint32 pid = 0;
    QString name;
    QString identity;
    QString path;
    QString usage;              // "1.2 Mbit/s · 12.4 MB"
    QString activity;           // "Browser (Likely)" or "Unresolved"
    QString control;            // "Blocked", "Limited", "Foreground", or "—"
    bool unresolved = false;
};

// ─── One policy in force ────────────────────────────────────────────────────
struct Control
{
    QString policyId;
    QString summary;
    QString effect;             // "Block, downloads"
    QString state;              // "active"
    QString enforcement;        // NG-053 summary, so partial enforcement shows here too
    QDateTime expiration;
    bool temporary = false;
};

// ─── One suggested action ───────────────────────────────────────────────────
struct Recommendation
{
    quint32 pid = 0;
    QString name;
    QString path;
    QString title;
    QString reason;
};

// ─── The first view ─────────────────────────────────────────────────────────
struct Summary
{
    QList<Row> rows;
    int consumerCount = 0;
    quint64 totalRxBytes = 0;
    quint64 totalTxBytes = 0;
    quint64 totalBytesPerSecond = 0;

    quint32 topPid = 0;
    QString topName;
    QString topPath;
    QString headline;           // "chrome.exe is the top consumer at 1.2 Mbit/s"
    QString topSummary;         // name, identity, usage, and what controls it

    QList<Control> controls;
    QString controlSummary;     // "2 controls in force (1 temporary)"

    int unresolvedConsumers = 0;
    quint64 unresolvedBytes = 0;
    QString unresolvedSummary;

    QList<Recommendation> recommendations;
    QString recommendationSummary;

    bool isEmpty() const { return consumerCount == 0; }
};

// Current rate first, then total bytes, then the process name, so equal
// consumers do not reshuffle between refreshes.
QList<const Consumer *> rankConsumers(const QList<Consumer> &consumers, int limit);

// A consumer is unresolved when this build cannot say what it is: no executable
// path to act on, or no activity classification to explain it.
bool isUnresolved(const Consumer &consumer);

// `now` decides which stored policies are in force (NG-023) and which temporary
// ones are still counting down.
Summary build(const QList<Consumer> &consumers, const QList<NetworkPolicy> &policies,
              const QDateTime &now, int limit = kDefaultTopCount);

} // namespace TopConsumers
