/**
 * @file   evidenceexport.h
 * @brief  Filtered audit and attribution exports (NG-055): versioned JSON and
 *         CSV, with destination redaction on by default.
 * @author Codebuff
 *
 * The two exports are pure functions: they take the rows the view currently
 * shows and return the bytes to write, so the envelope, the CSV escaping, and
 * the redaction rules can be checked without a dialog or a file.
 *
 * Redaction reuses the NG-036 helpers rather than re-deriving what a host name
 * looks like. A redacted destination keeps enough to correlate a report — the
 * network part of an address and the top-level label of a name — and never
 * gains a field that was not already there. Only metadata is exported: the
 * audit contract has no payload field, and attribution records hold names,
 * addresses, sightings, and confidence, never packet content.
 *
 * CSV files start with `#`-prefixed metadata lines so a spreadsheet can still
 * read the table below them while a script can recover the schema version.
 */

#pragma once

#include <QList>
#include <QString>
#include <QStringList>

#include "attribution/dnscorrelator.h"
#include "network/auditeventstore.h"

namespace EvidenceExport {

constexpr int kSchemaVersion = 1;
constexpr const char *kAttributionFormat = "oasis.attribution";

/// One CSV field: quoted only when it has to be, with embedded quotes doubled.
QString csvField(const QString &value);
/// A comma-separated row with a trailing line break.
QString csvRow(const QStringList &values);

/// The same envelope the store's JSON export uses, with the events redacted on
/// request and a `redacted` flag recording which form the file is in.
QString auditJson(const QList<AuditEvent> &events,
                  const AuditRetentionSettings &retention,
                  bool redactDestinations,
                  const QString &exportedAt = QString());

/// Audit rows as CSV: metadata lines, one header row, one row per event.
QString auditCsv(const QList<AuditEvent> &events,
                 bool redactDestinations,
                 const QString &exportedAt = QString());

/// Destinations as versioned JSON, with each name's confidence and evidence.
QString attributionJson(const QList<DestinationNameSummary> &destinations,
                        bool redactDestinations,
                        const QString &exportedAt = QString());

/// Destinations as CSV: metadata lines, `confidence` column included.
QString attributionCsv(const QList<DestinationNameSummary> &destinations,
                       bool redactDestinations,
                       const QString &exportedAt = QString());

/// Redacted or verbatim form of one exported destination, so the JSON and CSV
/// writers cannot disagree about what a redacted value looks like.
QString exportAddress(const QString &address, bool redactDestinations);
QString exportName(const QString &name, bool redactDestinations);

/// Plain name for `ApplicationIdentity::Confidence`, as used by the export.
/// The attribution vocabulary matches the identity one ("confirmed", "strong
/// inference", "weak inference", "unknown"), so the two read the same way.
QString confidenceName(ApplicationIdentity::Confidence confidence);

} // namespace EvidenceExport
