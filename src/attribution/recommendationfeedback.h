/**
 * @file    recommendationfeedback.h
 * @brief   Local recommendation feedback (NG-043): remembers whether the user
 *          found a suggestion useful, incorrect, or unwanted.
 * @author  Ali Sakkaf
 *
 * Feedback is stored on this device only. It is keyed by the activity category
 * and the application's durable identity, never by a destination, a rate, or
 * any packet content, and nothing is uploaded. The engine reads it so a
 * preference the user expressed changes future local suggestions.
 */
#pragma once

#include <QDateTime>
#include <QList>
#include <QMap>
#include <QString>

enum class RecommendationFeedback : int
{
    None = 0,
    Useful,      // the suggestion was right; keep offering it
    Incorrect,   // the basis was wrong; downgrade the suggestion to a review
    Unwanted     // stop offering this suggestion for this application
};

QString recommendationFeedbackToken(RecommendationFeedback feedback);
QString recommendationFeedbackDisplayName(RecommendationFeedback feedback);
bool recommendationFeedbackFromToken(const QString &token,
                                     RecommendationFeedback *feedback);

struct RecommendationFeedbackEntry
{
    QString key;
    RecommendationFeedback feedback = RecommendationFeedback::None;
    QDateTime updatedAt;
};

/**
 * Persisted feedback map.
 *
 * The payload is a versioned JSON document (`schemaVersion` = 1) under one
 * QSettings key. A malformed or newer document is rejected as a whole and the
 * store starts empty rather than half-applying a config it does not understand.
 * Only the feedback key, the verdict, and its timestamp are written.
 */
class RecommendationFeedbackStore
{
public:
    static constexpr int kSchemaVersion = 1;
    /// Hard bound on remembered verdicts; the least recently updated is dropped.
    static constexpr int kMaxEntries = 512;

    static QString settingsGroup();
    static QString settingsKey();

    /// Load the stored feedback; an unreadable store starts empty.
    RecommendationFeedbackStore();

    RecommendationFeedback feedbackFor(const QString &key) const;
    bool contains(const QString &key) const;
    int count() const;
    QList<RecommendationFeedbackEntry> entries() const;

    /// Record one verdict and persist immediately. `None` removes the entry.
    /// Returns false when the settings backend reports an error.
    bool setFeedback(const QString &key, RecommendationFeedback feedback);

    /// Forget every verdict, in memory and on disk.
    bool clear();

    /// The serialised form (one JSON object) used by tests and diagnostics.
    static QString toJson(const QList<RecommendationFeedbackEntry> &entries);
    static QList<RecommendationFeedbackEntry> fromJson(const QString &json,
                                                       bool *ok = nullptr);

private:
    void evictOldest();

    QMap<QString, RecommendationFeedbackEntry> m_entries;
};
