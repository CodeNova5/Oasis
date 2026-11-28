/**
 * @file    networkwidgetnotices.cpp
 * @brief   DS-011: retained notice evidence and the two reversal actions.
 * @author  Oasis
 *
 * A notice is delivered once, but the user may click its action minutes later,
 * possibly from the tray while the window is hidden. The decision and the
 * observation behind the notice are therefore kept, keyed by the coordinator
 * key the notice carried, until the bounded retention window drops the oldest
 * entry. Acting on a notice only writes a rule; the next milestone crossing
 * resolves it through the normal precedence path, so no action here bypasses
 * DS-008 or DS-009.
 */

#include "networkwidget.h"

#include "datasavernotification.h"

#include <QDateTime>

namespace {

// Delivered notices whose actions stay available. The coordinator already folds
// repeats per key, so one burst of the same decision is one entry; this cap is
// what keeps a long session bounded.
constexpr int kMaxRetainedNotices = 24;

} // namespace

void NetworkWidget::retainNotice(
    const QString &notificationKey,
    const DataSaverNotifications::DecisionNotice &evidence)
{
    if (notificationKey.isEmpty())
        return;

    // A repeat of the same key replaces the older evidence without growing the
    // order list, so the entry keeps its position and is evicted last.
    if (!m_noticeEvidence.contains(notificationKey))
        m_noticeOrder.append(notificationKey);
    m_noticeEvidence.insert(notificationKey, evidence);

    while (m_noticeOrder.size() > kMaxRetainedNotices)
        m_noticeEvidence.remove(m_noticeOrder.takeFirst());
}

bool NetworkWidget::noticeEvidence(
    const QString &notificationKey,
    DataSaverNotifications::DecisionNotice *evidence) const
{
    if (notificationKey.isEmpty())
        return false;

    const auto found = m_noticeEvidence.constFind(notificationKey);
    if (found == m_noticeEvidence.constEnd())
        return false;

    if (evidence)
        *evidence = found.value();
    return true;
}

bool NetworkWidget::allowOnceForNotice(const QString &notificationKey, QString *error)
{
    DataSaverNotifications::DecisionNotice evidence;
    if (!noticeEvidence(notificationKey, &evidence)) {
        if (error) *error = QStringLiteral("the notice is no longer available");
        return false;
    }

    // Tier 2 only: a one-hour session override, flow-scoped when the observation
    // has a usable flow id. It never writes to disk and expires on its own.
    const bool applied =
        DataSaverNotifications::allowOnce(evidence.observation, evidence.decision,
                                          &m_sessionOverrides,
                                          QDateTime::currentDateTimeUtc(), nullptr, error);
    if (applied)
        emit dataSaverNoticeResolved(notificationKey,
                                     DataSaverNotifications::allowOnceActionToken());
    return applied;
}

bool NetworkWidget::alwaysAllowForNotice(const QString &notificationKey, bool confirmed,
                                         QString *error)
{
    DataSaverNotifications::DecisionNotice evidence;
    if (!noticeEvidence(notificationKey, &evidence)) {
        if (error) *error = QStringLiteral("the notice is no longer available");
        return false;
    }

    // Tier 1: the pinned store refuses an unconfirmed Allow rule, which is the
    // DS-005 gate behind the Always Allow action.
    const bool applied =
        DataSaverNotifications::alwaysAllow(evidence.observation, evidence.decision,
                                            confirmed, QDateTime::currentDateTimeUtc(),
                                            nullptr, error);
    if (applied)
        emit dataSaverNoticeResolved(notificationKey,
                                     DataSaverNotifications::alwaysAllowActionToken());
    return applied;
}
