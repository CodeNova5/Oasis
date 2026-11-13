/**
 * @file    statusbadge.cpp
 * @author  Oasis
 */
#include "statusbadge.h"

#include "ui/theme/dimensions.h"
#include "ui/theme/typography.h"

#include <QStyle>

StatusBadge::StatusBadge(QWidget *parent)
    : QLabel(parent)
{
    setProperty("uiRole", QStringLiteral("badge"));
    setAlignment(Qt::AlignCenter);
    setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    setFixedHeight(Theme::Dim::BadgeHeight);
    setStatus(Status::Unknown);
}

QString StatusBadge::token(Status status)
{
    switch (status) {
    case Status::Active:     return QStringLiteral("active");
    case Status::Pending:    return QStringLiteral("pending");
    case Status::Degraded:   return QStringLiteral("degraded");
    case Status::StoredOnly: return QStringLiteral("stored-only");
    case Status::Failed:     return QStringLiteral("failed");
    case Status::Inactive:   return QStringLiteral("inactive");
    case Status::Expired:    return QStringLiteral("expired");
    case Status::Unknown:    break;
    }
    return QStringLiteral("unknown");
}

QString StatusBadge::defaultLabel(Status status)
{
    switch (status) {
    case Status::Active:     return QStringLiteral("Active");
    case Status::Pending:    return QStringLiteral("Pending");
    case Status::Degraded:   return QStringLiteral("Degraded");
    case Status::StoredOnly: return QStringLiteral("Stored only");
    case Status::Failed:     return QStringLiteral("Failed");
    case Status::Inactive:   return QStringLiteral("Inactive");
    case Status::Expired:    return QStringLiteral("Expired");
    case Status::Unknown:    break;
    }
    return QStringLiteral("Unknown");
}

void StatusBadge::setStatus(Status status, const QString &text)
{
    m_status = status;
    setText(text.isEmpty() ? defaultLabel(status) : text);
    setProperty("status", token(status));
    // A badge's tint is the whole signal, so give it the same tooltip the
    // tables use rather than leaving an unexplained color.
    switch (status) {
    case Status::Active:
        setToolTip(QStringLiteral("Confirmed active by the monitoring or enforcement layer."));
        break;
    case Status::Inactive:
        setToolTip(QStringLiteral("Intentionally paused or disabled."));
        break;
    case Status::Pending:
        setToolTip(QStringLiteral("Waiting for the operating system to confirm the change."));
        break;
    case Status::Degraded:
        setToolTip(QStringLiteral("Running with partial capability; some traffic or rules are not covered."));
        break;
    case Status::StoredOnly:
        setToolTip(QStringLiteral("Saved locally but not enforced: the enforcement driver is unavailable."));
        break;
    case Status::Failed:
        setToolTip(QStringLiteral("The last operation failed. Open diagnostics for details."));
        break;
    case Status::Expired:
        setToolTip(QStringLiteral("A time-bound rule has completed."));
        break;
    case Status::Unknown:
        setToolTip(QStringLiteral("Not enough evidence to determine the state."));
        break;
    }
    restyle();
}

void StatusBadge::restyle()
{
    if (style()) {
        style()->unpolish(this);
        style()->polish(this);
    }
    update();
}
