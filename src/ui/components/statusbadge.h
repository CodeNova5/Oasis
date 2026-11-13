/**
 * @file    statusbadge.h
 * @brief   Pill badge for operational / enforcement / attribution status
 *          (DESIGN_SYSTEM.md §6).
 * @author  Oasis
 */
#pragma once
#include <QLabel>

class StatusBadge : public QLabel
{
    Q_OBJECT
public:
    enum class Status {
        Active,
        Inactive,
        Pending,
        Degraded,
        StoredOnly,
        Failed,
        Unknown,
        Expired
    };
    Q_ENUM(Status)

    explicit StatusBadge(QWidget *parent = nullptr);

    /// Set the state and its label. An empty text uses the state's default
    /// label, so a caller never has to repeat the vocabulary of §6.1.
    void setStatus(Status status, const QString &text = QString());
    Status status() const { return m_status; }

    /// The QSS property value used for the tint (e.g. "stored-only").
    static QString token(Status status);
    static QString defaultLabel(Status status);

private:
    void restyle();

    Status m_status = Status::Unknown;
};
