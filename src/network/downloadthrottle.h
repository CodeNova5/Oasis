/**
 * @file    downloadthrottle.h
 * @brief   WinDivert based inbound (download) bandwidth shaper.
 * @author  Ali Sakkaf
 */
#pragma once

#include <QHash>
#include <QMutex>
#include <QString>
#include <QThread>

// Windows QoS only shapes egress traffic, so throttling a download needs the
// packets themselves. This shaper diverts inbound TCP/UDP packets for the
// throttled executables through WinDivert and re-injects each one on a
// per-executable token schedule, which backs the sender off through TCP flow
// control. All work happens on this thread; the GUI only hands over policies.
class DownloadShaper final : public QThread
{
    Q_OBJECT
public:
    explicit DownloadShaper(QObject *parent = nullptr);
    ~DownloadShaper() override;

    // Empty when WinDivert is usable, otherwise the reason it is not.
    static QString unavailableReason();

    // Keys are normalized executable paths (see ThrottlePolicyManager), values
    // are limits in bits per second. Thread-safe; wakes the shaper thread.
    void setPolicies(const QHash<QString, quint64> &policies);
    void stop();

signals:
    void shaperError(const QString &message);
    void limitingActiveChanged(bool active);

protected:
    void run() override;

private:
    bool stopRequested() const;

    mutable QMutex m_mutex;
    QHash<QString, quint64> m_policies;
    bool m_stopRequested = false;
    void *m_wakeEvent = nullptr;
};
