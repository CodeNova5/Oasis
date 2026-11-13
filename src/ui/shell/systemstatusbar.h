/**
 * @file    systemstatusbar.h
 * @brief   Persistent 28 px diagnostic strip (engine state, warnings, telemetry).
 * @author  Oasis
 */
#pragma once
#include <QFrame>

class QDateTime;
class QLabel;

class SystemStatusBar : public QFrame
{
    Q_OBJECT
public:
    explicit SystemStatusBar(QWidget *parent = nullptr);

    /// Capture engine state and the adapter it is bound to.
    void setMonitoringState(bool active, const QString &adapter = QString());
    /// Latest notification or status line. Overrides the engine text.
    void setMessage(const QString &text, const QString &tooltip = QString());
    /// Degraded/error link. Empty text hides it.
    void setWarning(const QString &text, bool critical = false);
    void setSpeedText(const QString &rx, const QString &tx);
    void setHardware(int cpuPercent, int ramPercent);
    void setLastUpdated(const QDateTime &when);

signals:
    void messageActivated();
    void warningActivated();

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    QLabel *m_message = nullptr;
    QLabel *m_warning = nullptr;
    QLabel *m_rx = nullptr;
    QLabel *m_tx = nullptr;
    QLabel *m_cpu = nullptr;
    QLabel *m_ram = nullptr;
    QLabel *m_updated = nullptr;
    QLabel *m_localFirst = nullptr;
    QString m_adapter;
    bool    m_active = false;
};
