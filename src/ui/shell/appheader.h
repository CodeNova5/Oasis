/**
 * @file    appheader.h
 * @brief   Persistent 60 px page header (title, monitoring pill, utilities).
 * @author  Oasis
 */
#pragma once
#include <QFrame>

class QLabel;
class QPushButton;

class AppHeader : public QFrame
{
    Q_OBJECT
public:
    enum class MonitorState { Active, Degraded, Stopped };

    explicit AppHeader(QWidget *parent = nullptr);

    void setPage(const QString &title, const QString &subtitle = QString());
    void setMonitoringState(MonitorState state);
    void setDarkMode(bool dark);

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

signals:
    void themeToggleRequested();
    void minimizeToTrayRequested();
    void monitoringPillActivated();

private:
    void restylePill();

    QLabel      *m_title = nullptr;
    QLabel      *m_subtitle = nullptr;
    QLabel      *m_pill = nullptr;
    QPushButton *m_themeButton = nullptr;
    QPushButton *m_minimizeButton = nullptr;
    MonitorState m_state = MonitorState::Stopped;
};
