/**
 * @file    appheader.h
 * @brief   Persistent page header (stacked title, page actions, utilities).
 * @author  Oasis
 */
#pragma once
#include <QFrame>

class QLabel;
class QPushButton;
class QWidget;

class AppHeader : public QFrame
{
    Q_OBJECT
public:
    enum class MonitorState { Active, Degraded, Stopped };

    explicit AppHeader(QWidget *parent = nullptr);

    void setPage(const QString &title, const QString &subtitle = QString());
    void setPageActions(QWidget *actions);
    void setPageActionsVisible(bool visible);
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
    QWidget     *m_actionsHost = nullptr;
    QWidget     *m_actions = nullptr;
    QLabel      *m_pill = nullptr;
    QPushButton *m_themeButton = nullptr;
    QPushButton *m_minimizeButton = nullptr;
    MonitorState m_state = MonitorState::Stopped;
};
