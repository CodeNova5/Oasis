/**
 * @file    appheader.h
 * @brief   Persistent page header (stacked title, page actions, utilities).
 * @author  Oasis
 */
#pragma once
#include <QFrame>

class QLabel;
class QWidget;

class AppHeader : public QFrame
{
    Q_OBJECT
public:
    explicit AppHeader(QWidget *parent = nullptr);

    void setPage(const QString &title, const QString &subtitle = QString());
    void setPageActions(QWidget *actions);
    void setPageActionsVisible(bool visible);

private:
    QLabel  *m_title = nullptr;
    QLabel  *m_subtitle = nullptr;
    QWidget *m_actionsHost = nullptr;
    QWidget *m_actions = nullptr;
};
