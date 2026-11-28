/**
 * @file    systemtrayicon.h
 * @author  Oasis
 */
#pragma once
#include <QList>
#include <QObject>
#include <QPair>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QTimer>

class SystemTrayIcon : public QObject
{
    Q_OBJECT
public:
    explicit SystemTrayIcon(QObject *parent=nullptr);
    void setSpeed(quint64 rxBps, quint64 txBps);
    void show()  { m_tray->show(); }
    QSystemTrayIcon *tray() const { return m_tray; }

    // DS-011: a delivered notice as a tray balloon. A Windows tray balloon has no
    // buttons, so the actions of the latest notice live in the context menu
    // (`setNoticeActions`) and clicking the balloon brings the window forward.
    void showNotice(const QString &title, const QString &message, bool critical);
    // Rebuilds the "Latest Data Saver notice" submenu. `actions` holds
    // (token, label) pairs; an empty list hides the submenu and keeps the menu
    // from offering an action for a notice that is no longer current.
    void setNoticeActions(const QString &noticeKey,
                          const QList<QPair<QString, QString>> &actions);

signals:
    void showRequested();
    void quitRequested();
    // One action was chosen from the latest notice's submenu. `noticeKey` is the
    // key the notice carried, so the receiver can resolve the same decision.
    void noticeActionRequested(const QString &noticeKey, const QString &token);

private:
    QSystemTrayIcon *m_tray;
    QMenu           *m_menu;
    QMenu           *m_noticeMenu;
    QString          m_noticeKey;
    QIcon buildIcon(quint64 rx, quint64 tx);
};
