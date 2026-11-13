/**
 * @file    appsidebar.h
 * @brief   Expanded 232 px navigation sidebar for the application shell.
 * @author  Oasis
 */
#pragma once
#include <QFrame>
#include <QVector>

class QVBoxLayout;
class QButtonGroup;
class QToolButton;

class AppSidebar : public QFrame
{
    Q_OBJECT
public:
    explicit AppSidebar(QWidget *parent = nullptr);

    /// Add a section header to the scrolling top group. Returns its index.
    void addSection(const QString &title);
    /// Add a nav item; returns the index used by itemActivated().
    int addItem(const QString &label);
    /// Add a section header in the pinned bottom group (Settings, Help).
    void addPinnedSection(const QString &title);
    int addPinnedItem(const QString &label);

    int count() const { return m_items.size(); }
    int currentIndex() const { return m_current; }
    void setCurrentIndex(int index);

signals:
    void itemActivated(int index);

private:
    QToolButton *createItem(const QString &label, int index);

    QVBoxLayout   *m_topLayout = nullptr;
    QVBoxLayout   *m_bottomLayout = nullptr;
    QButtonGroup  *m_group = nullptr;
    QVector<QToolButton *> m_items;
    int            m_current = -1;
};
