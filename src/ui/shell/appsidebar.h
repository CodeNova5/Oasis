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
class QPushButton;
class QPaintEvent;

class AppSidebar : public QFrame
{
    Q_OBJECT
public:
    explicit AppSidebar(QWidget *parent = nullptr);

    /// Add a nav item; returns the index used by itemActivated().
    int addItem(const QString &label);
    /// Add a nav item in the pinned bottom group (Settings).
    int addPinnedItem(const QString &label);

    int count() const { return m_items.size(); }
    int currentIndex() const { return m_current; }
    void setCurrentIndex(int index);

signals:
    void itemActivated(int index);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QPushButton *createItem(const QString &label, int index);

    QVBoxLayout   *m_topLayout = nullptr;
    QVBoxLayout   *m_bottomLayout = nullptr;
    QButtonGroup  *m_group = nullptr;
    QVector<QPushButton *> m_items;
    int            m_current = -1;
};
