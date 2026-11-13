/**
 * @file    emptystatewidget.h
 * @brief   Centered empty/degraded panel (DESIGN_SYSTEM.md §7.5).
 * @author  Oasis
 */
#pragma once
#include <QWidget>

class QLabel;
class QPushButton;

class EmptyStateWidget : public QWidget
{
    Q_OBJECT
public:
    explicit EmptyStateWidget(QWidget *parent = nullptr);

    void setTitle(const QString &title);
    void setDetail(const QString &detail);
    /// An empty text hides the action button.
    void setAction(const QString &text);
    void setActionVariant(const QString &variant);

signals:
    void actionTriggered();

private:
    QLabel      *m_icon = nullptr;
    QLabel      *m_title = nullptr;
    QLabel      *m_detail = nullptr;
    QPushButton *m_action = nullptr;
};
