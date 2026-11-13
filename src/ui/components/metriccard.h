/**
 * @file    metriccard.h
 * @brief   KPI card: 12 px label, 28 px value, 11 px caption
 *          (DESIGN_SYSTEM.md §7.2).
 * @author  Oasis
 */
#pragma once
#include <QFrame>

class QLabel;

class MetricCard : public QFrame
{
    Q_OBJECT
public:
    explicit MetricCard(const QString &label, QWidget *parent = nullptr);

    void setValue(const QString &value);
    void setCaption(const QString &caption);
    /// Tint the value text (e.g. download blue, upload green).
    void setValueColor(const QColor &color);
    /// Make the whole card behave as one control (Overview → Activity).
    void setClickable(bool clickable);
    void setToolTipText(const QString &text);

signals:
    void clicked();

protected:
    void mouseReleaseEvent(QMouseEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;

private:
    QLabel *m_label = nullptr;
    QLabel *m_value = nullptr;
    QLabel *m_caption = nullptr;
    bool    m_clickable = false;
};
