/**
 * @file    trafficchart.h
 * @brief   Dual-series download/upload area chart for the last five minutes
 *          (SCREENS_SPEC.md Screen 01, DESIGN_SYSTEM.md §2.2).
 *
 * Custom-painted so the chart follows the theme tokens and stays readable at
 * every Windows scaling level. It only renders the samples it is given; it owns
 * no timer and no capture state.
 *
 * @author  Oasis
 */
#pragma once
#include <QDateTime>
#include <QVector>
#include <QWidget>

namespace Overview {

struct TrafficPoint
{
    QDateTime timestamp;
    quint64   rxBytesPerSecond = 0;
    quint64   txBytesPerSecond = 0;
};

} // namespace Overview

class TrafficChart : public QWidget
{
    Q_OBJECT
public:
    explicit TrafficChart(QWidget *parent = nullptr);

    void setSeries(const QVector<Overview::TrafficPoint> &points);
    void clear();

    /// Empty-chart copy, e.g. while monitoring is stopped.
    void setPlaceholder(const QString &text);

    QSize sizeHint() const override { return QSize(560, 200); }
    QSize minimumSizeHint() const override { return QSize(240, 150); }

signals:
    void activated();

protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void changeEvent(QEvent *event) override;

private:
    void paintEmpty(QPainter &painter);
    void paintSeries(QPainter &painter);

    QVector<Overview::TrafficPoint> m_points;
    QString m_placeholder;
};
