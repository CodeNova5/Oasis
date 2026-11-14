/**
 * @file    activitytimeline.h
 * @brief   Interactive dual-series bandwidth chart with anomaly markers.
 *
 * Renders the samples and markers it is given and owns no timer or capture
 * state. Selecting a range emits bucket indices; clicking once clears the
 * selection, matching the Activity screen's brush behaviour.
 *
 * @author  Oasis
 */
#pragma once

#include <QDateTime>
#include <QVector>
#include <QWidget>

#include "activity/activityseries.h"

class QPainter;

struct ActivityMarker
{
    QDateTime at;
    QString   tone;   // warning, danger, success, info
    QString   label;
};

class ActivityTimeline : public QWidget
{
    Q_OBJECT
public:
    explicit ActivityTimeline(QWidget *parent = nullptr);

    void setPoints(const QVector<Activity::SeriesPoint> &points);
    void setMarkers(const QVector<ActivityMarker> &markers);
    void setRange(Activity::Range range);
    void setBucketSeconds(int seconds);
    void setPlaceholder(const QString &text);

    void clearSelection();
    /// Restores a brush without emitting, so a host can keep a time selection
    /// stable while new samples arrive.
    void setSelection(int first, int last);
    bool hasSelection() const { return m_selFirst >= 0 && m_selLast > m_selFirst; }
    int selectionFirst() const { return m_selFirst; }
    int selectionLast() const { return m_selLast; }

    QSize sizeHint() const override { return QSize(720, 214); }
    QSize minimumSizeHint() const override { return QSize(260, 150); }

signals:
    void selectionChanged(int first, int last);
    void selectionCleared();

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void leaveEvent(QEvent *event) override;
    void changeEvent(QEvent *event) override;

private:
    int indexAtX(int x) const;
    int plotLeft() const;
    int plotRight() const;
    int plotTop() const;
    int plotBottom() const;
    QRect plotRect() const;
    double xForIndex(int index) const;
    void paintEmpty(QPainter &painter);
    void paintChart(QPainter &painter);
    void paintHover(QPainter &painter);
    void notifySelection();

    QVector<Activity::SeriesPoint> m_points;
    QVector<ActivityMarker> m_markers;
    Activity::Range m_range = Activity::Range::Hour;
    int m_bucketSeconds = 60;
    QString m_placeholder;

    int m_hover = -1;
    int m_anchor = -1;
    int m_selFirst = -1;
    int m_selLast = -1;
    bool m_dragging = false;
};
