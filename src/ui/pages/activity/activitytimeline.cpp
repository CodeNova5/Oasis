/**
 * @file    activitytimeline.cpp
 * @author  Oasis
 */
#include "activitytimeline.h"

#include "ui/theme/colors.h"
#include "ui/theme/thememanager.h"

#include <QFontMetrics>
#include <QLinearGradient>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QtMath>

#include <algorithm>
#include <limits>

namespace {

QString formatRate(double bytesPerSecond)
{
    static const char *units[] = { "B/s", "KB/s", "MB/s", "GB/s" };
    int unit = 0;
    while (bytesPerSecond >= 1024.0 && unit < 3) {
        bytesPerSecond /= 1024.0;
        ++unit;
    }
    const int decimals = bytesPerSecond >= 100.0 || unit == 0 ? 0 : 1;
    return QStringLiteral("%1 %2")
        .arg(QString::number(bytesPerSecond, 'f', decimals),
             QString::fromLatin1(units[unit]));
}

QString formatAxisTime(const QDateTime &at, Activity::Range range)
{
    switch (range) {
    case Activity::Range::Live:
        return at.toString(QStringLiteral("HH:mm:ss"));
    case Activity::Range::Hour:
        return at.toString(QStringLiteral("HH:mm"));
    case Activity::Range::Day:
        return at.toString(QStringLiteral("HH:mm"));
    case Activity::Range::Week:
        return at.toString(QStringLiteral("MMM d"));
    }
    return at.toString(QStringLiteral("HH:mm"));
}

QColor toneColor(const QString &tone, const Theme::Palette &p)
{
    if (tone == QLatin1String("danger"))
        return Theme::qcolor(p.semanticDanger);
    if (tone == QLatin1String("success"))
        return Theme::qcolor(p.semanticSuccess);
    if (tone == QLatin1String("info"))
        return Theme::qcolor(p.semanticInfo);
    return Theme::qcolor(p.semanticWarning);
}

} // namespace

ActivityTimeline::ActivityTimeline(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("activityTimeline"));
    setMouseTracking(true);
    setCursor(Qt::CrossCursor);
    setAttribute(Qt::WA_OpaquePaintEvent, false);
}

void ActivityTimeline::setPoints(const QVector<Activity::SeriesPoint> &points)
{
    m_points = points;
    if (m_selFirst >= m_points.size() || m_selLast >= m_points.size()) {
        m_selFirst = -1;
        m_selLast = -1;
    }
    m_hover = -1;
    update();
}

void ActivityTimeline::setMarkers(const QVector<ActivityMarker> &markers)
{
    m_markers = markers;
    update();
}

void ActivityTimeline::setRange(Activity::Range range)
{
    m_range = range;
    update();
}

void ActivityTimeline::setBucketSeconds(int seconds)
{
    m_bucketSeconds = std::max(1, seconds);
    update();
}

void ActivityTimeline::setPlaceholder(const QString &text)
{
    m_placeholder = text;
    update();
}

void ActivityTimeline::clearSelection()
{
    if (m_selFirst < 0 && m_selLast < 0)
        return;
    m_selFirst = -1;
    m_selLast = -1;
    m_dragging = false;
    m_anchor = -1;
    update();
    emit selectionCleared();
}

void ActivityTimeline::setSelection(int first, int last)
{
    if (first < 0 || last < 0 || first >= m_points.size() || last >= m_points.size()) {
        m_selFirst = -1;
        m_selLast = -1;
    } else {
        m_selFirst = std::min(first, last);
        m_selLast = std::max(first, last);
    }
    update();
}

int ActivityTimeline::plotLeft() const { return 58; }
int ActivityTimeline::plotRight() const { return width() - 12; }
int ActivityTimeline::plotTop() const { return 14; }
int ActivityTimeline::plotBottom() const { return height() - 26; }

QRect ActivityTimeline::plotRect() const
{
    return QRect(QPoint(plotLeft(), plotTop()),
                 QPoint(std::max(plotLeft(), plotRight()),
                        std::max(plotTop(), plotBottom())));
}

double ActivityTimeline::xForIndex(int index) const
{
    if (m_points.size() <= 1)
        return plotRect().center().x();
    const double step = double(plotRect().width()) / double(m_points.size() - 1);
    return plotRect().left() + step * index;
}

int ActivityTimeline::indexAtX(int x) const
{
    if (m_points.isEmpty())
        return -1;
    const QRect r = plotRect();
    if (x < r.left())
        return 0;
    if (x > r.right())
        return m_points.size() - 1;
    if (m_points.size() == 1)
        return 0;
    const double step = double(r.width()) / double(m_points.size() - 1);
    return std::min(int(m_points.size()) - 1,
                    std::max(0, int(qRound((x - r.left()) / step))));
}

void ActivityTimeline::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setRenderHint(QPainter::TextAntialiasing, true);

    bool hasData = false;
    for (const Activity::SeriesPoint &point : m_points) {
        if (point.totalBytes() > 0) {
            hasData = true;
            break;
        }
    }
    if (!hasData)
        paintEmpty(painter);
    else
        paintChart(painter);
}

void ActivityTimeline::paintEmpty(QPainter &painter)
{
    const Theme::Palette p = Theme::palette(ThemeManager::instance().isDark());
    painter.setPen(Theme::qcolor(p.textMuted));
    QFont font = painter.font();
    font.setPointSizeF(font.pointSizeF() + 0.5);
    painter.setFont(font);
    painter.drawText(rect(), Qt::AlignCenter,
                     m_placeholder.isEmpty()
                         ? QStringLiteral("No bandwidth samples in this range yet.")
                         : m_placeholder);
}

void ActivityTimeline::paintChart(QPainter &painter)
{
    const Theme::Palette p = Theme::palette(ThemeManager::instance().isDark());
    const QRect plot = plotRect();
    if (plot.width() < 40 || plot.height() < 40)
        return;

    const QColor accent = Theme::qcolor(p.accentPrimary);
    const QColor download = Theme::qcolor(p.chartDownload);
    const QColor upload = Theme::qcolor(p.chartUpload);
    const QColor textMuted = Theme::qcolor(p.textMuted);
    const QColor textSecondary = Theme::qcolor(p.textSecondary);
    const QColor grid = Theme::qcolor(p.borderDefault);

    quint64 maxRx = 0;
    quint64 maxTx = 0;
    for (const Activity::SeriesPoint &point : m_points) {
        maxRx = std::max(maxRx, point.rxBytes);
        maxTx = std::max(maxTx, point.txBytes);
    }
    double maxValue = double(std::max(maxRx, maxTx));
    if (maxValue <= 0.0)
        maxValue = 1.0;
    maxValue *= 1.12;

    // ── Grid and y labels ────────────────────────────────────────────────
    QFont small = painter.font();
    small.setPointSizeF(9.0);
    painter.setFont(small);
    for (int line = 0; line <= 4; ++line) {
        const double ratio = line / 4.0;
        const int y = plot.bottom() - int(qRound(ratio * plot.height()));
        painter.setPen(QPen(grid, 1, line == 0 ? Qt::SolidLine : Qt::DotLine));
        painter.drawLine(plot.left(), y, plot.right(), y);
        painter.setPen(textMuted);
        painter.drawText(QRect(0, y - 8, plot.left() - 8, 16),
                         Qt::AlignRight | Qt::AlignVCenter,
                         formatRate(maxValue * ratio
                                    / double(std::max(1, m_bucketSeconds))));
    }

    // ── x labels ────────────────────────────────────────────────────────
    const int labelCount = std::min(5, int(m_points.size()));
    for (int i = 0; i < labelCount; ++i) {
        const int index = labelCount == 1
            ? 0
            : int(qRound(double(i) * (m_points.size() - 1) / double(labelCount - 1)));
        const int x = int(qRound(xForIndex(index)));
        painter.setPen(textMuted);
        const int align = i == 0 ? Qt::AlignLeft
            : (i == labelCount - 1 ? Qt::AlignRight : Qt::AlignHCenter);
        QRect labelRect(x - 40, plot.bottom() + 6, 80, 16);
        if (i == 0) labelRect.moveLeft(plot.left());
        if (i == labelCount - 1) labelRect.moveRight(plot.right());
        painter.drawText(labelRect, align | Qt::AlignVCenter,
                         formatAxisTime(m_points.at(index).start, m_range));
    }

    // ── Curves ──────────────────────────────────────────────────────────
    QVector<QPointF> rxPoints;
    QVector<QPointF> txPoints;
    rxPoints.reserve(m_points.size());
    txPoints.reserve(m_points.size());
    for (int i = 0; i < m_points.size(); ++i) {
        const int x = int(qRound(xForIndex(i)));
        const Activity::SeriesPoint &point = m_points.at(i);
        rxPoints.append(QPointF(x, plot.bottom()
            - (double(point.rxBytes) / maxValue) * plot.height()));
        txPoints.append(QPointF(x, plot.bottom()
            - (double(point.txBytes) / maxValue) * plot.height()));
    }

    auto buildPath = [&](const QVector<QPointF> &points) {
        QPainterPath path(points.first());
        for (int i = 1; i < points.size(); ++i) {
            const QPointF prev = points.at(i - 1);
            const QPointF cur = points.at(i);
            const double midX = (prev.x() + cur.x()) / 2.0;
            path.cubicTo(QPointF(midX, prev.y()), QPointF(midX, cur.y()), cur);
        }
        return path;
    };

    auto fillPath = [&](const QPainterPath &line, const QColor &color) {
        QPainterPath area = line;
        area.lineTo(QPointF(rxPoints.last().x(), plot.bottom()));
        area.lineTo(QPointF(rxPoints.first().x(), plot.bottom()));
        area.closeSubpath();
        QLinearGradient gradient(0, plot.top(), 0, plot.bottom());
        QColor top = color;
        top.setAlpha(ThemeManager::instance().isDark() ? 55 : 38);
        QColor bottom = color;
        bottom.setAlpha(0);
        gradient.setColorAt(0.0, top);
        gradient.setColorAt(1.0, bottom);
        painter.fillPath(area, gradient);
    };

    const QPainterPath rxPath = buildPath(rxPoints);
    const QPainterPath txPath = buildPath(txPoints);
    fillPath(txPath, upload);
    fillPath(rxPath, download);

    painter.setPen(QPen(upload, 1.6));
    painter.drawPath(txPath);
    painter.setPen(QPen(download, 2.0));
    painter.drawPath(rxPath);

    // ── Selection band ──────────────────────────────────────────────────
    if (hasSelection()) {
        const double step = m_points.size() > 1
            ? double(plot.width()) / double(m_points.size() - 1) : double(plot.width());
        const double left = std::max(double(plot.left()),
                                     xForIndex(m_selFirst) - step / 2.0);
        const double right = std::min(double(plot.right()),
                                      xForIndex(m_selLast) + step / 2.0);
        QColor band = accent;
        band.setAlpha(ThemeManager::instance().isDark() ? 40 : 28);
        painter.fillRect(QRectF(left, plot.top(), right - left, plot.height()), band);
        painter.setPen(QPen(accent, 1, Qt::DashLine));
        painter.drawLine(QPointF(left, plot.top()), QPointF(left, plot.bottom()));
        painter.drawLine(QPointF(right, plot.top()), QPointF(right, plot.bottom()));
    }

    // ── Event markers ───────────────────────────────────────────────────
    for (const ActivityMarker &marker : m_markers) {
        int best = -1;
        qint64 bestDelta = std::numeric_limits<qint64>::max();
        for (int i = 0; i < m_points.size(); ++i) {
            const qint64 delta = qAbs(m_points.at(i).start.msecsTo(marker.at));
            if (delta < bestDelta) {
                bestDelta = delta;
                best = i;
            }
        }
        if (best < 0)
            continue;
        const double x = xForIndex(best);
        const double y = txPoints.at(best).y() < rxPoints.at(best).y()
            ? txPoints.at(best).y() : rxPoints.at(best).y();
        const QColor color = toneColor(marker.tone, p);
        painter.setPen(QPen(color, 1.2, Qt::DashLine));
        painter.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()));
        painter.setBrush(color);
        painter.setPen(QPen(Theme::qcolor(p.surfacePrimary), 1.5));
        painter.drawEllipse(QPointF(x, std::max(double(plot.top() + 5), y - 6)), 4.0, 4.0);
    }

    // ── Hover crosshair and tooltip ─────────────────────────────────────
    if (m_hover >= 0 && m_hover < m_points.size() && !m_dragging) {
        const Activity::SeriesPoint &point = m_points.at(m_hover);
        const double x = xForIndex(m_hover);
        painter.setPen(QPen(textSecondary, 1, Qt::DotLine));
        painter.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()));

        const QString when = point.start.toString(QStringLiteral("MMM d, HH:mm:ss"));
        const QString rxText = formatRate(double(point.rxBytes) / m_bucketSeconds);
        const QString txText = formatRate(double(point.txBytes) / m_bucketSeconds);
        const QString body = QStringLiteral("%1\n↓ %2    ↑ %3").arg(when, rxText, txText);

        QFont tooltipFont = painter.font();
        tooltipFont.setPointSizeF(9.0);
        painter.setFont(tooltipFont);
        const QFontMetrics metrics(tooltipFont);
        const QRect textBounds = metrics.boundingRect(QRect(0, 0, 260, 200),
                                                      Qt::AlignLeft, body);
        const int boxWidth = textBounds.width() + 20;
        const int boxHeight = textBounds.height() + 16;
        int boxX = int(x) + 14;
        if (boxX + boxWidth > plot.right())
            boxX = int(x) - boxWidth - 14;
        boxX = std::max(plot.left(), boxX);
        const int boxY = plot.top() + 6;
        const QRect box(boxX, boxY, boxWidth, boxHeight);
        painter.setPen(Qt::NoPen);
        QColor bg = Theme::qcolor(p.tooltipBackground);
        bg.setAlpha(242);
        painter.setBrush(bg);
        painter.drawRoundedRect(box, 6, 6);
        painter.setPen(QPen(grid, 1));
        painter.drawRoundedRect(box, 6, 6);
        painter.setPen(Theme::qcolor(p.tooltipText));
        painter.drawText(box.adjusted(10, 8, -10, -8), Qt::AlignLeft | Qt::AlignVCenter, body);
    }
}

void ActivityTimeline::notifySelection()
{
    if (hasSelection())
        emit selectionChanged(m_selFirst, m_selLast);
}

void ActivityTimeline::mousePressEvent(QMouseEvent *event)
{
    if (event->button() != Qt::LeftButton || m_points.isEmpty()) {
        QWidget::mousePressEvent(event);
        return;
    }
    const int index = indexAtX(int(event->pos().x()));
    if (index < 0)
        return;
    m_anchor = index;
    m_selFirst = index;
    m_selLast = index;
    m_dragging = true;
    m_hover = index;
    update();
}

void ActivityTimeline::mouseMoveEvent(QMouseEvent *event)
{
    if (m_points.isEmpty()) {
        QWidget::mouseMoveEvent(event);
        return;
    }
    const int index = indexAtX(int(event->pos().x()));
    if (m_dragging && m_anchor >= 0) {
        m_selFirst = std::min(m_anchor, index);
        m_selLast = std::max(m_anchor, index);
        m_hover = index;
        update();
        notifySelection();
    } else if (index != m_hover) {
        m_hover = index;
        update();
    }
}

void ActivityTimeline::mouseReleaseEvent(QMouseEvent *event)
{
    if (event->button() != Qt::LeftButton || !m_dragging) {
        QWidget::mouseReleaseEvent(event);
        return;
    }
    m_dragging = false;
    if (!hasSelection()) {
        // A click, not a drag: clear the brush exactly like the screen mock.
        m_selFirst = -1;
        m_selLast = -1;
        update();
        emit selectionCleared();
    } else {
        notifySelection();
    }
}

void ActivityTimeline::leaveEvent(QEvent *event)
{
    m_hover = -1;
    update();
    QWidget::leaveEvent(event);
}

void ActivityTimeline::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::PaletteChange
        || event->type() == QEvent::StyleChange
        || event->type() == QEvent::ThemeChange) {
        update();
    }
    QWidget::changeEvent(event);
}
