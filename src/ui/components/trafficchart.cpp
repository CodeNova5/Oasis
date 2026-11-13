/**
 * @file    trafficchart.cpp
 * @author  Oasis
 */
#include "trafficchart.h"

#include "ui/theme/colors.h"
#include "ui/theme/dimensions.h"
#include "ui/theme/thememanager.h"
#include "ui/theme/typography.h"

#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QStyle>
#include <QLinearGradient>

#include <cmath>

namespace {

constexpr int kLeftMargin = 58;
constexpr int kRightMargin = 12;
constexpr int kTopMargin = 12;
constexpr int kBottomMargin = 24;
constexpr int kGridLines = 4;
constexpr qint64 kVisibleWindowMs = 30 * 1000;
constexpr int kSmoothingRadius = 3;

QString formatAxisValue(double bytesPerSecond)
{
    if (bytesPerSecond <= 0.0)
        return QStringLiteral("0");
    const char *units[] = { "B/s", "KB/s", "MB/s", "GB/s" };
    int unit = 0;
    double value = bytesPerSecond;
    while (value >= 1024.0 && unit < 3) {
        value /= 1024.0;
        ++unit;
    }
    const int precision = value >= 10.0 ? 0 : 1;
    return QString::number(value, 'f', precision) + QLatin1Char(' ')
           + QString::fromLatin1(units[unit]);
}

/// Round an axis maximum up to 1, 2 or 5 × 10^n so gridline labels stay clean.
double niceCeiling(double maximum)
{
    if (maximum <= 0.0)
        return 0.0;
    const double magnitude = std::pow(10.0, std::floor(std::log10(maximum)));
    const double normalized = maximum / magnitude;
    double step = 10.0;
    if (normalized <= 1.0)
        step = 1.0;
    else if (normalized <= 2.0)
        step = 2.0;
    else if (normalized <= 5.0)
        step = 5.0;
    return step * magnitude;
}

QVector<Overview::TrafficPoint> smoothSeries(
    const QVector<Overview::TrafficPoint> &samples)
{
    QVector<Overview::TrafficPoint> smoothed = samples;
    for (int i = 0; i < samples.size(); ++i) {
        double rxTotal = 0.0;
        double txTotal = 0.0;
        double weightTotal = 0.0;

        const qint64 timestamp = samples.at(i).timestamp.toMSecsSinceEpoch();
        const int first = qMax(0, i - kSmoothingRadius);
        const int last = qMin(samples.size() - 1, i + kSmoothingRadius);
        for (int j = first; j <= last; ++j) {
            const qint64 neighborTimestamp = samples.at(j).timestamp.toMSecsSinceEpoch();
            if (samples.at(i).timestamp.isValid() && samples.at(j).timestamp.isValid()
                && qAbs(neighborTimestamp - timestamp) > kSmoothingRadius * 1000)
                continue;

            const double weight = kSmoothingRadius + 1 - qAbs(j - i);
            rxTotal += double(samples.at(j).rxBytesPerSecond) * weight;
            txTotal += double(samples.at(j).txBytesPerSecond) * weight;
            weightTotal += weight;
        }

        if (weightTotal > 0.0) {
            smoothed[i].rxBytesPerSecond = qRound64(rxTotal / weightTotal);
            smoothed[i].txBytesPerSecond = qRound64(txTotal / weightTotal);
        }
    }
    return smoothed;
}

} // namespace

TrafficChart::TrafficChart(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("TrafficChart"));
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setCursor(Qt::PointingHandCursor);
    setAccessibleName(QStringLiteral("Network traffic for the last 30 seconds"));
    setToolTip(QStringLiteral("Download and upload rate over the last 30 seconds."));

    connect(&ThemeManager::instance(), &ThemeManager::themeChanged,
            this, [this](ThemeManager::Mode) { update(); });
}

void TrafficChart::setSeries(const QVector<Overview::TrafficPoint> &points)
{
    m_points = points;
    update();
}

void TrafficChart::clear()
{
    m_points.clear();
    update();
}

void TrafficChart::setPlaceholder(const QString &text)
{
    m_placeholder = text;
    update();
}

void TrafficChart::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setRenderHint(QPainter::TextAntialiasing, true);

    if (m_points.isEmpty()) {
        paintEmpty(painter);
        return;
    }
    paintSeries(painter);
}

void TrafficChart::paintEmpty(QPainter &painter)
{
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
    painter.setPen(Theme::qcolor(palette.textMuted));
    QFont f = font();
    f.setPixelSize(Theme::Type::Body);
    painter.setFont(f);
    painter.drawText(rect(), Qt::AlignCenter,
                     m_placeholder.isEmpty()
                         ? QStringLiteral("Waiting for the first samples…")
                         : m_placeholder);
}

void TrafficChart::paintSeries(QPainter &painter)
{
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
    const QColor download = Theme::qcolor(palette.chartDownload);
    const QColor upload = Theme::qcolor(palette.chartUpload);
    const QColor grid = Theme::qcolor(palette.borderDefault);
    const QColor muted = Theme::qcolor(palette.textMuted);

    const QRectF plot(kLeftMargin, kTopMargin,
                      qMax(10, width() - kLeftMargin - kRightMargin),
                      qMax(10, height() - kTopMargin - kBottomMargin));

    // Show only the trailing five minutes, anchored to the newest sample.
    QDateTime endTime;
    for (const auto &point : m_points) {
        if (point.timestamp.isValid())
            endTime = point.timestamp;
    }

    QVector<Overview::TrafficPoint> visible;
    visible.reserve(m_points.size());
    const qint64 endMs = endTime.isValid() ? endTime.toMSecsSinceEpoch() : 0;
    const qint64 startMs = endMs - kVisibleWindowMs;
    for (const auto &point : m_points) {
        if (!endTime.isValid() || !point.timestamp.isValid()
            || point.timestamp.toMSecsSinceEpoch() >= startMs) {
            visible.push_back(point);
        }
    }

    if (visible.isEmpty()) {
        paintEmpty(painter);
        return;
    }

    visible = smoothSeries(visible);

    double maximum = 0.0;
    for (const auto &point : visible) {
        maximum = qMax(maximum, double(point.rxBytesPerSecond));
        maximum = qMax(maximum, double(point.txBytesPerSecond));
    }
    const double axisMax = niceCeiling(maximum);

    QFont axisFont = font();
    axisFont.setPixelSize(Theme::Type::Metadata);
    painter.setFont(axisFont);

    // Subtle dotted grid with a restrained Y-axis scale.
    for (int i = 0; i <= kGridLines; ++i) {
        const double ratio = double(i) / double(kGridLines);
        const double y = plot.top() + plot.height() * ratio;
        painter.setPen(QPen(grid, 1, Qt::DotLine));
        painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y));
        painter.setPen(muted);
        painter.drawText(QRectF(0, y - 8, kLeftMargin - 8, 16),
                         Qt::AlignRight | Qt::AlignVCenter,
                         formatAxisValue(axisMax * (1.0 - ratio)));
    }

    const QDateTime startTime = endTime.isValid()
                                    ? endTime.addMSecs(-kVisibleWindowMs)
                                    : QDateTime();
    for (int i = 0; i <= 5; ++i) {
        const double ratio = double(i) / 5.0;
        const double x = plot.left() + plot.width() * ratio;
        const QString label = startTime.isValid()
                                  ? startTime.addSecs(i * 6).toString(QStringLiteral("HH:mm:ss"))
                                  : QString();
        painter.setPen(muted);
        painter.drawText(QRectF(x - 34, plot.bottom() + 4, 68, 18),
                         Qt::AlignHCenter | Qt::AlignTop, label);
    }

    const auto buildPath = [&](bool downloadSeries) {
        QVector<QPointF> points;
        points.reserve(visible.size());

        for (int i = 0; i < visible.size(); ++i) {
            const auto &sample = visible.at(i);
            const double value = downloadSeries
                                     ? double(sample.rxBytesPerSecond)
                                     : double(sample.txBytesPerSecond);

            double ratio = visible.size() == 1
                               ? 1.0
                               : double(i) / double(visible.size() - 1);
            if (endTime.isValid() && sample.timestamp.isValid()) {
                ratio = qBound(0.0,
                               double(sample.timestamp.toMSecsSinceEpoch() - startMs)
                                   / double(kVisibleWindowMs),
                               1.0);
            }

            const double x = plot.left() + plot.width() * ratio;
            const double y = plot.bottom()
                             - (axisMax > 0.0 ? value / axisMax : 0.0) * plot.height();
            points.push_back(QPointF(x, y));
        }

        QPainterPath path;
        if (points.isEmpty())
            return path;
        path.moveTo(points.first());

        if (points.size() == 2) {
            path.lineTo(points.last());
            return path;
        }

        // Smooth Catmull-Rom-like cubic segments; clamp control-point heights
        // to each segment's endpoints so interpolation cannot create spikes.
        for (int i = 0; i < points.size() - 1; ++i) {
            const QPointF p0 = points.at(qMax(0, i - 1));
            const QPointF p1 = points.at(i);
            const QPointF p2 = points.at(i + 1);
            const QPointF p3 = points.at(qMin(points.size() - 1, i + 2));
            const double dx = p2.x() - p1.x();

            QPointF c1(p1.x() + dx / 3.0, p1.y() + (p2.y() - p0.y()) / 6.0);
            QPointF c2(p2.x() - dx / 3.0, p2.y() - (p3.y() - p1.y()) / 6.0);
            const double low = qMin(p1.y(), p2.y());
            const double high = qMax(p1.y(), p2.y());
            c1.setY(qBound(low, c1.y(), high));
            c2.setY(qBound(low, c2.y(), high));
            path.cubicTo(c1, c2, p2);
        }
        return path;
    };

    const auto paintSeriesPath = [&](const QPainterPath &line, const QColor &color) {
        if (line.isEmpty())
            return;

        QPainterPath area = line;
        area.lineTo(plot.right(), plot.bottom());
        area.lineTo(plot.left(), plot.bottom());
        area.closeSubpath();

        QLinearGradient fill(plot.topLeft(), plot.bottomLeft());
        QColor top = color;
        top.setAlpha(76);
        QColor bottom = color;
        bottom.setAlpha(0);
        fill.setColorAt(0.0, top);
        fill.setColorAt(1.0, bottom);

        painter.save();
        painter.setPen(Qt::NoPen);
        painter.setBrush(fill);
        painter.drawPath(area);
        painter.setBrush(Qt::NoBrush);
        painter.setPen(QPen(color, 2.0, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        painter.drawPath(line);
        painter.restore();
    };

    paintSeriesPath(buildPath(true), download);
    paintSeriesPath(buildPath(false), upload);

    // Compact legend in the chart's upper-right corner.
    int legendX = qMax(kLeftMargin + 8, width() - 210);
    const int legendY = kTopMargin;
    const auto legendEntry = [&](const QString &text, const QColor &color) {
        painter.setPen(Qt::NoPen);
        painter.setBrush(color);
        painter.drawRoundedRect(QRectF(legendX, legendY + 2, 8, 8), 2, 2);
        painter.setPen(muted);
        painter.drawText(QRectF(legendX + 14, legendY - 4, 78, 20),
                         Qt::AlignLeft | Qt::AlignVCenter, text);
        legendX += 88;
    };
    legendEntry(QStringLiteral("Download"), download);
    legendEntry(QStringLiteral("Upload"), upload);
}

void TrafficChart::mouseReleaseEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton) {
        emit activated();
        event->accept();
        return;
    }
    QWidget::mouseReleaseEvent(event);
}

void TrafficChart::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::PaletteChange || event->type() == QEvent::StyleChange)
        update();
    QWidget::changeEvent(event);
}
