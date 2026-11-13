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

#include <cmath>

namespace {

constexpr int kLeftMargin = 58;
constexpr int kRightMargin = 12;
constexpr int kTopMargin = 12;
constexpr int kBottomMargin = 24;
constexpr int kGridLines = 4;

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

} // namespace

TrafficChart::TrafficChart(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("TrafficChart"));
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setCursor(Qt::PointingHandCursor);
    setAccessibleName(QStringLiteral("Network traffic for the last 60 minutes"));
    setToolTip(QStringLiteral("Download and upload rate over the last 60 minutes."));

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

    double maximum = 0.0;
    for (const Overview::TrafficPoint &point : m_points) {
        maximum = qMax(maximum, double(point.rxBytesPerSecond));
        maximum = qMax(maximum, double(point.txBytesPerSecond));
    }
    const double axisMax = niceCeiling(maximum);

    // ── Grid + value labels ────────────────────────────────────────────────
    QFont axisFont = font();
    axisFont.setPixelSize(Theme::Type::Metadata);
    painter.setFont(axisFont);

    for (int i = 0; i <= kGridLines; ++i) {
        const double ratio = double(i) / double(kGridLines);
        const double y = plot.top() + plot.height() * ratio;
        painter.setPen(QPen(grid, 1));
        painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y));

        painter.setPen(muted);
        const double value = axisMax * (1.0 - ratio);
        painter.drawText(QRectF(0, y - 8, kLeftMargin - 8, 16),
                         Qt::AlignRight | Qt::AlignVCenter,
                         formatAxisValue(value));
    }

    // ── Time labels ────────────────────────────────────────────────────────
    const QDateTime first = m_points.first().timestamp;
    const QDateTime last = m_points.last().timestamp;
    if (first.isValid() && last.isValid() && first != last) {
        const int ticks = 4;
        for (int i = 0; i <= ticks; ++i) {
            const double ratio = double(i) / double(ticks);
            const double x = plot.left() + plot.width() * ratio;
            const QDateTime stamp = first.addMSecs(
                qint64(last.toMSecsSinceEpoch() - first.toMSecsSinceEpoch()) * i / ticks);
            painter.setPen(muted);
            const QRectF labelRect(x - 30, plot.bottom() + 4, 60, 18);
            painter.drawText(labelRect, Qt::AlignHCenter | Qt::AlignTop,
                             stamp.toString(QStringLiteral("HH:mm")));
        }
    }

    // ── Series ─────────────────────────────────────────────────────────────
    const auto buildPath = [&](bool downloadSeries) {
        QPainterPath path;
        for (int i = 0; i < m_points.size(); ++i) {
            const Overview::TrafficPoint &point = m_points.at(i);
            const double value = downloadSeries ? double(point.rxBytesPerSecond)
                                                : double(point.txBytesPerSecond);
            const double x = m_points.size() == 1
                                 ? plot.center().x()
                                 : plot.left() + plot.width() * i / double(m_points.size() - 1);
            const double y = plot.bottom() - (axisMax > 0.0 ? value / axisMax : 0.0) * plot.height();
            if (i == 0)
                path.moveTo(x, y);
            else
                path.lineTo(x, y);
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

        QColor fill = color;
        fill.setAlpha(36);
        painter.setPen(Qt::NoPen);
        painter.setBrush(fill);
        painter.drawPath(area);

        painter.setBrush(Qt::NoBrush);
        painter.setPen(QPen(color, 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        painter.drawPath(line);
    };

    paintSeriesPath(buildPath(true), download);
    paintSeriesPath(buildPath(false), upload);

    // ── Legend ─────────────────────────────────────────────────────────────
    const int legendY = kTopMargin;
    int legendX = qMax(kLeftMargin + 8, width() - 210);
    const auto legendEntry = [&](const QString &text, const QColor &color) {
        painter.setPen(Qt::NoPen);
        painter.setBrush(color);
        painter.drawEllipse(QPointF(legendX + 4, legendY + 6), 4, 4);
        painter.setPen(muted);
        painter.drawText(QRectF(legendX + 12, legendY - 4, 80, 20),
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
