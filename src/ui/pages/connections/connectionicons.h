/**
 * @file    connectionicons.h
 * @brief   Stroke glyphs used by the Connections screen, painted from the
 *          Lucide geometry the mock uses so the page needs no image assets.
 * @author  Oasis
 */
#pragma once

#include <QColor>
#include <QIcon>
#include <QPainter>
#include <QPixmap>
#include <QString>
#include <QtMath>

namespace ConnectionsUi {

enum class Glyph {
    Globe,
    Shield,
    TrendUp,
    TrendDown,
    Info,
    Search,
    GroupLines,
    ChevronDown,
    ChevronRight,
    Pause,
    Play,
    Download,
    Warning,
    Close,
    Clock,
    ArrowOut,
    ArrowIn,
    ArrowBoth,
    Branch
};

/// Strokes one glyph into `rect` (a 24 x 24 design box). `stroke` is the on-screen
/// pen width in pixels, independent of the box size.
inline void drawGlyph(QPainter *painter, Glyph glyph, const QRectF &rect,
                      const QColor &color, qreal stroke = 1.75)
{
    if (rect.width() <= 0)
        return;

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    painter->translate(rect.topLeft());
    const qreal scale = rect.width() / 24.0;
    painter->scale(scale, scale);

    QPen pen(color, stroke * 24.0 / rect.width(), Qt::SolidLine, Qt::RoundCap,
             Qt::RoundJoin);
    painter->setPen(pen);
    painter->setBrush(Qt::NoBrush);

    switch (glyph) {
    case Glyph::Globe:
        painter->drawEllipse(QPointF(12, 12), 10, 10);
        painter->drawEllipse(QPointF(12, 12), 4, 10);
        painter->drawLine(QPointF(2, 12), QPointF(22, 12));
        break;
    case Glyph::Shield:
    case Glyph::Warning:
        if (glyph == Glyph::Shield) {
            painter->drawPath(QPainterPath());
            QPainterPath shield;
            shield.moveTo(12, 22);
            shield.cubicTo(20, 18, 20, 12, 20, 12);
            shield.lineTo(20, 5);
            shield.lineTo(12, 2);
            shield.lineTo(4, 5);
            shield.lineTo(4, 12);
            shield.cubicTo(4, 12, 4, 18, 12, 22);
            shield.closeSubpath();
            painter->drawPath(shield);
        } else {
            QPainterPath triangle;
            triangle.moveTo(12, 3.5);
            triangle.lineTo(21.5, 20);
            triangle.cubicTo(22, 21, 21.3, 21.5, 20.3, 21.5);
            triangle.lineTo(3.7, 21.5);
            triangle.cubicTo(2.7, 21.5, 2, 21, 2.5, 20);
            triangle.closeSubpath();
            painter->drawPath(triangle);
            painter->drawLine(QPointF(12, 9), QPointF(12, 14));
            painter->drawPoint(QPointF(12, 17.5));
        }
        break;
    case Glyph::TrendUp:
        painter->drawPolyline(QPolygonF{
            QPointF(23, 6), QPointF(13.5, 15.5), QPointF(8.5, 10.5), QPointF(1, 18)});
        painter->drawPolyline(QPolygonF{
            QPointF(17, 6), QPointF(23, 6), QPointF(23, 12)});
        break;
    case Glyph::TrendDown:
        painter->drawPolyline(QPolygonF{
            QPointF(23, 18), QPointF(13.5, 8.5), QPointF(8.5, 13.5), QPointF(1, 6)});
        painter->drawPolyline(QPolygonF{
            QPointF(17, 18), QPointF(23, 18), QPointF(23, 12)});
        break;
    case Glyph::Info:
        painter->drawEllipse(QPointF(12, 12), 10, 10);
        painter->drawLine(QPointF(12, 11), QPointF(12, 16.5));
        painter->drawPoint(QPointF(12, 7.5));
        break;
    case Glyph::Search:
        painter->drawEllipse(QPointF(11, 11), 8, 8);
        painter->drawLine(QPointF(21, 21), QPointF(16.65, 16.65));
        break;
    case Glyph::GroupLines:
        painter->drawLine(QPointF(4, 6), QPointF(20, 6));
        painter->drawLine(QPointF(4, 12), QPointF(20, 12));
        painter->drawLine(QPointF(4, 18), QPointF(11, 18));
        break;
    case Glyph::ChevronDown:
        painter->drawPolyline(QPolygonF{
            QPointF(6, 9), QPointF(12, 15), QPointF(18, 9)});
        break;
    case Glyph::ChevronRight:
        painter->drawPolyline(QPolygonF{
            QPointF(9, 18), QPointF(15, 12), QPointF(9, 6)});
        break;
    case Glyph::Pause:
        painter->setBrush(color);
        painter->setPen(Qt::NoPen);
        painter->drawRect(QRectF(6, 4, 4, 16));
        painter->drawRect(QRectF(14, 4, 4, 16));
        break;
    case Glyph::Play:
        painter->setBrush(color);
        painter->setPen(Qt::NoPen);
        painter->drawPolygon(QPolygonF{
            QPointF(5, 3), QPointF(19, 12), QPointF(5, 21)});
        break;
    case Glyph::Download:
        painter->drawPath(QPainterPath());
        {
            QPainterPath tray;
            tray.moveTo(21, 15);
            tray.lineTo(21, 19);
            tray.cubicTo(21, 20.1, 20.1, 21, 19, 21);
            tray.lineTo(5, 21);
            tray.cubicTo(3.9, 21, 3, 20.1, 3, 19);
            tray.lineTo(3, 15);
            painter->drawPath(tray);
        }
        painter->drawPolyline(QPolygonF{
            QPointF(7, 10), QPointF(12, 15), QPointF(17, 10)});
        painter->drawLine(QPointF(12, 15), QPointF(12, 3));
        break;
    case Glyph::Close:
        painter->drawLine(QPointF(18, 6), QPointF(6, 18));
        painter->drawLine(QPointF(6, 6), QPointF(18, 18));
        break;
    case Glyph::Clock:
        painter->drawEllipse(QPointF(12, 12), 10, 10);
        painter->drawPolyline(QPolygonF{
            QPointF(12, 6), QPointF(12, 12), QPointF(16, 14)});
        break;
    case Glyph::ArrowOut:
        painter->drawLine(QPointF(7, 17), QPointF(17, 7));
        painter->drawPolyline(QPolygonF{
            QPointF(7, 7), QPointF(17, 7), QPointF(17, 17)});
        break;
    case Glyph::ArrowIn:
        painter->drawLine(QPointF(17, 7), QPointF(7, 17));
        painter->drawPolyline(QPolygonF{
            QPointF(17, 17), QPointF(7, 17), QPointF(7, 7)});
        break;
    case Glyph::ArrowBoth:
        painter->drawLine(QPointF(7, 16), QPointF(7, 4));
        painter->drawPolyline(QPolygonF{
            QPointF(3, 8), QPointF(7, 4), QPointF(11, 8)});
        painter->drawLine(QPointF(17, 8), QPointF(17, 20));
        painter->drawPolyline(QPolygonF{
            QPointF(21, 16), QPointF(17, 20), QPointF(13, 16)});
        break;
    case Glyph::Branch:
        painter->drawLine(QPointF(12, 20), QPointF(21, 20));
        painter->drawLine(QPointF(4, 4), QPointF(4, 20));
        painter->drawLine(QPointF(4, 12), QPointF(12, 12));
        break;
    }
    painter->restore();
}

inline QPixmap glyphPixmap(Glyph glyph, int size, const QColor &color,
                           qreal stroke = 1.75)
{
    const qreal ratio = qApp ? qApp->devicePixelRatio() : 1.0;
    QPixmap pixmap(qRound(size * ratio), qRound(size * ratio));
    pixmap.setDevicePixelRatio(ratio);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    drawGlyph(&painter, glyph, QRectF(0, 0, size, size), color, stroke);
    return pixmap;
}

inline QIcon glyphIcon(Glyph glyph, int size, const QColor &color,
                       qreal stroke = 1.75)
{
    return QIcon(glyphPixmap(glyph, size, color, stroke));
}

} // namespace ConnectionsUi
