/**
 * @file   policyeditorstyle.h
 * @brief  Palette, glyphs and shared widgets for the policy editor surfaces.
 *
 * The editor and its rule form are scoped surfaces: their colours are
 * resolved for the active theme and applied to the dialog, so they do not
 * leak into the rest of the app. Everything here is header-only so both
 * implementation units can share it without a new object file.
 *
 * @author Codebuff
 */

#pragma once

#include <QAbstractButton>
#include <QApplication>
#include <QColor>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QRectF>
#include <QScrollArea>
#include <QString>
#include <QStyle>
#include <QWidget>

namespace PolicyEditorStyle {

// ─── Glyphs ─────────────────────────────────────────────────────────────────
enum Glyph {
    GlyphShield,
    GlyphClose,
    GlyphFolder,
    GlyphUpDown,
    GlyphClock,
    GlyphChevronDown,
    GlyphChevronUp,
    GlyphEye,
    GlyphCheck,
    GlyphBolt,
    GlyphBan
};

inline void paintGlyph(QPainter &p, int glyph, const QRectF &rect, const QColor &color,
                qreal strokeWidth = 1.6)
{
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.translate(rect.topLeft());
    p.scale(rect.width() / 24.0, rect.height() / 24.0);
    const qreal penWidth = strokeWidth * 24.0 / qMax(1.0, rect.width());
    QPen pen(color, penWidth, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);

    switch (glyph) {
    case GlyphShield: {
        QPainterPath shield;
        shield.moveTo(12.0, 2.8);
        shield.lineTo(19.4, 5.8);
        shield.lineTo(19.4, 11.0);
        shield.cubicTo(19.4, 15.9, 16.1, 19.3, 12.0, 21.0);
        shield.cubicTo(7.9, 19.3, 4.6, 15.9, 4.6, 11.0);
        shield.lineTo(4.6, 5.8);
        shield.closeSubpath();
        p.drawPath(shield);

        QPainterPath check;
        check.moveTo(8.5, 12.0);
        check.lineTo(11.0, 14.4);
        check.lineTo(15.6, 9.5);
        p.drawPath(check);
        break;
    }
    case GlyphClose:
        p.drawLine(QPointF(6, 6), QPointF(18, 18));
        p.drawLine(QPointF(18, 6), QPointF(6, 18));
        break;
    case GlyphFolder: {
        QPainterPath folder;
        folder.moveTo(3.0, 7.0);
        folder.cubicTo(3.0, 5.9, 3.9, 5.0, 5.0, 5.0);
        folder.lineTo(9.2, 5.0);
        folder.lineTo(11.2, 7.2);
        folder.lineTo(19.0, 7.2);
        folder.cubicTo(20.1, 7.2, 21.0, 8.1, 21.0, 9.2);
        folder.lineTo(21.0, 17.0);
        folder.cubicTo(21.0, 18.1, 20.1, 19.0, 19.0, 19.0);
        folder.lineTo(5.0, 19.0);
        folder.cubicTo(3.9, 19.0, 3.0, 18.1, 3.0, 17.0);
        folder.closeSubpath();
        p.drawPath(folder);
        break;
    }
    case GlyphUpDown:
        p.drawLine(QPointF(7, 16), QPointF(7, 4));
        p.drawLine(QPointF(7, 4), QPointF(3, 8));
        p.drawLine(QPointF(7, 4), QPointF(11, 8));
        p.drawLine(QPointF(17, 8), QPointF(17, 20));
        p.drawLine(QPointF(17, 20), QPointF(13, 16));
        p.drawLine(QPointF(17, 20), QPointF(21, 16));
        break;
    case GlyphClock:
        p.drawEllipse(QPointF(12, 12), 9.0, 9.0);
        p.drawLine(QPointF(12, 7), QPointF(12, 12));
        p.drawLine(QPointF(12, 12), QPointF(15, 14));
        break;
    case GlyphChevronDown:
        p.drawLine(QPointF(6, 9), QPointF(12, 15));
        p.drawLine(QPointF(12, 15), QPointF(18, 9));
        break;
    case GlyphChevronUp:
        p.drawLine(QPointF(6, 15), QPointF(12, 9));
        p.drawLine(QPointF(12, 9), QPointF(18, 15));
        break;
    case GlyphEye: {
        QPainterPath eye;
        eye.moveTo(2.5, 12.0);
        eye.cubicTo(4.4, 7.6, 7.9, 5.2, 12.0, 5.2);
        eye.cubicTo(16.1, 5.2, 19.6, 7.6, 21.5, 12.0);
        eye.cubicTo(19.6, 16.4, 16.1, 18.8, 12.0, 18.8);
        eye.cubicTo(7.9, 18.8, 4.4, 16.4, 2.5, 12.0);
        eye.closeSubpath();
        p.drawPath(eye);
        p.drawEllipse(QPointF(12, 12), 3.0, 3.0);
        break;
    }
    case GlyphCheck:
        p.drawLine(QPointF(5, 12.5), QPointF(9.5, 17));
        p.drawLine(QPointF(9.5, 17), QPointF(19, 7.5));
        break;
    case GlyphBolt: {
        QPainterPath bolt;
        bolt.moveTo(13.2, 2.0);
        bolt.lineTo(4.2, 13.8);
        bolt.lineTo(10.6, 13.8);
        bolt.lineTo(10.2, 22.0);
        bolt.lineTo(19.8, 9.4);
        bolt.lineTo(13.2, 9.4);
        bolt.closeSubpath();
        p.setPen(Qt::NoPen);
        p.setBrush(color);
        p.drawPath(bolt);
        break;
    }
    case GlyphBan:
        p.drawEllipse(QPointF(12, 12), 9.0, 9.0);
        p.drawLine(QPointF(5.6, 5.6), QPointF(18.4, 18.4));
        break;
    default:
        break;
    }
    p.restore();
}

inline QPixmap glyphPixmap(int glyph, int size, const QColor &color, qreal strokeWidth = 1.6)
{
    const qreal dpr = qApp ? qApp->devicePixelRatio() : 1.0;
    QPixmap pm(qRound(size * dpr), qRound(size * dpr));
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    paintGlyph(p, glyph, QRectF(0, 0, size, size), color, strokeWidth);
    return pm;
}

// ─── Palette ────────────────────────────────────────────────────────────────
// Exact mockup colours, resolved for the theme that is active when the dialog
// opens. The dialog is a scoped surface: its colours do not leak into the rest
// of the app and are rebuilt on a theme change.
struct DialogColors
{
    QColor card;
    QColor title;
    QColor text;
    QColor secondary;
    QColor muted;
    QColor border;
    QColor field;
    QColor fieldBorder;
    QColor hover;
    QColor hoverSoft;
    QColor accordionBg;
    QColor accent;
    QColor accentHover;
    QColor accentSolid;
    QColor accentSolidHover;
    QColor accentPressed;
    QColor accentSoft;
    QColor accentBorder;
    QColor accentText;
    QColor impactBg;
    QColor impactBorder;
    QColor inactiveBg;
    QColor inactiveBorder;
    QColor rateUnitBg;
    QColor dangerText;
    QColor successText;
    QColor chip;
    QColor scroll;
    QColor scrollHover;
    QColor warningText;
    QColor warningSoft;
    QColor warningBorder;
    QColor toastBg;
    QColor toastBorder;
};

inline DialogColors dialogColors(bool dark)
{
    DialogColors c;
    if (dark) {
        c.card = QColor("#161A23");
        c.title = QColor("#FFFFFF");
        c.text = QColor("#E2E8F0");
        c.secondary = QColor("#CBD5E1");
        c.muted = QColor("#94A3B8");
        c.border = QColor("#1E293B");
        c.field = QColor("#0F1219");
        c.fieldBorder = QColor("#334155");
        c.hover = QColor("#1E293B");
        c.hoverSoft = QColor("#1E293B");
        c.accordionBg = QColor("#12151E");
        c.accent = QColor("#3B82F6");
        c.accentHover = QColor("#60A5FA");
        c.accentSolid = QColor("#2563EB");
        c.accentSolidHover = QColor("#3B82F6");
        c.accentPressed = QColor("#1D4ED8");
        c.accentSoft = QColor(59, 130, 246, 38);
        c.accentBorder = QColor(59, 130, 246, 51);
        c.accentText = QColor("#93C5FD");
        c.impactBg = QColor(59, 130, 246, 23);
        c.impactBorder = QColor(59, 130, 246, 51);
        c.inactiveBg = QColor(30, 41, 59, 128);
        c.inactiveBorder = QColor("#334155");
        c.rateUnitBg = QColor("#1E293B");
        c.dangerText = QColor("#FB7185");
        c.successText = QColor("#34D399");
        c.chip = QColor("#1E293B");
        c.scroll = QColor(148, 163, 184, 64);
        c.scrollHover = QColor(148, 163, 184, 115);
        c.warningText = QColor("#FCD34D");
        c.warningSoft = QColor(245, 158, 11, 26);
        c.warningBorder = QColor(245, 158, 11, 64);
        c.toastBg = QColor("#0F172A");
        c.toastBorder = QColor(255, 255, 255, 31);
    } else {
        c.card = QColor("#FFFFFF");
        c.title = QColor("#0F172A");
        c.text = QColor("#334155");
        c.secondary = QColor("#475569");
        c.muted = QColor("#64748B");
        c.border = QColor("#E2E8F0");
        c.field = QColor("#F8FAFC");
        c.fieldBorder = QColor("#E2E8F0");
        c.hover = QColor("#F1F5F9");
        c.hoverSoft = QColor("#F8FAFC");
        c.accordionBg = QColor("#F8FAFC");
        c.accent = QColor("#3B82F6");
        c.accentHover = QColor("#2563EB");
        c.accentSolid = QColor("#2563EB");
        c.accentSolidHover = QColor("#3B82F6");
        c.accentPressed = QColor("#1E40AF");
        c.accentSoft = QColor(59, 130, 246, 26);
        c.accentBorder = QColor(59, 130, 246, 51);
        c.accentText = QColor("#1D4ED8");
        c.impactBg = QColor(59, 130, 246, 18);
        c.impactBorder = QColor(59, 130, 246, 51);
        c.inactiveBg = QColor(226, 232, 240, 153);
        c.inactiveBorder = QColor("#CBD5E1");
        c.rateUnitBg = QColor(226, 232, 240, 204);
        c.dangerText = QColor("#E11D48");
        c.successText = QColor("#059669");
        c.chip = QColor("#F1F5F9");
        c.scroll = QColor(148, 163, 184, 89);
        c.scrollHover = QColor(148, 163, 184, 140);
        c.warningText = QColor("#92400E");
        c.warningSoft = QColor(245, 158, 11, 26);
        c.warningBorder = QColor(245, 158, 11, 64);
        c.toastBg = QColor("#0F172A");
        c.toastBorder = QColor(255, 255, 255, 31);
    }
    return c;
}

inline QString css(const QColor &color)
{
    if (color.alpha() == 255)
        return color.name(QColor::HexRgb);
    return QStringLiteral("rgba(%1,%2,%3,%4)")
        .arg(color.red())
        .arg(color.green())
        .arg(color.blue())
        .arg(QString::number(color.alphaF(), 'f', 3));
}


inline QLabel *makeLabel(const QString &text, const QString &objectName, QWidget *parent)
{
    auto *label = new QLabel(text, parent);
    label->setObjectName(objectName);
    return label;
}

// QScrollArea::sizeHint() caps the height it reports to 24 text lines, which
// made the whole dialog stop at ~496 px. Report the real content height instead
// and let showEvent() cap it against the screen.
class PolicyScrollArea : public QScrollArea
{
public:
    using QScrollArea::QScrollArea;

    QSize sizeHint() const override
    {
        QSize hint = QScrollArea::sizeHint();
        if (widget() && widgetResizable())
            hint.setHeight(widget()->sizeHint().height() + 2 * frameWidth());
        if (maximumHeight() < QWIDGETSIZE_MAX)
            hint.setHeight(qMin(hint.height(), maximumHeight()));
        return hint;
    }
};

// Re-apply the style sheet after a dynamic property changes.
inline void repolish(QWidget *widget)
{
    if (!widget) return;
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
    widget->update();
}

} // namespace PolicyEditorStyle
