/**
 * @file   policyeditordialog.cpp
 * @brief  Policy scope selection and creation (NG-022).
 *
 * The layout mirrors `create_network_policy_modal_ui.html`: a 520 px rounded
 * card, 20 px padding, Inter / JetBrains Mono type, three action cards, a
 * collapsible schedule group, and a live impact summary. Everything is painted
 * or styled here so the dialog does not fall back to native control chrome.
 *
 * @author Codebuff
 */

#include "policyeditordialog.h"

#include "policyschedule.h"
#include "ui/theme/thememanager.h"

#include <QAbstractButton>
#include <QAbstractItemView>
#include <QApplication>
#include <QButtonGroup>
#include <QComboBox>
#include <QDateTime>
#include <QDateTimeEdit>
#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontMetrics>
#include <QGraphicsDropShadowEffect>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QIcon>
#include <QIntValidator>
#include <QLabel>
#include <QLayout>
#include <QLineEdit>
#include <QLocale>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QResizeEvent>
#include <QScreen>
#include <QScrollArea>
#include <QShowEvent>
#include <QStyle>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>
#include <QWindow>

namespace {

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

void paintGlyph(QPainter &p, int glyph, const QRectF &rect, const QColor &color,
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

QPixmap glyphPixmap(int glyph, int size, const QColor &color, qreal strokeWidth = 1.6)
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

DialogColors dialogColors(bool dark)
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

QString css(const QColor &color)
{
    if (color.alpha() == 255)
        return color.name(QColor::HexRgb);
    return QStringLiteral("rgba(%1,%2,%3,%4)")
        .arg(color.red())
        .arg(color.green())
        .arg(color.blue())
        .arg(QString::number(color.alphaF(), 'f', 3));
}

QString dialogStyleSheet(const DialogColors &c)
{
    QString s = QStringLiteral(R"QSS(
QDialog { background: transparent; }
QFrame#policyCard { background: {card}; border: 1px solid {border}; border-radius: 16px; }
QWidget { font-family: "Inter"; font-size: 12px; color: {text}; }
QFrame#headerIconTile { background: {accentSoft}; border: 1px solid {accentBorder}; border-radius: 12px; }
QLabel { background: transparent; color: {text}; }
QLabel#dialogTitle { font-size: 16px; font-weight: 600; color: {title}; }
QLabel#dialogSubtitle { font-size: 12px; color: {muted}; }
QLabel#processBadge { font-family: "JetBrains Mono"; font-size: 11px; color: {secondary}; background: {field}; border: 1px solid {border}; border-radius: 4px; padding: 1px 6px; }
QFrame#headerLine { background: {border}; border: none; }
QScrollArea { background: transparent; border: none; }
QScrollArea > QWidget > QWidget { background: transparent; }
QWidget#dialogBody { background: transparent; }
QScrollBar:vertical { background: transparent; width: 6px; margin: 0; }
QScrollBar::handle:vertical { background: {scroll}; border-radius: 3px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: {scrollHover}; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QLabel#sectionLabel { font-size: 12px; font-weight: 600; color: {muted}; }
QComboBox#scopePill, QComboBox#directionPill { background: {field}; border: 1px solid {border}; border-radius: 11px; padding: 1px 8px; color: {secondary}; font-size: 11px; }
QComboBox#scopePill::drop-down, QComboBox#directionPill::drop-down { width: 0; border: none; }
QComboBox#scopePill::down-arrow, QComboBox#directionPill::down-arrow { width: 0; height: 0; image: none; }
QComboBox#scopePill:disabled, QComboBox#directionPill:disabled { color: {muted}; }
QComboBox QAbstractItemView { background: {card}; color: {text}; border: 1px solid {border}; padding: 4px; outline: 0; selection-background-color: {accentSolid}; selection-color: #FFFFFF; }
QFrame#targetField, QFrame#rateField { background: {field}; border: 1px solid {fieldBorder}; border-radius: 12px; }
QFrame#targetField[focused="true"], QFrame#rateField[focused="true"] { border: 1px solid {accent}; }
QLineEdit#targetInput { background: transparent; border: none; padding: 0; font-family: "JetBrains Mono"; font-size: 12px; color: {text}; selection-background-color: {accentSolid}; selection-color: #FFFFFF; }
QLineEdit#rateInput { background: transparent; border: none; padding: 0; font-family: "JetBrains Mono"; font-size: 14px; font-weight: 600; color: {title}; selection-background-color: {accentSolid}; selection-color: #FFFFFF; }
QLabel#rateUnit { background: {rateUnitBg}; border-radius: 8px; padding: 3px 8px; font-family: "JetBrains Mono"; font-size: 12px; font-weight: 600; color: {secondary}; }
QLabel#helperText { font-size: 11px; color: {muted}; }
QLabel#serviceBanner { font-size: 11px; color: {warningText}; background: {warningSoft}; border: 1px solid {warningBorder}; border-radius: 12px; padding: 8px 10px; }
QLabel#fieldLabel { font-size: 12px; font-weight: 500; color: {secondary}; }
QPushButton#iconButton { background: transparent; border: none; border-radius: 8px; padding: 0; }
QPushButton#iconButton:hover { background: {hover}; }
QPushButton#presetChip, QPushButton#advisoryChip { background: {chip}; border: 1px solid {border}; border-radius: 6px; padding: 1px 8px; font-family: "JetBrains Mono"; font-size: 11px; color: {muted}; }
QPushButton#presetChip:hover, QPushButton#advisoryChip:hover { background: {accentSoft}; color: {accentText}; }
QPushButton#advisoryChip:checked { background: {accentSoft}; border-color: {accent}; color: {accentText}; }
QFrame#accordion { background: {accordionBg}; border: 1px solid {border}; border-radius: 12px; }
QPushButton#accordionHeader { background: transparent; border: none; text-align: left; }
QPushButton#accordionHeader:hover { background: {hoverSoft}; border-radius: 11px; }
QLabel#accordionTitle { font-size: 12px; font-weight: 500; color: {secondary}; }
QLabel#accordionStatus { font-size: 11px; color: {muted}; }
QLabel#accordionStatus[configured="true"] { color: {accentText}; font-weight: 500; }
QFrame#accordionLine { background: {border}; border: none; }
QComboBox#fieldCombo, QLineEdit#noteInput, QLineEdit#monoField, QDateTimeEdit#expirationEdit { background: {field}; border: 1px solid {fieldBorder}; border-radius: 8px; padding: 5px 8px; color: {text}; font-size: 12px; }
QComboBox#fieldCombo:focus, QLineEdit#noteInput:focus, QLineEdit#monoField:focus, QDateTimeEdit#expirationEdit:focus { border-color: {accent}; }
QComboBox#fieldCombo::drop-down { border: none; width: 18px; }
QComboBox#fieldCombo::down-arrow { width: 0; height: 0; image: none; }
QLineEdit#monoField { font-family: "JetBrains Mono"; font-size: 11px; }
QDateTimeEdit#expirationEdit { font-family: "JetBrains Mono"; font-size: 11px; }
QDateTimeEdit#expirationEdit::drop-down { border: none; width: 20px; }
QFrame#impactCard { background: {impactBg}; border: 1px solid {impactBorder}; border-radius: 12px; }
QFrame#impactCard[enabled="false"] { background: {inactiveBg}; border: 1px solid {inactiveBorder}; }
QLabel#impactCaption { font-size: 11px; font-weight: 600; color: {accentText}; }
QLabel#impactSummary { font-size: 12px; color: {text}; }
QLabel#enabledState { font-size: 11px; font-weight: 500; color: {secondary}; }
QLabel#enforcementLabel { font-size: 11px; color: {muted}; }
QLabel#enforcementLabel[warning="true"] { color: {warningText}; }
QPushButton#cancelButton { background: transparent; border: 1px solid {border}; border-radius: 12px; padding: 8px 16px; color: {secondary}; font-size: 12px; font-weight: 500; }
QPushButton#cancelButton:hover { background: {hover}; }
QPushButton#saveButton { background: {accentSolid}; border: 1px solid {accentSolid}; border-radius: 12px; padding: 8px 16px; color: #FFFFFF; font-size: 12px; font-weight: 600; }
QPushButton#saveButton:hover { background: {accentSolidHover}; border-color: {accentSolidHover}; }
QPushButton#saveButton:pressed { background: {accentPressed}; }
QPushButton#saveButton:focus { border: 1px solid {title}; }
QLabel#toast { background: {toastBg}; color: #FFFFFF; border: 1px solid {toastBorder}; border-radius: 12px; padding: 10px 14px; font-size: 12px; font-weight: 500; }
)QSS");

    struct Token
    {
        const char *name;
        QColor value;
    };
    const Token tokens[] = {
        {"{card}", c.card},
        {"{title}", c.title},
        {"{text}", c.text},
        {"{secondary}", c.secondary},
        {"{muted}", c.muted},
        {"{border}", c.border},
        {"{field}", c.field},
        {"{fieldBorder}", c.fieldBorder},
        {"{hover}", c.hover},
        {"{hoverSoft}", c.hoverSoft},
        {"{accordionBg}", c.accordionBg},
        {"{accent}", c.accent},
        {"{accentHover}", c.accentHover},
        {"{accentSolid}", c.accentSolid},
        {"{accentSolidHover}", c.accentSolidHover},
        {"{accentPressed}", c.accentPressed},
        {"{accentSoft}", c.accentSoft},
        {"{accentBorder}", c.accentBorder},
        {"{accentText}", c.accentText},
        {"{impactBg}", c.impactBg},
        {"{impactBorder}", c.impactBorder},
        {"{inactiveBg}", c.inactiveBg},
        {"{inactiveBorder}", c.inactiveBorder},
        {"{rateUnitBg}", c.rateUnitBg},
        {"{chip}", c.chip},
        {"{scroll}", c.scroll},
        {"{scrollHover}", c.scrollHover},
        {"{warningText}", c.warningText},
        {"{warningSoft}", c.warningSoft},
        {"{warningBorder}", c.warningBorder},
        {"{toastBg}", c.toastBg},
        {"{toastBorder}", c.toastBorder},
    };
    for (const Token &token : tokens)
        s.replace(QLatin1String(token.name), css(token.value));
    return s;
}

QLabel *makeLabel(const QString &text, const QString &objectName, QWidget *parent)
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

} // namespace

// ─── Painted controls ───────────────────────────────────────────────────────

class PolicyActionCard : public QAbstractButton
{
public:
    PolicyActionCard(int glyph, const QString &label, const QColor &accent,
                     QWidget *parent = nullptr)
        : QAbstractButton(parent)
        , m_glyph(glyph)
        , m_accent(accent)
    {
        setText(label);
        setCheckable(true);
        setCursor(Qt::PointingHandCursor);
        setFocusPolicy(Qt::StrongFocus);
        setMinimumHeight(62);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

    void setColors(const QColor &bg, const QColor &border, const QColor &text,
                   const QColor &hover, const QColor &checkedText)
    {
        m_bg = bg;
        m_border = border;
        m_text = text;
        m_hover = hover;
        m_checkedText = checkedText;
        update();
    }

    QSize sizeHint() const override { return QSize(150, 62); }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);

        const QRectF r = QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5);
        QColor bg = m_bg;
        QColor border = m_border;
        qreal borderWidth = 1.0;
        if (isChecked()) {
            bg = m_accent;
            bg.setAlpha(26);
            border = m_accent;
            borderWidth = 2.0;
        } else if (underMouse()) {
            bg = m_hover;
            border = m_text;
            border.setAlpha(60);
        }

        p.setBrush(bg);
        p.setPen(QPen(border, borderWidth));
        p.drawRoundedRect(r, 12, 12);

        paintGlyph(p, m_glyph, QRectF(width() / 2.0 - 8.0, 12.0, 16.0, 16.0),
                   m_accent, 1.6);

        QFont labelFont(QStringLiteral("Inter"));
        labelFont.setPixelSize(12);
        labelFont.setWeight(QFont::DemiBold);
        p.setFont(labelFont);
        p.setPen(isChecked() ? m_checkedText : m_text);
        p.drawText(QRect(0, 34, width(), 18),
                   Qt::AlignHCenter | Qt::AlignTop, text());

        if (hasFocus()) {
            QColor focus = m_accent;
            focus.setAlpha(150);
            p.setBrush(Qt::NoBrush);
            p.setPen(QPen(focus, 1, Qt::DashLine));
            p.drawRoundedRect(r.adjusted(2, 2, -2, -2), 9, 9);
        }
    }

private:
    int m_glyph;
    QColor m_accent;
    QColor m_bg;
    QColor m_border;
    QColor m_text;
    QColor m_hover;
    QColor m_checkedText;
};

class PolicyToggleSwitch : public QAbstractButton
{
public:
    explicit PolicyToggleSwitch(QWidget *parent = nullptr)
        : QAbstractButton(parent)
    {
        setCheckable(true);
        setCursor(Qt::PointingHandCursor);
        setFocusPolicy(Qt::StrongFocus);
        setFixedSize(32, 18);
    }

    void setColors(const QColor &off, const QColor &on, const QColor &knob)
    {
        m_off = off;
        m_on = on;
        m_knob = knob;
        update();
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF track = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
        p.setBrush(isChecked() ? m_on : m_off);
        p.setPen(Qt::NoPen);
        p.drawRoundedRect(track, 9, 9);

        const qreal knobSize = 14.0;
        const qreal x = isChecked() ? width() - knobSize - 2.0 : 2.0;
        p.setBrush(m_knob);
        p.drawEllipse(QRectF(x, 2.0, knobSize, knobSize));

        if (hasFocus()) {
            p.setBrush(Qt::NoBrush);
            p.setPen(QPen(m_on, 1, Qt::DotLine));
            p.drawRoundedRect(QRectF(rect()).adjusted(1, 1, -1, -1), 8, 8);
        }
    }

private:
    QColor m_off;
    QColor m_on;
    QColor m_knob;
};

class PolicyCheckBox : public QAbstractButton
{
public:
    explicit PolicyCheckBox(const QString &text, QWidget *parent = nullptr)
        : QAbstractButton(parent)
    {
        setText(text);
        setCheckable(true);
        setCursor(Qt::PointingHandCursor);
        setFocusPolicy(Qt::StrongFocus);
        setMinimumHeight(20);
    }

    void setColors(const QColor &text, const QColor &border, const QColor &fill,
                   const QColor &background)
    {
        m_text = text;
        m_border = border;
        m_fill = fill;
        m_background = background;
        update();
    }

    QSize sizeHint() const override
    {
        const QFontMetrics fm(font());
        return QSize(fm.horizontalAdvance(text()) + 26, 20);
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);

        const QRectF box(1.0, (height() - 14.0) / 2.0, 14.0, 14.0);
        p.setBrush(isChecked() ? m_fill : m_background);
        p.setPen(QPen(isChecked() ? m_fill : m_border, 1.0));
        p.drawRoundedRect(box, 3, 3);

        if (isChecked()) {
            paintGlyph(p, GlyphCheck, box.adjusted(3, 3, -3, -3),
                       QColor("#FFFFFF"), 2.2);
        }

        QFont labelFont(QStringLiteral("Inter"));
        labelFont.setPixelSize(12);
        labelFont.setWeight(QFont::Medium);
        p.setFont(labelFont);
        p.setPen(m_text);
        p.drawText(QRect(22, 0, width() - 22, height()),
                   Qt::AlignLeft | Qt::AlignVCenter, text());

        if (hasFocus()) {
            p.setBrush(Qt::NoBrush);
            p.setPen(QPen(m_fill, 1, Qt::DotLine));
            p.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 4, 4);
        }
    }

private:
    QColor m_text;
    QColor m_border;
    QColor m_fill;
    QColor m_background;
};

// ─── Dialog ─────────────────────────────────────────────────────────────────

PolicyEditorDialog::PolicyEditorDialog(const PolicyTarget &target, QWidget *parent)
    : QDialog(parent)
    , m_target(target)
{
    buildUi();
    setWindowTitle(QStringLiteral("Create Network Policy"));
    updateScopeTarget();
    updateActionControls();
    updateImpactPreview();
}

PolicyEditorDialog::PolicyEditorDialog(const NetworkPolicy &policy, QWidget *parent)
    : QDialog(parent)
{
    m_editing = true;
    m_policy = policy;
    m_policyId = policy.id;
    m_policySource = policy.source;

    PolicyScopeKind scope = PolicyScopeKind::ExecutablePath;
    policyScopeKindFromKey(policy.scope, &scope);
    switch (scope) {
    case PolicyScopeKind::Pid:
        m_target.pid = policy.targetId.toUInt();
        break;
    case PolicyScopeKind::Publisher:
        m_target.publisher = policy.targetId;
        break;
    case PolicyScopeKind::Service:
        m_target.serviceName = policy.targetId;
        break;
    case PolicyScopeKind::ApplicationGroup:
        m_target.groupId = policy.targetId;
        break;
    case PolicyScopeKind::ExecutablePath:
        m_target.executablePath = policy.targetId;
        break;
    }

    buildUi();
    setWindowTitle(QStringLiteral("Edit Network Policy"));
    m_titleLabel->setText(QStringLiteral("Edit Network Policy"));

    const int scopeIndex = m_scopeCombo->findData(static_cast<int>(scope));
    if (scopeIndex >= 0) m_scopeCombo->setCurrentIndex(scopeIndex);
    updateScopeTarget();

    setAction(policy.action);
    const int directionIndex = m_directionCombo->findData(static_cast<int>(policy.direction));
    if (directionIndex >= 0) m_directionCombo->setCurrentIndex(directionIndex);
    if (policy.rateBitsPerSecond > 0) {
        const qint64 kbps = qRound64(static_cast<double>(policy.rateBitsPerSecond) / 8000.0);
        m_rateEdit->setText(QString::number(kbps));
    }
    setScheduleValue(policy.schedule);
    m_expiresCheck->setChecked(policy.expiration.isValid());
    m_expirationWrap->setVisible(policy.expiration.isValid());
    if (policy.expiration.isValid()) m_expirationEdit->setDateTime(policy.expiration);
    m_enabledSwitch->setChecked(policy.enabled);
    m_descriptionEdit->setText(policy.description);
    updateActionControls();
    updateImpactPreview();
}

void PolicyEditorDialog::buildUi()
{
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setSizeGripEnabled(false);
    setModal(true);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(0);
    root->setSizeConstraint(QLayout::SetFixedSize);

    m_card = new QFrame(this);
    m_card->setObjectName(QStringLiteral("policyCard"));
    m_card->setFixedWidth(520);
    root->addWidget(m_card, 0, Qt::AlignHCenter);

    const bool dark = ThemeManager::instance().isDark();
    auto *shadow = new QGraphicsDropShadowEffect(m_card);
    shadow->setBlurRadius(48);
    shadow->setOffset(0, 14);
    shadow->setColor(QColor(0, 0, 0, dark ? 180 : 45));
    m_card->setGraphicsEffect(shadow);

    auto *cardLayout = new QVBoxLayout(m_card);
    cardLayout->setContentsMargins(0, 0, 0, 0);
    cardLayout->setSpacing(0);

    // ── Header ────────────────────────────────────────────────────────────
    m_header = new QWidget(m_card);
    auto *headerRow = new QHBoxLayout(m_header);
    headerRow->setContentsMargins(20, 20, 20, 16);
    headerRow->setSpacing(12);

    auto *iconTile = new QFrame(m_header);
    iconTile->setObjectName(QStringLiteral("headerIconTile"));
    iconTile->setFixedSize(36, 36);
    auto *iconLayout = new QVBoxLayout(iconTile);
    iconLayout->setContentsMargins(0, 0, 0, 0);
    m_headerIcon = new QLabel(iconTile);
    m_headerIcon->setAlignment(Qt::AlignCenter);
    m_headerIcon->setFixedSize(20, 20);
    iconLayout->addWidget(m_headerIcon, 0, Qt::AlignCenter);
    headerRow->addWidget(iconTile, 0, Qt::AlignTop);

    auto *titleColumn = new QVBoxLayout();
    titleColumn->setContentsMargins(0, 0, 0, 0);
    titleColumn->setSpacing(3);
    m_titleLabel = makeLabel(QStringLiteral("Create Network Policy"),
                             QStringLiteral("dialogTitle"), m_header);
    titleColumn->addWidget(m_titleLabel);

    auto *subtitleRow = new QHBoxLayout();
    subtitleRow->setContentsMargins(0, 0, 0, 0);
    subtitleRow->setSpacing(6);
    auto *subtitlePrefix =
        makeLabel(QStringLiteral("Target process:"), QStringLiteral("dialogSubtitle"),
                  m_header);
    subtitleRow->addWidget(subtitlePrefix);
    m_processBadge = makeLabel(processBadgeText(), QStringLiteral("processBadge"),
                               m_header);
    m_processBadge->setProperty("fullText", processBadgeText());
    m_processBadge->setToolTip(processBadgeText());
    subtitleRow->addWidget(m_processBadge);
    subtitleRow->addStretch(1);
    titleColumn->addLayout(subtitleRow);
    headerRow->addLayout(titleColumn, 1);

    m_closeButton = new QPushButton(m_header);
    m_closeButton->setObjectName(QStringLiteral("iconButton"));
    m_closeButton->setFixedSize(28, 28);
    m_closeButton->setCursor(Qt::PointingHandCursor);
    m_closeButton->setToolTip(QStringLiteral("Close"));
    m_closeButton->setAccessibleName(QStringLiteral("Close"));
    headerRow->addWidget(m_closeButton, 0, Qt::AlignTop);

    cardLayout->addWidget(m_header);

    auto *headerLine = new QFrame(m_card);
    headerLine->setObjectName(QStringLiteral("headerLine"));
    headerLine->setFixedHeight(1);
    cardLayout->addWidget(headerLine);

    // ── Scrollable body ───────────────────────────────────────────────────
    m_scroll = new PolicyScrollArea(m_card);
    m_scroll->setWidgetResizable(true);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scroll->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContents);

    auto *body = new QWidget;
    body->setObjectName(QStringLiteral("dialogBody"));
    auto *bodyLayout = new QVBoxLayout(body);
    bodyLayout->setContentsMargins(20, 20, 20, 20);
    bodyLayout->setSpacing(20);
    m_scroll->setWidget(body);
    cardLayout->addWidget(m_scroll, 1);

    // ── 1. Target & scope ─────────────────────────────────────────────────
    auto *sectionTarget = new QWidget(body);
    auto *targetLayout = new QVBoxLayout(sectionTarget);
    targetLayout->setContentsMargins(0, 0, 0, 0);
    targetLayout->setSpacing(10);

    auto *targetHead = new QHBoxLayout();
    targetHead->setContentsMargins(0, 0, 0, 0);
    targetHead->setSpacing(8);
    m_scopeLabel = makeLabel(QStringLiteral("1. TARGET APPLICATION"),
                             QStringLiteral("sectionLabel"), sectionTarget);
    targetHead->addWidget(m_scopeLabel);
    targetHead->addStretch(1);

    m_scopeCombo = new QComboBox(sectionTarget);
    m_scopeCombo->setObjectName(QStringLiteral("scopePill"));
    m_scopeCombo->setCursor(Qt::PointingHandCursor);
    m_scopeCombo->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    m_scopeCombo->setFixedHeight(22);
    for (PolicyScopeKind scope : {PolicyScopeKind::Pid, PolicyScopeKind::ExecutablePath,
                                  PolicyScopeKind::Publisher, PolicyScopeKind::Service,
                                  PolicyScopeKind::ApplicationGroup}) {
        m_scopeCombo->addItem(QStringLiteral("Scope: ") + policyScopeDisplayName(scope),
                              static_cast<int>(scope));
    }
    // The executable path is the narrow default: it survives a restart without
    // silently widening to everything the vendor ships.
    m_scopeCombo->setCurrentIndex(1);
    targetHead->addWidget(m_scopeCombo);
    targetLayout->addLayout(targetHead);

    m_targetField = new QFrame(sectionTarget);
    m_targetField->setObjectName(QStringLiteral("targetField"));
    m_targetField->setFixedHeight(36);
    auto *targetFieldLayout = new QHBoxLayout(m_targetField);
    targetFieldLayout->setContentsMargins(12, 0, 6, 0);
    targetFieldLayout->setSpacing(6);

    m_targetEdit = new QLineEdit(m_targetField);
    m_targetEdit->setObjectName(QStringLiteral("targetInput"));
    m_targetEdit->setFrame(false);
    m_targetEdit->installEventFilter(this);
    targetFieldLayout->addWidget(m_targetEdit, 1);

    m_browseButton = new QPushButton(m_targetField);
    m_browseButton->setObjectName(QStringLiteral("iconButton"));
    m_browseButton->setFixedSize(26, 26);
    m_browseButton->setCursor(Qt::PointingHandCursor);
    m_browseButton->setToolTip(QStringLiteral("Browse executable..."));
    m_browseButton->setAccessibleName(QStringLiteral("Browse executable"));
    targetFieldLayout->addWidget(m_browseButton);
    targetLayout->addWidget(m_targetField);

    m_serviceBanner = makeLabel(QString(), QStringLiteral("serviceBanner"), sectionTarget);
    m_serviceBanner->setWordWrap(true);
    m_serviceBanner->setTextFormat(Qt::RichText);
    m_serviceBanner->setVisible(false);
    targetLayout->addWidget(m_serviceBanner);

    m_targetHint = makeLabel(QString(), QStringLiteral("helperText"), sectionTarget);
    m_targetHint->setWordWrap(true);
    targetLayout->addWidget(m_targetHint);
    bodyLayout->addWidget(sectionTarget);

    auto *divider = new QFrame(body);
    divider->setObjectName(QStringLiteral("headerLine"));
    divider->setFixedHeight(1);
    bodyLayout->addWidget(divider);

    // ── 2. Traffic action & limit ─────────────────────────────────────────
    auto *sectionAction = new QWidget(body);
    auto *actionLayout = new QVBoxLayout(sectionAction);
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(12);

    auto *actionHead = new QHBoxLayout();
    actionHead->setContentsMargins(0, 0, 0, 0);
    actionHead->setSpacing(8);
    actionHead->addWidget(makeLabel(QStringLiteral("2. TRAFFIC ACTION & LIMIT"),
                                    QStringLiteral("sectionLabel"), sectionAction));
    actionHead->addStretch(1);

    m_directionCombo = new QComboBox(sectionAction);
    m_directionCombo->setObjectName(QStringLiteral("directionPill"));
    m_directionCombo->setCursor(Qt::PointingHandCursor);
    m_directionCombo->setFixedHeight(22);
    m_directionCombo->addItem(QStringLiteral("Direction: Download"),
                              static_cast<int>(NetworkDirection::Download));
    m_directionCombo->addItem(QStringLiteral("Direction: Upload"),
                              static_cast<int>(NetworkDirection::Upload));
    m_directionCombo->addItem(QStringLiteral("Direction: Both"),
                              static_cast<int>(NetworkDirection::Both));
    m_directionCombo->setCurrentIndex(2);
    actionHead->addWidget(m_directionCombo);
    actionLayout->addLayout(actionHead);

    auto *actionRow = new QHBoxLayout();
    actionRow->setContentsMargins(0, 0, 0, 0);
    actionRow->setSpacing(8);

    m_actionGroup = new QButtonGroup(this);
    m_actionGroup->setExclusive(true);

    struct CardSpec
    {
        NetworkPolicy::Action action;
        int glyph;
        const char *label;
        const char *accent;
    };
    const CardSpec cards[] = {
        {NetworkPolicy::Action::Throttle, GlyphBolt, "Throttle", "#3B82F6"},
        {NetworkPolicy::Action::Block, GlyphBan, "Block", "#F43F5E"},
        {NetworkPolicy::Action::Allow, GlyphCheck, "Allow", "#10B981"},
    };
    for (const CardSpec &spec : cards) {
        auto *card = new PolicyActionCard(
            spec.glyph, QString::fromLatin1(spec.label), QColor(spec.accent),
            sectionAction);
        m_actionGroup->addButton(card, static_cast<int>(spec.action));
        m_actionCards.append(card);
        actionRow->addWidget(card, 1);
    }
    actionLayout->addLayout(actionRow);

    // Advisory actions are kept, but secondary: the mockup leads with the three
    // enforcement actions and these three do not create a rule or limit.
    auto *advisoryRow = new QHBoxLayout();
    advisoryRow->setContentsMargins(0, 0, 0, 0);
    advisoryRow->setSpacing(6);
    advisoryRow->addWidget(makeLabel(QStringLiteral("Advisory:"),
                                     QStringLiteral("helperText"), sectionAction));
    const QList<QPair<NetworkPolicy::Action, QString>> advisory = {
        {NetworkPolicy::Action::Notify, QStringLiteral("Notify")},
        {NetworkPolicy::Action::Ask, QStringLiteral("Ask")},
        {NetworkPolicy::Action::NoAction, QStringLiteral("No action")},
    };
    for (const auto &item : advisory) {
        auto *chip = new QPushButton(item.second, sectionAction);
        chip->setObjectName(QStringLiteral("advisoryChip"));
        chip->setCheckable(true);
        chip->setCursor(Qt::PointingHandCursor);
        chip->setFixedHeight(20);
        m_actionGroup->addButton(chip, static_cast<int>(item.first));
        advisoryRow->addWidget(chip);
    }
    advisoryRow->addStretch(1);
    actionLayout->addLayout(advisoryRow);

    // Kept so an existing Schedule policy can round-trip through the editor.
    auto *scheduleAction = new QPushButton(sectionAction);
    scheduleAction->setCheckable(true);
    scheduleAction->setVisible(false);
    m_actionGroup->addButton(scheduleAction, static_cast<int>(NetworkPolicy::Action::Schedule));

    m_rateContainer = new QWidget(sectionAction);
    auto *rateLayout = new QVBoxLayout(m_rateContainer);
    rateLayout->setContentsMargins(0, 0, 0, 0);
    rateLayout->setSpacing(8);

    auto *rateHead = new QHBoxLayout();
    rateHead->setContentsMargins(0, 0, 0, 0);
    rateHead->setSpacing(4);
    rateHead->addWidget(makeLabel(QStringLiteral("Bandwidth Speed Limit"),
                                  QStringLiteral("fieldLabel"), m_rateContainer));
    rateHead->addStretch(1);
    for (int preset : {50, 250, 500, 1024}) {
        auto *chip = new QPushButton(QString::number(preset), m_rateContainer);
        chip->setObjectName(QStringLiteral("presetChip"));
        chip->setCursor(Qt::PointingHandCursor);
        chip->setFixedHeight(20);
        connect(chip, &QPushButton::clicked, this, [this, preset]() {
            m_rateEdit->setText(QString::number(preset));
            m_rateEdit->setFocus();
            m_rateEdit->selectAll();
        });
        rateHead->addWidget(chip);
    }
    rateLayout->addLayout(rateHead);

    m_rateField = new QFrame(m_rateContainer);
    m_rateField->setObjectName(QStringLiteral("rateField"));
    m_rateField->setFixedHeight(40);
    auto *rateFieldLayout = new QHBoxLayout(m_rateField);
    rateFieldLayout->setContentsMargins(14, 0, 6, 0);
    rateFieldLayout->setSpacing(6);
    m_rateEdit = new QLineEdit(m_rateField);
    m_rateEdit->setObjectName(QStringLiteral("rateInput"));
    m_rateEdit->setFrame(false);
    m_rateEdit->setValidator(new QIntValidator(1, 1000000, m_rateEdit));
    m_rateEdit->setText(QStringLiteral("400"));
    m_rateEdit->setToolTip(QStringLiteral(
        "This build requests a fixed 51.2 KB/s limit. A different rate is "
        "stored with the policy but is not applied yet."));
    m_rateEdit->installEventFilter(this);
    rateFieldLayout->addWidget(m_rateEdit, 1);
    auto *unit = makeLabel(QStringLiteral("KB/s"), QStringLiteral("rateUnit"), m_rateField);
    rateFieldLayout->addWidget(unit);
    rateLayout->addWidget(m_rateField);
    actionLayout->addWidget(m_rateContainer);

    bodyLayout->addWidget(sectionAction);

    // ── 3. Schedule, expiration & note ────────────────────────────────────
    m_accordion = new QFrame(body);
    m_accordion->setObjectName(QStringLiteral("accordion"));
    auto *accordionLayout = new QVBoxLayout(m_accordion);
    accordionLayout->setContentsMargins(0, 0, 0, 0);
    accordionLayout->setSpacing(0);

    m_accordionHeader = new QPushButton(m_accordion);
    m_accordionHeader->setObjectName(QStringLiteral("accordionHeader"));
    m_accordionHeader->setCursor(Qt::PointingHandCursor);
    m_accordionHeader->setFixedHeight(42);
    auto *accordionHead = new QHBoxLayout(m_accordionHeader);
    accordionHead->setContentsMargins(14, 0, 14, 0);
    accordionHead->setSpacing(8);
    m_clockIcon = new QLabel(m_accordionHeader);
    m_clockIcon->setFixedSize(16, 16);
    m_clockIcon->setAttribute(Qt::WA_TransparentForMouseEvents);
    accordionHead->addWidget(m_clockIcon);
    auto *accordionTitle = makeLabel(QStringLiteral("Schedule, Expiration & Note"),
                                     QStringLiteral("accordionTitle"),
                                     m_accordionHeader);
    accordionTitle->setAttribute(Qt::WA_TransparentForMouseEvents);
    accordionHead->addWidget(accordionTitle);
    m_accordionStatus = makeLabel(QString(), QStringLiteral("accordionStatus"),
                                  m_accordionHeader);
    m_accordionStatus->setAttribute(Qt::WA_TransparentForMouseEvents);
    accordionHead->addWidget(m_accordionStatus);
    accordionHead->addStretch(1);
    m_chevron = new QLabel(m_accordionHeader);
    m_chevron->setFixedSize(16, 16);
    m_chevron->setAttribute(Qt::WA_TransparentForMouseEvents);
    accordionHead->addWidget(m_chevron);
    accordionLayout->addWidget(m_accordionHeader);

    m_accordionBody = new QWidget(m_accordion);
    m_accordionBody->setObjectName(QStringLiteral("accordionBody"));
    m_accordionBody->setMaximumHeight(0);
    auto *accordionBodyLayout = new QVBoxLayout(m_accordionBody);
    accordionBodyLayout->setContentsMargins(14, 0, 14, 14);
    accordionBodyLayout->setSpacing(12);

    auto *accordionLine = new QFrame(m_accordionBody);
    accordionLine->setObjectName(QStringLiteral("accordionLine"));
    accordionLine->setFixedHeight(1);
    accordionBodyLayout->addWidget(accordionLine);

    accordionBodyLayout->addWidget(makeLabel(QStringLiteral("Recurring Active Window"),
                                             QStringLiteral("fieldLabel"),
                                             m_accordionBody));
    m_scheduleCombo = new QComboBox(m_accordionBody);
    m_scheduleCombo->setObjectName(QStringLiteral("fieldCombo"));
    m_scheduleCombo->setCursor(Qt::PointingHandCursor);
    m_scheduleCombo->addItem(QStringLiteral("Always in force (24/7)"), QString());
    m_scheduleCombo->addItem(QStringLiteral("Work hours (Mon–Fri, 09:00–17:00)"),
                             QStringLiteral("work-hours"));
    m_scheduleCombo->addItem(QStringLiteral("Overnight (Daily, 22:00–06:00)"),
                             QStringLiteral("overnight"));
    m_scheduleCombo->addItem(QStringLiteral("Custom schedule window..."),
                             QStringLiteral("custom"));
    accordionBodyLayout->addWidget(m_scheduleCombo);

    m_customScheduleWrap = new QWidget(m_accordionBody);
    auto *customLayout = new QVBoxLayout(m_customScheduleWrap);
    customLayout->setContentsMargins(0, 0, 0, 0);
    customLayout->setSpacing(0);
    m_customScheduleEdit = new QLineEdit(m_customScheduleWrap);
    m_customScheduleEdit->setObjectName(QStringLiteral("monoField"));
    m_customScheduleEdit->setPlaceholderText(
        QStringLiteral("e.g. Mon,Wed,Fri 18:00-23:00"));
    customLayout->addWidget(m_customScheduleEdit);
    m_customScheduleWrap->setVisible(false);
    accordionBodyLayout->addWidget(m_customScheduleWrap);

    m_expiresCheck = new PolicyCheckBox(
        QStringLiteral("Automatically expire policy"), m_accordionBody);
    accordionBodyLayout->addWidget(m_expiresCheck);

    m_expirationWrap = new QWidget(m_accordionBody);
    auto *expiryLayout = new QVBoxLayout(m_expirationWrap);
    expiryLayout->setContentsMargins(0, 0, 0, 0);
    expiryLayout->setSpacing(0);
    m_expirationEdit = new QDateTimeEdit(
        QDateTime::currentDateTime().addSecs(3600), m_expirationWrap);
    m_expirationEdit->setObjectName(QStringLiteral("expirationEdit"));
    m_expirationEdit->setCalendarPopup(true);
    m_expirationEdit->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm"));
    expiryLayout->addWidget(m_expirationEdit);
    m_expirationWrap->setVisible(false);
    accordionBodyLayout->addWidget(m_expirationWrap);

    accordionBodyLayout->addWidget(makeLabel(QStringLiteral("Note / Reason"),
                                             QStringLiteral("fieldLabel"),
                                             m_accordionBody));
    m_descriptionEdit = new QLineEdit(m_accordionBody);
    m_descriptionEdit->setObjectName(QStringLiteral("noteInput"));
    m_descriptionEdit->setPlaceholderText(
        QStringLiteral("Optional description (e.g. Prevent background sync spikes)"));
    accordionBodyLayout->addWidget(m_descriptionEdit);

    accordionLayout->addWidget(m_accordionBody);
    bodyLayout->addWidget(m_accordion);

    // ── 4. Live impact preview ────────────────────────────────────────────
    m_impactCard = new QFrame(body);
    m_impactCard->setObjectName(QStringLiteral("impactCard"));
    auto *impactLayout = new QVBoxLayout(m_impactCard);
    impactLayout->setContentsMargins(14, 14, 14, 14);
    impactLayout->setSpacing(10);

    auto *impactHead = new QHBoxLayout();
    impactHead->setContentsMargins(0, 0, 0, 0);
    impactHead->setSpacing(6);
    m_eyeIcon = new QLabel(m_impactCard);
    m_eyeIcon->setFixedSize(14, 14);
    impactHead->addWidget(m_eyeIcon);
    impactHead->addWidget(makeLabel(QStringLiteral("LIVE POLICY SUMMARY"),
                                    QStringLiteral("impactCaption"), m_impactCard));
    impactHead->addStretch(1);
    m_enabledLabel = makeLabel(QStringLiteral("Enabled"),
                               QStringLiteral("enabledState"), m_impactCard);
    impactHead->addWidget(m_enabledLabel);
    m_enabledSwitch = new PolicyToggleSwitch(m_impactCard);
    m_enabledSwitch->setChecked(true);
    impactHead->addWidget(m_enabledSwitch);
    impactLayout->addLayout(impactHead);

    m_impactLabel = makeLabel(QString(), QStringLiteral("impactSummary"), m_impactCard);
    m_impactLabel->setWordWrap(true);
    m_impactLabel->setTextFormat(Qt::RichText);
    m_impactLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    impactLayout->addWidget(m_impactLabel);

    m_enforcementLabel = makeLabel(QString(), QStringLiteral("enforcementLabel"),
                                   m_impactCard);
    m_enforcementLabel->setWordWrap(true);
    impactLayout->addWidget(m_enforcementLabel);
    bodyLayout->addWidget(m_impactCard);

    // ── Footer ────────────────────────────────────────────────────────────
    // Sits outside the scroll area so Cancel / Save stay reachable while the
    // form above scrolls.
    auto *footerLine = new QFrame(m_card);
    footerLine->setObjectName(QStringLiteral("headerLine"));
    footerLine->setFixedHeight(1);
    cardLayout->addWidget(footerLine);

    auto *footer = new QWidget(m_card);
    auto *footerRow = new QHBoxLayout(footer);
    footerRow->setContentsMargins(20, 12, 20, 16);
    footerRow->setSpacing(10);
    footerRow->addStretch(1);

    m_cancelButton = new QPushButton(QStringLiteral("Cancel"), footer);
    m_cancelButton->setObjectName(QStringLiteral("cancelButton"));
    m_cancelButton->setCursor(Qt::PointingHandCursor);
    m_cancelButton->setAutoDefault(false);
    footerRow->addWidget(m_cancelButton);

    m_saveButton = new QPushButton(QStringLiteral("Save Policy"), footer);
    m_saveButton->setObjectName(QStringLiteral("saveButton"));
    m_saveButton->setCursor(Qt::PointingHandCursor);
    m_saveButton->setDefault(true);
    footerRow->addWidget(m_saveButton);
    cardLayout->addWidget(footer);

    // Toast for validation and status, positioned over the card.
    m_toast = new QLabel(m_card);
    m_toast->setObjectName(QStringLiteral("toast"));
    m_toast->setWordWrap(true);
    m_toast->setMaximumWidth(360);
    m_toast->setVisible(false);
    m_toastEffect = new QGraphicsOpacityEffect(m_toast);
    m_toastEffect->setOpacity(0.0);
    m_toast->setGraphicsEffect(m_toastEffect);
    m_toastFade = new QPropertyAnimation(m_toastEffect, "opacity", this);
    m_toastFade->setDuration(220);

    // ── Connections ───────────────────────────────────────────────────────
    connect(m_closeButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_saveButton, &QPushButton::clicked, this, &PolicyEditorDialog::accept);
    connect(m_browseButton, &QPushButton::clicked,
            this, &PolicyEditorDialog::browseForExecutable);

    connect(m_scopeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() {
        updateScopeTarget();
        updateImpactPreview();
    });
    connect(m_targetEdit, &QLineEdit::textChanged, this, [this]() {
        updateServiceBanner();
        updateImpactPreview();
    });

    connect(m_actionGroup, &QButtonGroup::buttonToggled, this,
            [this](QAbstractButton *, bool checked) {
        if (checked) updateActionControls();
    });
    connect(m_directionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PolicyEditorDialog::updateImpactPreview);
    connect(m_rateEdit, &QLineEdit::textChanged,
            this, &PolicyEditorDialog::updateImpactPreview);

    connect(m_scheduleCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]() {
        const bool custom = m_scheduleCombo->currentData().toString() ==
                            QLatin1String("custom");
        m_customScheduleWrap->setVisible(custom);
        if (custom && m_customScheduleEdit->text().trimmed().isEmpty())
            m_customScheduleEdit->setFocus();
        updateImpactPreview();
    });
    connect(m_customScheduleEdit, &QLineEdit::textChanged,
            this, &PolicyEditorDialog::updateImpactPreview);
    connect(m_expiresCheck, &QAbstractButton::toggled, this, [this](bool checked) {
        m_expirationWrap->setVisible(checked);
        updateImpactPreview();
    });
    connect(m_expirationEdit, &QDateTimeEdit::dateTimeChanged,
            this, &PolicyEditorDialog::updateImpactPreview);

    connect(m_enabledSwitch, &QAbstractButton::toggled, this, [this](bool enabled) {
        m_enabledLabel->setText(enabled ? QStringLiteral("Enabled")
                                        : QStringLiteral("Disabled"));
        updateImpactPreview();
    });
    connect(m_accordionHeader, &QPushButton::clicked,
            this, &PolicyEditorDialog::toggleAccordion);

    m_accordionAnim = new QPropertyAnimation(m_accordionBody, "maximumHeight", this);
    m_accordionAnim->setDuration(240);
    m_accordionAnim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_accordionAnim, &QPropertyAnimation::valueChanged, this, [this]() {
        m_scroll->updateGeometry();
    });
    connect(m_accordionAnim, &QPropertyAnimation::finished, this, [this]() {
        if (m_accordionOpen)
            m_accordionBody->setMaximumHeight(QWIDGETSIZE_MAX);
    });

    // Drag the frameless card by its header.
    QWidget *handles[] = {m_header, m_titleLabel, m_processBadge, m_headerIcon};
    for (QWidget *handle : handles)
        handle->installEventFilter(this);

    applyTheme();
    updateAccordionStatus();

    // Cap the scroll viewport before the fixed-size layout is first applied so
    // the dialog never flashes at its full content height. Measure the chrome
    // (header, sticky footer, dividers and shadow margins) instead of assuming
    // a constant, then leave 8 px so the card always fits on screen.
    layout()->activate();
    const int chrome = cardLayout->sizeHint().height()
        - m_scroll->sizeHint().height() + 2 * 28;
    const QRect available = screen() ? screen()->availableGeometry()
                                     : QRect(0, 0, 1080, 720);
    m_scroll->setMaximumHeight(qMax(240, available.height() - chrome - 8));
}

void PolicyEditorDialog::applyTheme()
{
    const DialogColors c = dialogColors(ThemeManager::instance().isDark());
    setStyleSheet(dialogStyleSheet(c));

    // A long executable or publisher name must not push the close button out of
    // the fixed-width card; elide it in the middle and keep the full text in the
    // tooltip.
    const QString badgeText = m_processBadge->property("fullText").toString();
    m_processBadge->setMaximumWidth(240);
    m_processBadge->setText(m_processBadge->fontMetrics().elidedText(
        badgeText, Qt::ElideMiddle, 216));

    m_headerIcon->setPixmap(glyphPixmap(GlyphShield, 20, c.accent, 1.6));
    m_closeButton->setIcon(QIcon(glyphPixmap(GlyphClose, 16, c.muted, 1.8)));
    m_closeButton->setIconSize(QSize(16, 16));
    m_browseButton->setIcon(QIcon(glyphPixmap(GlyphFolder, 16, c.muted, 1.6)));
    m_browseButton->setIconSize(QSize(16, 16));
    m_clockIcon->setPixmap(glyphPixmap(GlyphClock, 16, c.muted, 1.6));
    m_eyeIcon->setPixmap(glyphPixmap(GlyphEye, 14, c.accentText, 1.6));
    m_chevron->setPixmap(glyphPixmap(m_accordionOpen ? GlyphChevronUp : GlyphChevronDown,
                                     16, c.muted, 1.8));
    m_saveButton->setIcon(QIcon(glyphPixmap(GlyphCheck, 14, QColor("#FFFFFF"), 2.0)));
    m_saveButton->setIconSize(QSize(14, 14));

    const bool dark = ThemeManager::instance().isDark();
    const QColor actionBg = dark ? QColor("#11151D") : c.field;
    const QColor actionText = dark ? c.muted : QColor("#475569");
    for (PolicyActionCard *card : m_actionCards)
        card->setColors(actionBg, c.fieldBorder, actionText, c.hover, c.accentText);

    m_enabledSwitch->setColors(dark ? QColor("#334155") : QColor("#CBD5E1"),
                               c.accentSolid, QColor("#FFFFFF"));
    m_expiresCheck->setColors(c.text, c.fieldBorder, c.accentSolid, c.field);

    // The mockup tracks its uppercase labels; Qt style sheets cannot set
    // letter spacing, so apply it to the font once the sheet has been styled.
    for (QLabel *label : findChildren<QLabel *>(QStringLiteral("sectionLabel"))) {
        QFont f = label->font();
        f.setLetterSpacing(QFont::AbsoluteSpacing, 0.6);
        label->setFont(f);
    }
    if (QLabel *caption = findChild<QLabel *>(QStringLiteral("impactCaption"))) {
        QFont f = caption->font();
        f.setLetterSpacing(QFont::AbsoluteSpacing, 0.6);
        caption->setFont(f);
    }

    m_impactCard->setProperty("enabled", m_enabledSwitch->isChecked());
    repolish(m_impactCard);

    if (!m_toast->isVisible()) m_toast->setGraphicsEffect(m_toastEffect);

    updateImpactPreview();
}

void PolicyEditorDialog::updateScopeTarget()
{
    const PolicyScopeKind scope = currentScope();

    // The target follows the scope: switching to publisher must not silently
    // keep a path in the field and save a policy that matches nothing.
    switch (scope) {
    case PolicyScopeKind::Pid:
        m_targetEdit->setReadOnly(true);
        m_targetEdit->setPlaceholderText(QString());
        m_browseButton->setVisible(false);
        if (m_target.pid == 0)
            m_targetEdit->clear();
        else if (m_target.processName.isEmpty())
            m_targetEdit->setText(QStringLiteral("PID %1").arg(m_target.pid));
        else
            m_targetEdit->setText(QStringLiteral("PID %1 (%2)")
                                      .arg(m_target.pid)
                                      .arg(m_target.processName));
        m_targetHint->setText(
            QStringLiteral("Applies only while this process instance is running."));
        break;
    case PolicyScopeKind::ExecutablePath:
        m_targetEdit->setReadOnly(false);
        m_targetEdit->setPlaceholderText(
            QStringLiteral("e.g. C:\\Program Files\\App\\app.exe"));
        m_browseButton->setVisible(true);
        m_targetEdit->setText(m_target.executablePath);
        m_targetHint->setText(
            QStringLiteral("Applies to this executable file now and on future launches."));
        break;
    case PolicyScopeKind::Publisher:
        m_targetEdit->setReadOnly(false);
        m_targetEdit->setPlaceholderText(QStringLiteral("e.g. Google LLC"));
        m_browseButton->setVisible(false);
        m_targetEdit->setText(m_target.publisher);
        m_targetHint->setText(
            QStringLiteral("Applies to every process signed by this publisher, including "
                           "software you have not seen yet."));
        break;
    case PolicyScopeKind::Service:
        m_targetEdit->setReadOnly(false);
        m_targetEdit->setPlaceholderText(QStringLiteral("e.g. wuauserv"));
        m_browseButton->setVisible(false);
        m_targetEdit->setText(m_target.serviceName);
        m_targetHint->setText(
            QStringLiteral("Applies to this Windows service and the processes that host it."));
        break;
    case PolicyScopeKind::ApplicationGroup:
        m_targetEdit->setReadOnly(true);
        m_targetEdit->setPlaceholderText(QString());
        m_browseButton->setVisible(false);
        m_targetEdit->setText(m_target.groupName.isEmpty()
            ? m_target.groupId
            : QStringLiteral("%1 (%2)").arg(m_target.groupName, m_target.groupId));
        m_targetHint->setText(
            QStringLiteral("Applies to every current and future member of this activity group."));
        break;
    }

    updateServiceBanner();
}

void PolicyEditorDialog::updateServiceBanner()
{
    const bool serviceScope = currentScope() == PolicyScopeKind::Service;
    const bool hostProcess =
        m_targetEdit->text().contains(QStringLiteral("svchost.exe"), Qt::CaseInsensitive);
    const bool show = serviceScope || hostProcess;

    m_serviceBanner->setVisible(show);
    m_targetHint->setVisible(!show);
    if (!show) return;

    QString service = serviceScope ? m_targetEdit->text().trimmed()
                                   : m_target.serviceName;
    if (service.isEmpty()) service = QStringLiteral("the selected service");
    m_serviceBanner->setText(
        QStringLiteral("<span style=\"font-weight:600;\">System Host Exception:</span> "
                       "<span style=\"font-family:'JetBrains Mono';\">svchost.exe</span> "
                       "hosts multiple Windows services. Scoped specifically to "
                       "<b>%1</b> so other system services aren't disrupted.")
            .arg(service.toHtmlEscaped()));
}

void PolicyEditorDialog::updateActionControls()
{
    const NetworkPolicy::Action action = currentAction();
    const bool shaping = action == NetworkPolicy::Action::Throttle ||
                         action == NetworkPolicy::Action::Schedule;
    m_rateContainer->setVisible(shaping);
    // The scroll area does not hear layout requests from its content widget, so
    // tell it the preferred height changed.
    m_scroll->updateGeometry();
    // Direction is stored either way, but only shaping uses it in this build.
    m_directionCombo->setEnabled(shaping);
    updateImpactPreview();
}

void PolicyEditorDialog::updateImpactPreview()
{
    if (!m_impactLabel) return;

    const bool enabled = m_enabledSwitch->isChecked();
    m_impactCard->setProperty("enabled", enabled);
    repolish(m_impactCard);

    m_impactLabel->setText(previewHtml());
    m_enforcementLabel->setText(enforcementText());

    const NetworkPolicy::Action action = currentAction();
    const bool advisory = action == NetworkPolicy::Action::Notify ||
                          action == NetworkPolicy::Action::Ask ||
                          action == NetworkPolicy::Action::NoAction;
    const bool shaping = action == NetworkPolicy::Action::Throttle ||
                         action == NetworkPolicy::Action::Schedule;
    const qint64 kbps = m_rateEdit->text().toLongLong();
    const bool warning = !policyScopeEnforcedByThisBuild(currentScope()) || advisory ||
                         (shaping && kbps > 0 && kbps * 8000 != 409600);
    m_enforcementLabel->setProperty("warning", warning);
    repolish(m_enforcementLabel);

    updateAccordionStatus();
}

void PolicyEditorDialog::updateAccordionStatus()
{
    if (!m_accordionStatus) return;
    const bool configured = !scheduleValue().isEmpty() || m_expiresCheck->isChecked();
    m_accordionStatus->setText(configured
        ? QStringLiteral("(Configured)")
        : QStringLiteral("(Optional — Always active)"));
    m_accordionStatus->setProperty("configured", configured);
    repolish(m_accordionStatus);
}

void PolicyEditorDialog::toggleAccordion()
{
    if (m_accordionAnim->state() == QPropertyAnimation::Running)
        m_accordionAnim->stop();

    int start = m_accordionBody->maximumHeight();
    if (start == QWIDGETSIZE_MAX) start = m_accordionBody->height();
    int end = 0;

    if (!m_accordionOpen) {
        m_accordionOpen = true;
        m_accordionBody->setMaximumHeight(QWIDGETSIZE_MAX);
        end = m_accordionBody->sizeHint().height();
        m_accordionBody->setMaximumHeight(start);
    } else {
        m_accordionOpen = false;
        start = m_accordionBody->height();
    }

    m_accordionAnim->setStartValue(start);
    m_accordionAnim->setEndValue(end);
    m_accordionAnim->start();

    m_chevron->setPixmap(glyphPixmap(
        m_accordionOpen ? GlyphChevronUp : GlyphChevronDown, 16,
        dialogColors(ThemeManager::instance().isDark()).muted, 1.8));
}

void PolicyEditorDialog::setScheduleValue(const QString &schedule)
{
    const QString value = schedule.trimmed();
    int index = m_scheduleCombo->findData(value);
    if (value.isEmpty()) {
        index = 0;
    } else if (index < 0) {
        index = m_scheduleCombo->findData(QStringLiteral("custom"));
        m_customScheduleEdit->setText(value);
        m_customScheduleWrap->setVisible(true);
    }
    if (index >= 0) m_scheduleCombo->setCurrentIndex(index);
}

QString PolicyEditorDialog::scheduleValue() const
{
    if (m_scheduleCombo->currentData().toString() == QLatin1String("custom"))
        return m_customScheduleEdit->text().trimmed();
    return m_scheduleCombo->currentData().toString().trimmed();
}

QString PolicyEditorDialog::processBadgeText() const
{
    QString name = m_target.processName;
    quint32 pid = m_target.pid;

    if (m_editing) {
        if (m_policy.scope == QLatin1String("pid"))
            pid = m_policy.targetId.toUInt();
        else if (name.isEmpty())
            name = QFileInfo(m_policy.targetId).fileName();
    }
    if (name.isEmpty() && !m_target.executablePath.isEmpty())
        name = QFileInfo(m_target.executablePath).fileName();
    if (name.isEmpty() && !m_target.groupName.isEmpty())
        name = m_target.groupName;
    if (name.isEmpty() && !m_target.serviceName.isEmpty())
        name = m_target.serviceName;
    if (name.isEmpty() && !m_target.publisher.isEmpty())
        name = m_target.publisher;
    if (name.isEmpty()) name = QStringLiteral("policy target");

    if (pid != 0)
        return QStringLiteral("%1 (PID %2)").arg(name).arg(pid);
    return name;
}

QString PolicyEditorDialog::previewHtml() const
{
    const DialogColors c = dialogColors(ThemeManager::instance().isDark());
    const PolicyScopeKind scope = currentScope();
    // PID and group policies store an opaque id; the badge carries the friendly
    // "name (PID)" form, so reuse it instead of showing the raw id.
    const QString rawTarget = (scope == PolicyScopeKind::Pid ||
                               scope == PolicyScopeKind::ApplicationGroup)
        ? m_processBadge->text()
        : targetForScope();
    QString targetName;
    if (scope == PolicyScopeKind::ExecutablePath)
        targetName = QFileInfo(rawTarget).fileName();
    else
        targetName = rawTarget.trimmed();
    if (targetName.isEmpty()) targetName = QStringLiteral("the selected target");

    const QString targetSpan = QStringLiteral(
        "<span style=\"font-family:'JetBrains Mono'; font-size:11px;\">%1</span>")
        .arg(targetName.toHtmlEscaped());

    const NetworkPolicy::Action action = currentAction();
    const NetworkDirection direction = static_cast<NetworkDirection>(
        m_directionCombo->currentData().toInt());
    const qint64 kbps = m_rateEdit->text().toLongLong();

    QString directionPhrase;
    switch (direction) {
    case NetworkDirection::Download: directionPhrase = QStringLiteral("for downloads"); break;
    case NetworkDirection::Upload: directionPhrase = QStringLiteral("for uploads"); break;
    case NetworkDirection::Both: directionPhrase = QStringLiteral("in both directions"); break;
    }

    QString actionPhrase;
    switch (action) {
    case NetworkPolicy::Action::Throttle:
        actionPhrase = QStringLiteral(
            "<b style=\"color:%1;\">Throttle</b> traffic for %2 to "
            "<b>%3 KB/s</b> %4")
            .arg(c.accentText.name(), targetSpan, QString::number(kbps),
                 directionPhrase);
        break;
    case NetworkPolicy::Action::Block:
        actionPhrase = QStringLiteral(
            "<b style=\"color:%1;\">Block</b> all inbound and outbound traffic for %2")
            .arg(c.dangerText.name(), targetSpan);
        break;
    case NetworkPolicy::Action::Allow:
        actionPhrase = QStringLiteral(
            "Explicitly <b style=\"color:%1;\">Allow</b> all inbound and outbound "
            "traffic for %2")
            .arg(c.successText.name(), targetSpan);
        break;
    case NetworkPolicy::Action::Notify:
        actionPhrase = QStringLiteral(
            "<b style=\"color:%1;\">Notify</b> you about traffic for %2")
            .arg(c.accentText.name(), targetSpan);
        break;
    case NetworkPolicy::Action::Ask:
        actionPhrase = QStringLiteral(
            "<b style=\"color:%1;\">Ask</b> before allowing traffic for %2")
            .arg(c.accentText.name(), targetSpan);
        break;
    case NetworkPolicy::Action::NoAction:
        actionPhrase = QStringLiteral("Take no action for %1").arg(targetSpan);
        break;
    case NetworkPolicy::Action::Schedule:
        actionPhrase = QStringLiteral(
            "<b style=\"color:%1;\">Apply the scheduled limit</b> to %2")
            .arg(c.accentText.name(), targetSpan);
        break;
    }

    const QString schedule = scheduleValue();
    QString schedulePhrase = QStringLiteral("active immediately");
    if (schedule == QLatin1String("work-hours")) {
        schedulePhrase = QStringLiteral(
            "active during <b>work hours (Mon–Fri, 09:00–17:00)</b>");
    } else if (schedule == QLatin1String("overnight")) {
        schedulePhrase = QStringLiteral("active <b>overnight (22:00–06:00)</b>");
    } else if (!schedule.isEmpty()) {
        schedulePhrase = QStringLiteral(
            "active during <span style=\"font-family:'JetBrains Mono'; font-size:11px;\">%1</span>")
            .arg(schedule.toHtmlEscaped());
    }

    QString expirationPhrase = QStringLiteral("with no expiration");
    if (m_expiresCheck->isChecked()) {
        expirationPhrase = QStringLiteral("until <b>%1</b>")
            .arg(m_expirationEdit->dateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm")));
    }

    const bool enabled = m_enabledSwitch->isChecked();
    if (!enabled) {
        return QStringLiteral(
            "<b>Saved inactive</b> — will %1, %2 %3 once enabled.")
            .arg(actionPhrase, schedulePhrase, expirationPhrase);
    }
    return QStringLiteral("This will %1, %2 %3.")
        .arg(actionPhrase, schedulePhrase, expirationPhrase);
}

QString PolicyEditorDialog::enforcementText() const
{
    const NetworkPolicy::Action action = currentAction();
    if (action == NetworkPolicy::Action::Notify ||
        action == NetworkPolicy::Action::Ask ||
        action == NetworkPolicy::Action::NoAction) {
        return QStringLiteral("Advisory only: this action does not change firewall "
                              "or bandwidth state in this build.");
    }

    QString note = policyScopeEnforcementNote(currentScope());
    const bool shaping = action == NetworkPolicy::Action::Throttle ||
                         action == NetworkPolicy::Action::Schedule;
    if (shaping) {
        note += QStringLiteral(" The throttle channel requests a fixed 51.2 KB/s "
                               "in this build, so the stored rate is not the "
                               "applied one.");
    }
    return note;
}

PolicyScopeKind PolicyEditorDialog::currentScope() const
{
    return static_cast<PolicyScopeKind>(m_scopeCombo->currentData().toInt());
}

NetworkPolicy::Action PolicyEditorDialog::currentAction() const
{
    if (!m_actionGroup) return NetworkPolicy::Action::Throttle;
    const int id = m_actionGroup->checkedId();
    if (id < 0) return NetworkPolicy::Action::Throttle;
    return static_cast<NetworkPolicy::Action>(id);
}

void PolicyEditorDialog::setAction(NetworkPolicy::Action action)
{
    if (QAbstractButton *button = m_actionGroup->button(static_cast<int>(action)))
        button->setChecked(true);
}

PolicyImpact PolicyEditorDialog::currentImpact() const
{
    PolicyImpact impact;
    impact.scope = currentScope();
    // PID and group policies are saved by id, but the preview and the
    // confirmation should name the thing the user recognises, so they reuse the
    // read-only target field that carries the process name or group name.
    impact.target = (impact.scope == PolicyScopeKind::Pid ||
                     impact.scope == PolicyScopeKind::ApplicationGroup)
        ? m_targetEdit->text().trimmed()
        : targetForScope();
    impact.action = currentAction();
    impact.direction = static_cast<NetworkDirection>(
        m_directionCombo->currentData().toInt());
    impact.rateBitsPerSecond = impact.action == NetworkPolicy::Action::Throttle
        ? static_cast<quint64>(qRound64(m_rateEdit->text().toDouble() * 8000.0))
        : 0;
    impact.expiration = m_expiresCheck->isChecked()
        ? m_expirationEdit->dateTime() : QDateTime();
    impact.schedule = scheduleValue();
    impact.enabled = m_enabledSwitch->isChecked();
    return impact;
}

QString PolicyEditorDialog::targetForScope() const
{
    switch (currentScope()) {
    case PolicyScopeKind::Pid: return QString::number(m_target.pid);
    case PolicyScopeKind::ApplicationGroup: return m_target.groupId;
    default: return m_targetEdit->text().trimmed();
    }
}

void PolicyEditorDialog::browseForExecutable()
{
    const QString start = m_targetEdit->text().trimmed().isEmpty()
        ? m_target.executablePath
        : m_targetEdit->text().trimmed();
    const QString file = QFileDialog::getOpenFileName(
        this, QStringLiteral("Select executable"), start,
        QStringLiteral("Executables (*.exe);;All files (*.*)"));
    if (!file.isEmpty()) {
        m_targetEdit->setText(QDir::toNativeSeparators(file));
        m_targetEdit->setFocus();
    }
}

void PolicyEditorDialog::showToast(const QString &message)
{
    if (!m_toast) return;

    if (m_toastFade->state() == QPropertyAnimation::Running) m_toastFade->stop();
    m_toast->setText(message);
    const int toastWidth = qMin(360, m_card->width() - 40);
    m_toast->setFixedWidth(toastWidth);
    // QLabel::adjustSize() ignores wrapped height, so measure it explicitly and
    // add the style's 10 px top/bottom padding plus the 1 px border.
    int textHeight = m_toast->heightForWidth(toastWidth);
    if (textHeight <= 0) textHeight = m_toast->fontMetrics().height();
    m_toast->setFixedHeight(textHeight + 24);
    // Keep the toast above the now-sticky footer.
    const int toastBottom = m_scroll->isVisible()
        ? m_scroll->geometry().bottom() - 12
        : m_card->height() - 20;
    const QPoint pos(m_card->width() - m_toast->width() - 20,
                     toastBottom - m_toast->height());
    m_toast->move(pos);
    m_toast->raise();
    m_toast->show();
    m_toastEffect->setOpacity(0.0);
    m_toastFade->setStartValue(0.0);
    m_toastFade->setEndValue(1.0);
    m_toastFade->start();

    QTimer::singleShot(3200, m_toast, [this]() {
        if (!m_toast) return;
        m_toastFade->stop();
        m_toastFade->setStartValue(m_toastEffect->opacity());
        m_toastFade->setEndValue(0.0);
        m_toastFade->start();
        QTimer::singleShot(240, m_toast, [this]() { m_toast->hide(); });
    });
}

void PolicyEditorDialog::repolish(QWidget *widget)
{
    if (!widget) return;
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
    widget->update();
}

bool PolicyEditorDialog::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == m_targetEdit || watched == m_rateEdit) {
        QFrame *frame = watched == m_targetEdit ? m_targetField : m_rateField;
        if (event->type() == QEvent::FocusIn) {
            frame->setProperty("focused", true);
            repolish(frame);
        } else if (event->type() == QEvent::FocusOut) {
            frame->setProperty("focused", false);
            repolish(frame);
        }
    }

    if (event->type() == QEvent::MouseButtonPress) {
        auto *mouse = static_cast<QMouseEvent *>(event);
        if (mouse->button() == Qt::LeftButton &&
            (watched == m_header || watched == m_titleLabel ||
             watched == m_processBadge || watched == m_headerIcon)) {
            if (windowHandle()) {
                windowHandle()->startSystemMove();
                return true;
            }
        }
    }

    return QDialog::eventFilter(watched, event);
}

void PolicyEditorDialog::showEvent(QShowEvent *event)
{
    QDialog::showEvent(event);
    if (!m_sized) {
        layout()->activate();
        adjustSize();
        m_sized = true;
    }
    if (!m_initialFocusDone) {
        m_initialFocusDone = true;
        // Start on the field the dialog is about. When the scope makes the
        // target read-only (PID or activity group), the action choice is the
        // first thing the user can actually change, so focus the selected
        // action card instead of a field that only displays a value.
        QWidget *initial = m_targetEdit;
        if (m_targetEdit->isReadOnly() && m_actionGroup &&
            m_actionGroup->checkedButton()) {
            initial = m_actionGroup->checkedButton();
        }
        if (initial) initial->setFocus(Qt::OtherFocusReason);
    }
    const QRect available = screen() ? screen()->availableGeometry()
                                     : QRect();
    if (available.isValid())
        move(available.center() - QPoint(width() / 2, height() / 2));
}

void PolicyEditorDialog::resizeEvent(QResizeEvent *event)
{
    QDialog::resizeEvent(event);
    // The fixed-size layout settles a beat after showEvent, so recentre on the
    // final size (and after any explicit content-height change).
    if (m_sized) {
        const QRect available = screen() ? screen()->availableGeometry()
                                         : QRect();
        if (available.isValid()) {
            const QPoint centered = available.center() -
                QPoint(width() / 2, height() / 2);
            if (pos() != centered) move(centered);
        }
    }
    if (m_toast && m_toast->isVisible()) {
        const int toastBottom = m_scroll->isVisible()
            ? m_scroll->geometry().bottom() - 12
            : m_card->height() - 20;
        m_toast->move(m_card->width() - m_toast->width() - 20,
                      toastBottom - m_toast->height());
    }
}

void PolicyEditorDialog::accept()
{
    const PolicyScopeKind scope = currentScope();
    const NetworkPolicy::Action action = currentAction();
    const QString target = targetForScope();

    if (scope == PolicyScopeKind::Pid && m_target.pid == 0) {
        showToast(QStringLiteral("Select a process row before creating a "
                                 "PID-scoped policy."));
        return;
    }
    if (scope == PolicyScopeKind::ApplicationGroup && m_target.groupId.isEmpty()) {
        showToast(QStringLiteral("This process does not belong to an activity group, "
                                 "so a group-scoped policy has no target."));
        return;
    }
    if (scope != PolicyScopeKind::Pid && scope != PolicyScopeKind::ApplicationGroup &&
        target.isEmpty()) {
        showToast(QStringLiteral("Enter the %1 this policy should cover.")
                      .arg(scope == PolicyScopeKind::Publisher
                               ? QStringLiteral("publisher")
                               : scope == PolicyScopeKind::Service
                                     ? QStringLiteral("service name")
                                     : QStringLiteral("path")));
        m_targetEdit->setFocus();
        return;
    }

    const QString schedule = scheduleValue();
    if (!schedule.isEmpty() && !scheduleIsSupported(schedule)) {
        showToast(QStringLiteral("The recurring window \"%1\" is not recognised. "
                                 "Use work-hours, overnight, HH:MM-HH:MM, or "
                                 "\"Mon-Fri 09:00-17:00\".").arg(schedule));
        return;
    }

    const bool shaping = action == NetworkPolicy::Action::Throttle ||
                         action == NetworkPolicy::Action::Schedule;
    if (shaping && m_rateEdit->text().toLongLong() <= 0) {
        showToast(QStringLiteral("A throttle policy needs a rate above zero."));
        m_rateEdit->setFocus();
        return;
    }

    const QDateTime now = QDateTime::currentDateTime();
    if (m_expiresCheck->isChecked() && m_expirationEdit->dateTime() <= now) {
        showToast(QStringLiteral("The expiration must be in the future."));
        m_expirationEdit->setFocus();
        return;
    }

    // NG-053: a publisher or group policy covers software the user did not pick
    // directly, so it is confirmed with its impact spelled out. Cancel is the
    // default button: an accidental Enter must not widen enforcement.
    const PolicyImpact impact = currentImpact();
    if (policyScopeRequiresConfirmation(impact.scope, impact.enabled)) {
        const QMessageBox::StandardButton answer = QMessageBox::question(
            this, QStringLiteral("Confirm broad policy"),
            policyConfirmationText(impact, now),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (answer != QMessageBox::Yes) return;
    }

    m_policy = NetworkPolicy();
    m_policy.id = m_editing
        ? m_policyId
        : QStringLiteral("policy-") +
              QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_policy.scope = policyScopeKey(scope);
    m_policy.targetId = target;
    m_policy.direction = static_cast<NetworkDirection>(
        m_directionCombo->currentData().toInt());
    m_policy.action = action;
    m_policy.rateBitsPerSecond = shaping
        ? static_cast<quint64>(qRound64(m_rateEdit->text().toDouble() * 8000.0))
        : 0;

    const bool expires = m_expiresCheck->isChecked();
    m_policy.schedule = schedule;
    m_policy.expiration = expires ? m_expirationEdit->dateTime() : QDateTime();
    if (expires && !schedule.isEmpty()) {
        m_policy.scheduleType = NetworkPolicy::ScheduleType::Both;
    } else if (expires) {
        m_policy.scheduleType = NetworkPolicy::ScheduleType::Expiration;
    } else if (!schedule.isEmpty()) {
        m_policy.scheduleType = NetworkPolicy::ScheduleType::Recurring;
    } else {
        m_policy.scheduleType = NetworkPolicy::ScheduleType::None;
    }

    m_policy.source = m_editing ? m_policySource : QStringLiteral("user");
    m_policy.enabled = m_enabledSwitch->isChecked();
    m_policy.description = m_descriptionEdit->text().trimmed();

    QDialog::accept();
}
