/**
 * @file   policyeditorcontrols.h
 * @brief  Painted controls used by the policy editor and its rule form.
 * @author Codebuff
 */

#pragma once

#include "policyeditorstyle.h"

#include <QAbstractButton>
#include <QFont>
#include <QPainter>
#include <QPen>
#include <QRect>
#include <QSizePolicy>
#include <QColor>
#include <QString>
#include <QWidget>



// ─── Painted controls ───────────────────────────────────────────────────────

namespace PolicyEditorStyle {
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
        setMinimumHeight(58);
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

    QSize sizeHint() const override { return QSize(150, 58); }

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

        paintGlyph(p, m_glyph, QRectF(width() / 2.0 - 8.0, 10.0, 16.0, 16.0),
                   m_accent, 1.6);

        QFont labelFont(QStringLiteral("Inter"));
        labelFont.setPixelSize(12);
        labelFont.setWeight(QFont::DemiBold);
        p.setFont(labelFont);
        p.setPen(isChecked() ? m_checkedText : m_text);
        p.drawText(QRect(0, 31, width(), 18),
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
} // namespace PolicyEditorStyle
