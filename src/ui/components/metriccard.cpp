/**
 * @file    metriccard.cpp
 * @author  Oasis
 */
#include "metriccard.h"

#include "ui/theme/dimensions.h"

#include <QKeyEvent>
#include <QLabel>
#include <QMouseEvent>
#include <QVBoxLayout>

MetricCard::MetricCard(const QString &label, QWidget *parent)
    : QFrame(parent)
{
    setObjectName(QStringLiteral("MetricCard"));
    setProperty("uiRole", QStringLiteral("card"));
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setMinimumWidth(120);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceMd,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceMd);
    layout->setSpacing(Theme::Dim::SpaceXs);

    m_label = new QLabel(label, this);
    m_label->setProperty("uiRole", QStringLiteral("kpiLabel"));

    m_value = new QLabel(QStringLiteral("—"), this);
    m_value->setProperty("uiRole", QStringLiteral("metricValue"));

    m_caption = new QLabel(this);
    m_caption->setProperty("uiRole", QStringLiteral("muted"));
    m_caption->setWordWrap(true);
    m_caption->hide();

    layout->addWidget(m_label);
    layout->addWidget(m_value);
    layout->addWidget(m_caption);
}

void MetricCard::setValue(const QString &value)
{
    m_value->setText(value.isEmpty() ? QStringLiteral("—") : value);
}

void MetricCard::setCaption(const QString &caption)
{
    m_caption->setText(caption);
    m_caption->setVisible(!caption.isEmpty());
}

void MetricCard::setValueColor(const QColor &color)
{
    if (!color.isValid()) {
        m_value->setStyleSheet(QString());
        return;
    }
    m_value->setStyleSheet(QStringLiteral("color: %1;").arg(color.name()));
}

void MetricCard::setClickable(bool clickable)
{
    m_clickable = clickable;
    setCursor(clickable ? Qt::PointingHandCursor : Qt::ArrowCursor);
    setFocusPolicy(clickable ? Qt::StrongFocus : Qt::NoFocus);
}

void MetricCard::setToolTipText(const QString &text)
{
    setToolTip(text);
}

void MetricCard::mouseReleaseEvent(QMouseEvent *event)
{
    if (m_clickable && event->button() == Qt::LeftButton && rect().contains(event->pos())) {
        emit clicked();
        event->accept();
        return;
    }
    QFrame::mouseReleaseEvent(event);
}

void MetricCard::keyPressEvent(QKeyEvent *event)
{
    if (m_clickable
        && (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter
            || event->key() == Qt::Key_Space)) {
        emit clicked();
        event->accept();
        return;
    }
    QFrame::keyPressEvent(event);
}
