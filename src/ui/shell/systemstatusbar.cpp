/**
 * @file    systemstatusbar.cpp
 * @author  Oasis
 */
#include "systemstatusbar.h"

#include "ui/theme/dimensions.h"

#include <QDateTime>
#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QStyle>

SystemStatusBar::SystemStatusBar(QWidget *parent)
    : QFrame(parent)
{
    setObjectName(QStringLiteral("statusBar"));
    setFixedHeight(Theme::Dim::StatusBarHeight);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(Theme::Dim::SpaceXl, 0,
                               Theme::Dim::SpaceXl, 0);
    layout->setSpacing(Theme::Dim::SpaceLg);

    m_message = new QLabel(QStringLiteral("Monitoring: Stopped"), this);
    m_message->setObjectName(QStringLiteral("statusMsg"));
    m_message->setCursor(Qt::PointingHandCursor);
    m_message->setToolTip(QStringLiteral("Click for the details of the last notification."));
    m_message->installEventFilter(this);

    m_warning = new QLabel(this);
    m_warning->setObjectName(QStringLiteral("warningMsg"));
    m_warning->setCursor(Qt::PointingHandCursor);
    m_warning->installEventFilter(this);
    m_warning->hide();

    m_rx = new QLabel(QStringLiteral("↓ 0 B/s"), this);
    m_rx->setObjectName(QStringLiteral("rxLabel"));
    m_tx = new QLabel(QStringLiteral("↑ 0 B/s"), this);
    m_tx->setObjectName(QStringLiteral("txLabel"));
    m_cpu = new QLabel(QStringLiteral("CPU —"), this);
    m_cpu->setObjectName(QStringLiteral("cpuLabel"));
    m_ram = new QLabel(QStringLiteral("RAM —"), this);
    m_ram->setObjectName(QStringLiteral("ramLabel"));

    m_updated = new QLabel(this);
    m_updated->setProperty("uiRole", QStringLiteral("muted"));
    m_localFirst = new QLabel(QStringLiteral("Local-first"), this);
    m_localFirst->setProperty("uiRole", QStringLiteral("muted"));

    layout->addWidget(m_message);
    layout->addStretch(1);
    layout->addWidget(m_warning);
    layout->addStretch(1);
    layout->addWidget(m_rx);
    layout->addWidget(m_tx);
    layout->addWidget(m_cpu);
    layout->addWidget(m_ram);
    layout->addWidget(m_updated);
    layout->addWidget(m_localFirst);

    setMonitoringState(false);
}

void SystemStatusBar::setMonitoringState(bool active, const QString &adapter)
{
    m_active = active;
    if (!adapter.isEmpty())
        m_adapter = adapter;

    QString text = active ? QStringLiteral("Monitoring: Active")
                          : QStringLiteral("Monitoring: Stopped");
    if (active && !m_adapter.isEmpty())
        text += QStringLiteral(" · Adapter: %1").arg(m_adapter);
    m_message->setText(text);
    m_message->setToolTip(active
        ? QStringLiteral("Packet capture is running. Click for the last notification.")
        : QStringLiteral("Packet capture is stopped. Click for diagnostics."));
}

void SystemStatusBar::setMessage(const QString &text, const QString &tooltip)
{
    if (text.isEmpty())
        return;
    m_message->setText(text);
    m_message->setToolTip(tooltip);
}

void SystemStatusBar::setWarning(const QString &text, bool critical)
{
    if (text.isEmpty()) {
        m_warning->clear();
        m_warning->hide();
        return;
    }
    m_warning->setText(text);
    m_warning->setProperty("severity",
                           critical ? QStringLiteral("failed") : QStringLiteral("warning"));
    m_warning->setToolTip(text + QStringLiteral("\nClick to open diagnostics."));
    m_warning->style()->unpolish(m_warning);
    m_warning->style()->polish(m_warning);
    m_warning->show();
}

void SystemStatusBar::setSpeedText(const QString &rx, const QString &tx)
{
    m_rx->setText(QStringLiteral("↓ ") + rx);
    m_tx->setText(QStringLiteral("↑ ") + tx);
}

void SystemStatusBar::setHardware(int cpuPercent, int ramPercent)
{
    m_cpu->setText(QStringLiteral("CPU %1%").arg(cpuPercent));
    m_ram->setText(QStringLiteral("RAM %1%").arg(ramPercent));
}

void SystemStatusBar::setLastUpdated(const QDateTime &when)
{
    m_updated->setText(QStringLiteral("Updated %1").arg(when.toString(QStringLiteral("HH:mm:ss"))));
}

bool SystemStatusBar::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonRelease) {
        const auto *mouse = static_cast<QMouseEvent *>(event);
        if (mouse->button() == Qt::LeftButton) {
            if (watched == m_message) {
                emit messageActivated();
                return true;
            }
            if (watched == m_warning) {
                emit warningActivated();
                return true;
            }
        }
    }
    return QFrame::eventFilter(watched, event);
}
