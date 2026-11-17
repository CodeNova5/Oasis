/**
 * @file    connectionstable.cpp
 * @author  Oasis
 */
#include "connectionstable.h"

#include "connectionicons.h"
#include "ui/theme/colors.h"
#include "ui/theme/thememanager.h"
#include "ui/theme/typography.h"

#include <QDateTime>
#include <QFontMetrics>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QScrollArea>
#include <QScrollBar>

#include <algorithm>

using ConnectionsUi::Glyph;

namespace {

constexpr int kPad = 16;
constexpr int kGap = 4;
constexpr int kHeaderHeight = 38;
constexpr int kGroupHeight = 48;
constexpr int kEndpointHeight = 40;
constexpr int kInspectWidth = 36;

enum Column {
    ColExpand = 0,
    ColApp,
    ColDestination,
    ColDirection,
    ColPort,
    ColPolicy,
    ColTraffic,
    ColActions,
    ColCount
};

Theme::Palette themePalette()
{
    return Theme::palette(ThemeManager::instance().isDark());
}

QColor color(const QString &value)
{
    return Theme::qcolor(value);
}

QColor alpha(const QColor &base, qreal factor)
{
    QColor result = base;
    result.setAlphaF(factor);
    return result;
}

QFont uiFont(int pixelSize, QFont::Weight weight)
{
    QFont font = Theme::Type::baseFont();
    font.setPixelSize(pixelSize);
    font.setWeight(weight);
    return font;
}

QFont tabular(QFont font)
{
    font.setFeature(QFont::Tag("tnum"), 1);
    return font;
}

QString applicationLabel(const Connections::Row &row)
{
    return row.displayName.trimmed().isEmpty() ? row.appName : row.displayName;
}

QString initialsFor(const QString &label)
{
    QString base = label;
    const int dot = base.lastIndexOf(QLatin1Char('.'));
    if (dot > 0)
        base.truncate(dot);

    QString initials;
    for (const QString &part : base.split(QRegularExpression(QStringLiteral("[^A-Za-z0-9]+")),
                                          Qt::SkipEmptyParts)) {
        initials.append(part.at(0).toUpper());
        if (initials.size() == 2)
            break;
    }
    return initials.isEmpty() ? QStringLiteral("?") : initials;
}

QString formatAge(qint64 ageMs)
{
    if (ageMs < 60LL * 1000)
        return QStringLiteral("just now");
    const qint64 minutes = ageMs / (60LL * 1000);
    if (minutes < 60)
        return QStringLiteral("%1 min ago").arg(minutes);
    return QStringLiteral("%1 h ago").arg(minutes / 60);
}

QString protoLabel(quint16 port, const QString &protocol)
{
    switch (port) {
    case 80:   return QStringLiteral("HTTP");
    case 443:  return QStringLiteral("HTTPS");
    case 53:   return QStringLiteral("DNS");
    case 22:   return QStringLiteral("SSH");
    case 25:
    case 587:  return QStringLiteral("SMTP");
    case 993:  return QStringLiteral("IMAPS");
    case 995:  return QStringLiteral("POP3S");
    case 123:  return QStringLiteral("NTP");
    case 445:  return QStringLiteral("SMB");
    case 3389: return QStringLiteral("RDP");
    case 8080: return QStringLiteral("HTTP");
    case 8443: return QStringLiteral("HTTPS");
    default:
        break;
    }
    return protocol.isEmpty() ? QStringLiteral("TCP") : protocol.toUpper();
}

quint16 rowPort(const Connections::Row &row)
{
    quint16 port = 0;
    for (const Connections::Endpoint &endpoint : row.endpoints) {
        if (port == 0 || endpoint.port < port)
            port = endpoint.port;
    }
    return port;
}

QString rowProto(const Connections::Row &row)
{
    quint16 port = 0;
    QString protocol;
    for (const Connections::Endpoint &endpoint : row.endpoints) {
        if (port == 0 || endpoint.port < port) {
            port = endpoint.port;
            protocol = endpoint.protocol;
        }
    }
    return protoLabel(port, protocol);
}

struct Columns
{
    int widths[ColCount] = {};
    int left = kPad;

    QRect cell(int column, int y, int height) const
    {
        int x = left;
        for (int i = 0; i < column; ++i)
            x += widths[i] + kGap;
        return QRect(x, y, widths[column], height);
    }
};

Columns columnsFor(int width)
{
    Columns columns;
    const int fixed = 32 + 220 + 110 + 90 + 100 + 110 + kInspectWidth;
    int app = width - kPad * 2 - fixed - kGap * (ColCount - 1);
    app = qMax(160, app);
    columns.widths[ColExpand] = 32;
    columns.widths[ColApp] = app;
    columns.widths[ColDestination] = 220;
    columns.widths[ColDirection] = 110;
    columns.widths[ColPort] = 90;
    columns.widths[ColPolicy] = 100;
    columns.widths[ColTraffic] = 110;
    columns.widths[ColActions] = kInspectWidth;
    return columns;
}

void drawElided(QPainter *painter, const QRect &rect, const QString &text,
                const QFont &font, const QColor &pen,
                Qt::Alignment alignment = Qt::AlignLeft | Qt::AlignVCenter)
{
    painter->save();
    painter->setFont(font);
    painter->setPen(pen);
    const QFontMetrics metrics(font);
    painter->drawText(rect, int(alignment),
                      metrics.elidedText(text, Qt::ElideRight, rect.width()));
    painter->restore();
}

void paintAppIcon(QPainter *painter, const QRectF &box, const QIcon &icon,
                  const QString &label, bool endpoint, const Theme::Palette &pal)
{
    const qreal radius = endpoint ? 4.0 : 7.0;
    painter->save();
    painter->setPen(QPen(color(pal.borderDefault), 1));
    painter->setBrush(color(pal.surfaceElevated));
    painter->drawRoundedRect(box.adjusted(0.5, 0.5, -0.5, -0.5), radius, radius);

    const QPixmap pixmap = icon.pixmap(box.size().toSize());
    if (!pixmap.isNull()) {
        const QPixmap scaled = pixmap.scaled(box.size().toSize(), Qt::KeepAspectRatio,
                                             Qt::SmoothTransformation);
        painter->drawPixmap(QPointF(box.center().x() - scaled.width() / 2.0,
                                    box.center().y() - scaled.height() / 2.0),
                            scaled);
    } else {
        painter->setFont(uiFont(endpoint ? 9 : 11, QFont::DemiBold));
        painter->setPen(color(pal.textSecondary));
        painter->drawText(box, Qt::AlignCenter, initialsFor(label));
    }
    painter->restore();
}

struct DirectionChip
{
    QString text;
    Glyph glyph = Glyph::ArrowOut;
    QColor foreground;
    QColor background;
};

DirectionChip directionChip(const QString &direction, const Theme::Palette &pal)
{
    if (direction == QLatin1String("Inbound"))
        return {QStringLiteral("In"), Glyph::ArrowIn, color(pal.semanticInfo),
                alpha(color(pal.semanticInfo), 0.10)};
    if (direction == QLatin1String("Both"))
        return {QStringLiteral("Both"), Glyph::ArrowBoth, color(pal.semanticWarning),
                alpha(color(pal.semanticWarning), 0.10)};
    return {QStringLiteral("Out"), Glyph::ArrowOut, color(pal.accentPrimary),
            alpha(color(pal.accentPrimary), 0.10)};
}

int paintDirection(QPainter *painter, int x, int centerY, const QString &direction,
                   const QString &proto, const Theme::Palette &pal)
{
    const DirectionChip chip = directionChip(direction, pal);
    const QFont font = uiFont(10, QFont::DemiBold);
    const QFontMetrics metrics(font);
    const int chipWidth = 6 + 10 + 3 + metrics.horizontalAdvance(chip.text) + 6;
    const QRect chipRect(x, centerY - 9, chipWidth, 18);

    painter->save();
    painter->setPen(Qt::NoPen);
    painter->setBrush(chip.background);
    painter->drawRoundedRect(chipRect, 4, 4);
    ConnectionsUi::drawGlyph(painter, chip.glyph,
                             QRectF(chipRect.left() + 6, centerY - 5, 10, 10),
                             chip.foreground, 1.6);
    painter->setFont(font);
    painter->setPen(chip.foreground);
    painter->drawText(QRect(chipRect.left() + 19, chipRect.top(), chipRect.width() - 22,
                            chipRect.height()),
                      Qt::AlignLeft | Qt::AlignVCenter, chip.text);
    painter->restore();

    const QFont protoFont = uiFont(10, QFont::DemiBold);
    const QFontMetrics protoMetrics(protoFont);
    const int protoWidth = protoMetrics.horizontalAdvance(proto) + 10;
    const QRect protoRect(chipRect.right() + 6, centerY - 8, protoWidth, 16);
    painter->save();
    painter->setPen(QPen(color(pal.borderDefault), 1));
    painter->setBrush(color(pal.surfaceElevated));
    painter->drawRoundedRect(protoRect, 3, 3);
    painter->setFont(protoFont);
    painter->setPen(color(pal.textMuted));
    painter->drawText(protoRect, Qt::AlignCenter, proto);
    painter->restore();

    return protoRect.right();
}

struct PolicyBadge
{
    QString text;
    QColor foreground;
    QColor background;
};

PolicyBadge policyBadge(const Connections::Row &row, const Theme::Palette &pal)
{
    if (row.policyToken == QLatin1String("blocked"))
        return {QStringLiteral("Blocked"), color(pal.semanticDanger),
                alpha(color(pal.semanticDanger), 0.12)};
    if (row.policyToken == QLatin1String("restricted"))
        return {QStringLiteral("Throttled"), color(pal.semanticSuccess),
                alpha(color(pal.semanticSuccess), 0.12)};
    return {QStringLiteral("No policy"), color(pal.textMuted),
            color(pal.surfaceElevated)};
}

void paintPolicy(QPainter *painter, int x, int centerY, const Connections::Row &row,
                 const Theme::Palette &pal)
{
    const PolicyBadge badge = policyBadge(row, pal);
    const QFont font = uiFont(11, QFont::DemiBold);
    const QFontMetrics metrics(font);
    const bool hasDot = row.policyToken != QLatin1String("none");
    const int width = metrics.horizontalAdvance(badge.text) + (hasDot ? 18 : 16);
    const QRect box(x, centerY - 11, width, 22);

    painter->save();
    painter->setPen(Qt::NoPen);
    painter->setBrush(badge.background);
    painter->drawRoundedRect(box, 6, 6);
    if (hasDot) {
        painter->setBrush(badge.foreground);
        painter->drawEllipse(QPointF(box.left() + 10.5, centerY), 2.5, 2.5);
    }
    painter->setFont(font);
    painter->setPen(badge.foreground);
    painter->drawText(QRect(box.left() + (hasDot ? 18 : 8), box.top(),
                            box.width() - (hasDot ? 22 : 10), box.height()),
                      Qt::AlignLeft | Qt::AlignVCenter, badge.text);
    painter->restore();
}

void paintTraffic(QPainter *painter, const QRect &cell, quint64 rx, quint64 tx,
                  const Theme::Palette &pal)
{
    const QFont font = tabular(uiFont(11, QFont::Medium));
    painter->save();
    painter->setFont(font);
    painter->setPen(color(pal.semanticSuccess));
    painter->drawText(QRect(cell.left(), cell.center().y() - 15, cell.width(), 15),
                      Qt::AlignRight | Qt::AlignVCenter,
                      QStringLiteral("↓ ") + Connections::formatBytes(rx));
    painter->setPen(color(pal.accentPrimary));
    painter->drawText(QRect(cell.left(), cell.center().y(), cell.width(), 15),
                      Qt::AlignRight | Qt::AlignVCenter,
                      QStringLiteral("↑ ") + Connections::formatBytes(tx));
    painter->restore();
}

} // namespace

// ============================================================================
// Header
// ============================================================================

class ConnectionsTableHeader : public QWidget
{
public:
    explicit ConnectionsTableHeader(ConnectionsTable *table)
        : QWidget(table)
        , m_table(table)
    {
        setFixedHeight(kHeaderHeight);
        setCursor(Qt::PointingHandCursor);
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        const Theme::Palette pal = themePalette();
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);

        QPainterPath top;
        top.addRoundedRect(QRectF(rect()), 9, 9);
        painter.setClipPath(top);
        painter.fillRect(rect(), color(pal.surfaceElevated));
        painter.setClipping(false);
        painter.fillRect(QRect(0, height() - 9, width(), 9), color(pal.surfaceElevated));

        QColor border = color(pal.borderDefault);
        border.setAlphaF(1.0);
        painter.setPen(QPen(border, 1));
        painter.drawLine(0, height() - 1, width(), height() - 1);

        // The content viewport loses the scrollbar width; use it so the header
        // columns line up with the row cells below.
        const int contentWidth = m_table->m_scroll
                                     ? m_table->m_scroll->viewport()->width()
                                     : width();
        const Columns columns = columnsFor(contentWidth);
        const QFont font = uiFont(11, QFont::DemiBold);
        const struct {
            int column;
            const char *label;
            ConnectionsTable::SortKey key;
            bool sortable;
        } items[] = {
            {ColApp, "Application / Process", ConnectionsTable::SortKey::Application, true},
            {ColDestination, "Destination", ConnectionsTable::SortKey::Destination, true},
            {ColDirection, "Direction · Proto", ConnectionsTable::SortKey::Application, false},
            {ColPort, "Port", ConnectionsTable::SortKey::Port, true},
            {ColPolicy, "Policy", ConnectionsTable::SortKey::Policy, true},
            {ColTraffic, "Traffic", ConnectionsTable::SortKey::Traffic, true},
        };

        for (const auto &item : items) {
            const QRect cell = columns.cell(item.column, 0, height());
            const bool sorted = item.sortable && m_table->m_sortKey == item.key;
            const QColor pen = sorted ? color(pal.textPrimary) : color(pal.textSecondary);
            const int arrowRoom = sorted ? 16 : 0;
            drawElided(&painter, cell.adjusted(0, 0, -arrowRoom, 0),
                       QString::fromLatin1(item.label), font, pen);
            if (sorted) {
                painter.save();
                painter.translate(cell.right() - 12, cell.center().y());
                if (m_table->m_sortOrder == Qt::AscendingOrder)
                    painter.rotate(180);
                ConnectionsUi::drawGlyph(&painter, Glyph::ChevronDown,
                                         QRectF(-6, -6, 12, 12), pen, 2.0);
                painter.restore();
            }
        }
    }

    void mouseReleaseEvent(QMouseEvent *event) override
    {
        if (event->button() != Qt::LeftButton)
            return;
        const int contentWidth = m_table->m_scroll
                                     ? m_table->m_scroll->viewport()->width()
                                     : width();
        const Columns columns = columnsFor(contentWidth);
        const QPointF position = event->position();
        auto hit = [&](int column) {
            const QRect cell = columns.cell(column, 0, height());
            return position.x() >= cell.left() && position.x() <= cell.right();
        };

        if (hit(ColApp))
            m_table->setSortKey(ConnectionsTable::SortKey::Application);
        else if (hit(ColDestination))
            m_table->setSortKey(ConnectionsTable::SortKey::Destination);
        else if (hit(ColPort))
            m_table->setSortKey(ConnectionsTable::SortKey::Port);
        else if (hit(ColPolicy))
            m_table->setSortKey(ConnectionsTable::SortKey::Policy);
        else if (hit(ColTraffic))
            m_table->setSortKey(ConnectionsTable::SortKey::Traffic);
        else
            return;
        update();
    }

private:
    ConnectionsTable *m_table = nullptr;
};

// ============================================================================
// Body
// ============================================================================

class ConnectionsTableBody : public QWidget
{
public:
    explicit ConnectionsTableBody(ConnectionsTable *table)
        : QWidget(table)
        , m_table(table)
    {
        setMouseTracking(true);
        setAttribute(Qt::WA_TranslucentBackground);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

    void clearHover()
    {
        if (m_hover < 0)
            return;
        m_hover = -1;
        unsetCursor();
        update();
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        const Theme::Palette pal = themePalette();
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        const Columns columns = columnsFor(width());
        const QList<ConnectionsTable::FlatRow> rows = m_table->buildFlatRows();

        for (int index = 0; index < rows.size(); ++index) {
            const ConnectionsTable::FlatRow &flat = rows.at(index);
            if (flat.row < 0 || flat.row >= m_table->m_rows.size())
                continue;
            const QRect rowRect(0, flat.y, width(), flat.height);
            const bool hovered = index == m_hover;
            const bool selected = m_table->m_selectedId == m_table->m_rows.at(flat.row).id;

            if (flat.endpoint < 0)
                paintGroupRow(&painter, rowRect, columns, m_table->m_rows.at(flat.row),
                              hovered, selected, pal);
            else
                paintEndpointRow(&painter, rowRect, columns, m_table->m_rows.at(flat.row),
                                 flat.endpoint, hovered, selected, pal);
        }
    }

    void mouseMoveEvent(QMouseEvent *event) override
    {
        const int hovered = flatAt(int(event->position().y()));
        if (hovered != m_hover) {
            m_hover = hovered;
            update();
        }

        const QList<ConnectionsTable::FlatRow> rows = m_table->buildFlatRows();
        if (hovered < 0 || hovered >= rows.size()) {
            unsetCursor();
            return;
        }
        const Columns columns = columnsFor(width());
        const ConnectionsTable::FlatRow &flat = rows.at(hovered);
        const int x = int(event->position().x());
        const bool overExpand = columns.cell(ColExpand, flat.y, flat.height).contains(x, flat.y);
        const bool overActions = columns.cell(ColActions, flat.y, flat.height).contains(x, flat.y);
        setCursor(overExpand || overActions ? Qt::PointingHandCursor : Qt::ArrowCursor);
    }

    void leaveEvent(QEvent *) override { clearHover(); }

    void mousePressEvent(QMouseEvent *event) override
    {
        if (event->button() != Qt::LeftButton)
            return;
        const QList<ConnectionsTable::FlatRow> rows = m_table->buildFlatRows();
        const int index = flatAt(int(event->position().y()));
        if (index < 0 || index >= rows.size())
            return;
        const ConnectionsTable::FlatRow &flat = rows.at(index);
        if (flat.row < 0 || flat.row >= m_table->m_rows.size())
            return;

        const Connections::Row &row = m_table->m_rows.at(flat.row);
        const Columns columns = columnsFor(width());
        const int x = int(event->position().x());
        const bool overActions = columns.cell(ColActions, flat.y, flat.height).contains(x, flat.y);

        if (overActions || flat.endpoint >= 0) {
            m_table->selectId(row.id);
            emit m_table->inspectRequested(row.id);
            return;
        }

        if (flat.endpoint < 0
            && columns.cell(ColExpand, flat.y, flat.height).contains(x, flat.y)) {
            m_table->toggleExpanded(row.id);
            return;
        }

        if (flat.endpoint < 0) {
            m_table->selectId(row.id);
            m_table->toggleExpanded(row.id);
            return;
        }
    }

    void mouseDoubleClickEvent(QMouseEvent *event) override
    {
        const QList<ConnectionsTable::FlatRow> rows = m_table->buildFlatRows();
        const int index = flatAt(int(event->position().y()));
        if (index < 0 || index >= rows.size())
            return;
        const ConnectionsTable::FlatRow &flat = rows.at(index);
        if (flat.row < 0 || flat.row >= m_table->m_rows.size())
            return;
        const Connections::Row &row = m_table->m_rows.at(flat.row);
        m_table->selectId(row.id);
        emit m_table->inspectRequested(row.id);
    }

private:
    int flatAt(int y) const
    {
        const QList<ConnectionsTable::FlatRow> rows = m_table->buildFlatRows();
        for (int index = 0; index < rows.size(); ++index) {
            const ConnectionsTable::FlatRow &flat = rows.at(index);
            if (y >= flat.y && y < flat.y + flat.height)
                return index;
        }
        return -1;
    }

    void paintGroupRow(QPainter *painter, const QRect &rect, const Columns &columns,
                       const Connections::Row &row, bool hovered, bool selected,
                       const Theme::Palette &pal)
    {
        QColor background = Qt::transparent;
        if (selected)
            background = color(pal.surfaceSelected);
        else if (m_table->isExpanded(row.id))
            background = alpha(color(pal.accentPrimary), 0.04);
        if (hovered && !selected)
            background = color(pal.surfaceHover);
        if (background.alpha() > 0)
            painter->fillRect(rect, background);

        QColor divider = color(pal.borderDefault);
        divider.setAlphaF(0.5);
        painter->setPen(QPen(divider, 1));
        painter->drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom());

        if (selected) {
            painter->fillRect(QRect(rect.left(), rect.top(), 2, rect.height()),
                              color(pal.accentPrimary));
        }

        const bool expanded = m_table->isExpanded(row.id);
        const bool closed = m_table->m_closedAt.contains(row.id);
        paintAppCell(painter, rect, columns, row, expanded, closed, pal);
        paintDestinationCell(painter, rect, columns, row.destination, row.addresses,
                             row.hasDomain, row.confidenceRank, pal);
        paintDirection(painter, columns.cell(ColDirection, rect.y(), rect.height()).left(),
                       rect.center().y(), row.direction, rowProto(row), pal);

        const QRect portCell = columns.cell(ColPort, rect.y(), rect.height());
        const bool blocked = row.policyToken == QLatin1String("blocked");
        drawElided(painter, portCell, QString::number(rowPort(row)),
                   tabular(uiFont(12, QFont::Medium)),
                   color(blocked ? pal.semanticDanger : pal.textPrimary));

        paintPolicy(painter, columns.cell(ColPolicy, rect.y(), rect.height()).left(),
                    rect.center().y(), row, pal);
        paintTraffic(painter, columns.cell(ColTraffic, rect.y(), rect.height()),
                     row.rxBytes, row.txBytes, pal);

        const QRect actions = columns.cell(ColActions, rect.y(), rect.height());
        if (hovered || selected)
            paintInspectAction(painter, actions, pal);
    }

    void paintEndpointRow(QPainter *painter, const QRect &rect, const Columns &columns,
                          const Connections::Row &row, int endpointIndex, bool hovered,
                          bool selected, const Theme::Palette &pal)
    {
        if (endpointIndex < 0 || endpointIndex >= row.endpoints.size())
            return;
        const Connections::Endpoint &endpoint = row.endpoints.at(endpointIndex);

        QColor tint = ThemeManager::instance().isDark() ? QColor(17, 19, 24, 110)
                                                        : QColor(0, 0, 0, 8);
        painter->fillRect(rect, tint);
        if (hovered && !selected)
            painter->fillRect(rect, color(pal.surfaceHover));

        QColor divider = color(pal.borderDefault);
        divider.setAlphaF(0.3);
        painter->setPen(QPen(divider, 1));
        painter->drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom());

        const QRect expand = columns.cell(ColExpand, rect.y(), rect.height());
        ConnectionsUi::drawGlyph(painter, Glyph::Branch,
                                 QRectF(expand.center().x() - 6, rect.center().y() - 6, 12, 12),
                                 color(pal.borderDefault), 1.5);

        const QRect app = columns.cell(ColApp, rect.y(), rect.height());
        paintAppIcon(painter, QRectF(app.left(), rect.center().y() - 10, 20, 20),
                     QIcon(), applicationLabel(row), true, pal);

        const QRect textRect(app.left() + 30, rect.top(), app.width() - 30, rect.height());
        drawElided(painter, QRect(textRect.left(), rect.center().y() - 14,
                                  textRect.width(), 15),
                   QStringLiteral("%1:%2").arg(endpoint.address).arg(endpoint.port),
                   tabular(uiFont(12, QFont::Normal)), color(pal.textSecondary));
        drawElided(painter, QRect(textRect.left(), rect.center().y() + 1,
                                  textRect.width(), 14),
                   QStringLiteral("%1 · %2")
                       .arg(Connections::sourceLabel(endpoint.source),
                            Connections::confidenceLabel(endpoint.confidence)),
                   uiFont(11, QFont::Normal), color(pal.textMuted));

        const QString name = endpoint.domainNames.isEmpty()
                                 ? (endpoint.domain.isEmpty() ? QString() : endpoint.domain)
                                 : endpoint.domainNames.first();
        paintDestinationCell(painter, rect, columns,
                             name.isEmpty() ? QStringLiteral("IP only") : name,
                             QStringList{endpoint.address}, !name.isEmpty(),
                             Connections::confidenceRank(endpoint.confidence), pal);

        paintDirection(painter, columns.cell(ColDirection, rect.y(), rect.height()).left(),
                       rect.center().y(),
                       Connections::directionFor(endpoint.rxBytes, endpoint.txBytes),
                       protoLabel(endpoint.port, endpoint.protocol), pal);

        const QRect portCell = columns.cell(ColPort, rect.y(), rect.height());
        drawElided(painter, portCell, QString::number(endpoint.port),
                   tabular(uiFont(12, QFont::Medium)), color(pal.textPrimary));

        paintPolicy(painter, columns.cell(ColPolicy, rect.y(), rect.height()).left(),
                    rect.center().y(), row, pal);
        paintTraffic(painter, columns.cell(ColTraffic, rect.y(), rect.height()),
                     endpoint.rxBytes, endpoint.txBytes, pal);

        if (hovered)
            paintInspectAction(painter, columns.cell(ColActions, rect.y(), rect.height()), pal);
    }

    void paintAppCell(QPainter *painter, const QRect &rect, const Columns &columns,
                      const Connections::Row &row, bool expanded, bool closed,
                      const Theme::Palette &pal)
    {
        const QRect expand = columns.cell(ColExpand, rect.y(), rect.height());
        painter->save();
        painter->translate(expand.center().x(), rect.center().y());
        if (expanded)
            painter->rotate(90);
        ConnectionsUi::drawGlyph(painter, Glyph::ChevronRight,
                                 QRectF(-6.5, -6.5, 13, 13),
                                 color(pal.textMuted), 2.0);
        painter->restore();

        const QRect app = columns.cell(ColApp, rect.y(), rect.height());
        paintAppIcon(painter, QRectF(app.left(), rect.center().y() - 14, 28, 28),
                     row.icon, applicationLabel(row), false, pal);

        const int textLeft = app.left() + 38;
        const int textWidth = qMax(0, app.width() - 38);
        const bool danger = row.policyToken == QLatin1String("blocked");
        drawElided(painter, QRect(textLeft, rect.top() + 7, textWidth, 18),
                   applicationLabel(row), uiFont(13, QFont::Medium),
                   color(closed ? pal.textSecondary
                                : (danger ? pal.semanticDanger : pal.textPrimary)));

        QString detail = QStringLiteral("%1 — %2 endpoint%3")
                             .arg(row.appName.isEmpty() ? QStringLiteral("Unknown process")
                                                        : row.appName)
                             .arg(row.endpointCount)
                             .arg(row.endpointCount == 1 ? QString() : QStringLiteral("s"));
        if (closed) {
            const qint64 age = QDateTime::currentMSecsSinceEpoch()
                               - m_table->m_closedAt.value(row.id);
            detail = QStringLiteral("Closed %1 · %2").arg(formatAge(age), detail);
        }
        drawElided(painter, QRect(textLeft, rect.top() + 25, textWidth, 15), detail,
                   uiFont(11, QFont::Normal), color(pal.textMuted));
    }

    void paintDestinationCell(QPainter *painter, const QRect &rect,
                              const Columns &columns, const QString &name,
                              const QStringList &addresses, bool hasDomain,
                              int confidenceRank, const Theme::Palette &pal)
    {
        const QRect cell = columns.cell(ColDestination, rect.y(), rect.height());
        QColor dot;
        switch (confidenceRank) {
        case 3: dot = color(pal.semanticSuccess); break;
        case 2: dot = color(pal.semanticInfo); break;
        case 1: dot = color(pal.semanticWarning); break;
        default: dot = color(pal.textMuted); break;
        }
        painter->save();
        painter->setPen(Qt::NoPen);
        painter->setBrush(dot);
        painter->drawEllipse(QPointF(cell.left() + 3.5, rect.top() + 16), 3.5, 3.5);
        painter->restore();

        const int textLeft = cell.left() + 12;
        const int textWidth = qMax(0, cell.width() - 12);
        if (hasDomain) {
            drawElided(painter, QRect(textLeft, rect.top() + 7, textWidth, 18), name,
                       uiFont(13, QFont::Medium), color(pal.textPrimary));
        } else {
            QFont font = uiFont(13, QFont::Normal);
            font.setItalic(true);
            drawElided(painter, QRect(textLeft, rect.top() + 7, textWidth, 18),
                       QStringLiteral("No domain"), font, color(pal.textMuted));
        }

        QString secondary = addresses.mid(0, 2).join(QStringLiteral(" · "));
        if (addresses.size() > 2)
            secondary += QStringLiteral(" +%1").arg(addresses.size() - 2);
        if (secondary.isEmpty())
            secondary = QStringLiteral("—");
        drawElided(painter, QRect(textLeft, rect.top() + 25, textWidth, 15), secondary,
                   tabular(uiFont(11, QFont::Normal)), color(pal.textMuted));
    }

    void paintInspectAction(QPainter *painter, const QRect &cell,
                            const Theme::Palette &pal)
    {
        const QRect button(cell.right() - 28, cell.center().y() - 14, 28, 28);
        painter->save();
        painter->setPen(Qt::NoPen);
        painter->setBrush(alpha(color(pal.accentPrimary), 0.10));
        painter->drawRoundedRect(button, 5, 5);
        ConnectionsUi::drawGlyph(painter, Glyph::Search,
                                 QRectF(button.center().x() - 7, button.center().y() - 7, 14, 14),
                                 color(pal.textPrimary), 1.75);
        painter->restore();
    }

private:
    ConnectionsTable *m_table = nullptr;
    int m_hover = -1;
};

// ============================================================================
// Table
// ============================================================================

ConnectionsTable::ConnectionsTable(QWidget *parent)
    : QWidget(parent)
{
    setMouseTracking(true);

    m_header = new ConnectionsTableHeader(this);

    m_scroll = new QScrollArea(this);
    m_scroll->setWidgetResizable(true);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_scroll->viewport()->setAutoFillBackground(false);
    m_scroll->setStyleSheet(QStringLiteral("QScrollArea { background: transparent; border: none; }"));

    auto *body = new ConnectionsTableBody(this);
    m_body = body;
    m_scroll->setWidget(m_body);

    connect(m_scroll->verticalScrollBar(), &QScrollBar::valueChanged, this,
            [this]() {
                if (auto *tableBody = static_cast<ConnectionsTableBody *>(m_body))
                    tableBody->clearHover();
            });
}

void ConnectionsTable::setRows(const QList<Connections::Row> &rows)
{
    m_rows = rows;

    QSet<QString> present;
    for (const Connections::Row &row : m_rows)
        present.insert(row.id);
    for (auto it = m_expanded.begin(); it != m_expanded.end();) {
        if (!present.contains(*it))
            it = m_expanded.erase(it);
        else
            ++it;
    }

    applySort();

    if (!m_autoExpanded && !m_rows.isEmpty()) {
        m_expanded.insert(m_rows.first().id);
        m_autoExpanded = true;
    }

    if (!m_selectedId.isEmpty() && !present.contains(m_selectedId)) {
        m_selectedId.clear();
        emit selectionChanged(QString());
    }

    rebuildBody();
    m_header->update();
}

void ConnectionsTable::setClosedAt(const QHash<QString, qint64> &closedAt)
{
    m_closedAt = closedAt;
    if (m_body)
        m_body->update();
}

void ConnectionsTable::refreshClosedTimestamps()
{
    if (m_body && !m_closedAt.isEmpty())
        m_body->update();
}

void ConnectionsTable::setSortKey(SortKey key)
{
    if (m_sortKey == key) {
        m_sortOrder = m_sortOrder == Qt::AscendingOrder ? Qt::DescendingOrder
                                                        : Qt::AscendingOrder;
    } else {
        m_sortKey = key;
        m_sortOrder = key == SortKey::Traffic ? Qt::DescendingOrder : Qt::AscendingOrder;
    }
    applySort();
    rebuildBody();
    m_header->update();
}

void ConnectionsTable::applySort()
{
    std::stable_sort(m_rows.begin(), m_rows.end(),
                     [this](const Connections::Row &a, const Connections::Row &b) {
        int compare = 0;
        switch (m_sortKey) {
        case SortKey::Application:
            compare = QString::compare(applicationLabel(a), applicationLabel(b),
                                       Qt::CaseInsensitive);
            break;
        case SortKey::Destination:
            compare = QString::compare(a.destination, b.destination, Qt::CaseInsensitive);
            break;
        case SortKey::Port: {
            const quint16 left = rowPort(a);
            const quint16 right = rowPort(b);
            compare = left < right ? -1 : (left > right ? 1 : 0);
            break;
        }
        case SortKey::Policy:
            compare = QString::compare(a.policy, b.policy, Qt::CaseInsensitive);
            break;
        case SortKey::Traffic: {
            const quint64 left = a.totalBytes();
            const quint64 right = b.totalBytes();
            compare = left < right ? -1 : (left > right ? 1 : 0);
            break;
        }
        }
        return m_sortOrder == Qt::AscendingOrder ? compare < 0 : compare > 0;
    });
}

QList<ConnectionsTable::FlatRow> ConnectionsTable::buildFlatRows() const
{
    QList<FlatRow> rows;
    int y = 0;
    for (int index = 0; index < m_rows.size(); ++index) {
        const Connections::Row &row = m_rows.at(index);
        rows.append({index, -1, y, kGroupHeight});
        y += kGroupHeight;
        if (!m_expanded.contains(row.id))
            continue;
        for (int endpoint = 0; endpoint < row.endpoints.size(); ++endpoint) {
            rows.append({index, endpoint, y, kEndpointHeight});
            y += kEndpointHeight;
        }
    }
    return rows;
}

void ConnectionsTable::rebuildBody()
{
    const QList<FlatRow> rows = buildFlatRows();
    const int contentHeight = rows.isEmpty() ? 0 : rows.last().y + rows.last().height;
    m_body->setFixedHeight(contentHeight);
    m_body->update();
}

void ConnectionsTable::toggleExpanded(const QString &id)
{
    if (id.isEmpty())
        return;
    if (m_expanded.contains(id))
        m_expanded.remove(id);
    else
        m_expanded.insert(id);
    rebuildBody();
}

void ConnectionsTable::selectId(const QString &id)
{
    m_selectedId = id;
    emit selectionChanged(id);

    const QList<FlatRow> rows = buildFlatRows();
    for (const FlatRow &flat : rows) {
        if (flat.row < 0 || flat.row >= m_rows.size() || m_rows.at(flat.row).id != id)
            continue;
        if (flat.endpoint >= 0)
            continue;
        const int maximum = m_scroll->verticalScrollBar()->maximum();
        if (flat.y < m_scroll->verticalScrollBar()->value())
            m_scroll->verticalScrollBar()->setValue(flat.y);
        else if (flat.y + flat.height
                 > m_scroll->verticalScrollBar()->value() + m_scroll->viewport()->height())
            m_scroll->verticalScrollBar()->setValue(
                qMin(maximum, flat.y + flat.height - m_scroll->viewport()->height()));
        break;
    }
    m_body->update();
}

void ConnectionsTable::clearSelection()
{
    if (m_selectedId.isEmpty())
        return;
    m_selectedId.clear();
    emit selectionChanged(QString());
    m_body->update();
}

void ConnectionsTable::paintEvent(QPaintEvent *)
{
    const Theme::Palette pal = themePalette();
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(QPen(color(pal.borderDefault), 1));
    painter.setBrush(color(pal.surfacePrimary));
    painter.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 10, 10);
}

void ConnectionsTable::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    const int headerHeight = kHeaderHeight;
    m_header->setGeometry(1, 1, qMax(0, width() - 2), headerHeight);
    m_scroll->setGeometry(1, headerHeight + 1, qMax(0, width() - 2),
                          qMax(0, height() - headerHeight - 2));
}
