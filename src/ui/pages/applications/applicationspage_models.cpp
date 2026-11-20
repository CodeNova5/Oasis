/**
 * @file    applicationspage_models.cpp
 * @brief   Row model, filter proxy and cell delegates for the Applications
 *          page, split out of applicationspage.cpp. Definitions only; the
 *          page's public interface is unchanged.
 */
#include "applicationspage_p.h"

#include <QPair>
#include <QVariantList>

using namespace ApplicationsPageDetail;

// ============================================================================
// Table model
// ============================================================================

ApplicationsPageTableModel::ApplicationsPageTableModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

void ApplicationsPageTableModel::setRows(const QList<Applications::Row> &rows)
{
    // One sample per beat, keyed by pid, so the sparkline follows the
    // application rather than its (sortable) view row.
    QHash<quint32, QVector<quint64>> history;
    history.reserve(rows.size());
    for (const Applications::Row &row : rows) {
        QVector<quint64> samples = m_history.value(row.pid);
        samples.append(row.rxBytesPerSecond + row.txBytesPerSecond);
        while (samples.size() > kSparkPoints)
            samples.removeFirst();
        history.insert(row.pid, samples);
    }

    // Diff the beat instead of resetting the model. A reset drops the
    // current index, the hovered cell and keyboard focus, and forces the
    // view to re-lay out, so the user loses their place while only
    // watching the numbers move.
    QHash<QString, QList<int>> available;
    available.reserve(m_rows.size());
    for (int i = 0; i < m_rows.size(); ++i)
        available[rowIdentity(m_rows.at(i))].append(i);

    const int previousCount = int(m_rows.size());
    QVector<bool> kept(previousCount, false);
    QList<QPair<int, Applications::Row>> matched;
    QList<Applications::Row> added;
    for (const Applications::Row &row : rows) {
        QList<int> &candidates = available[rowIdentity(row)];
        if (candidates.isEmpty()) {
            added.append(row);
            continue;
        }
        const int index = candidates.takeFirst();
        kept[index] = true;
        matched.append(qMakePair(index, row));
    }

    for (int i = previousCount - 1; i >= 0; --i) {
        if (kept.at(i))
            continue;
        beginRemoveRows(QModelIndex(), i, i);
        m_rows.removeAt(i);
        endRemoveRows();
    }

    QVector<int> positions(previousCount, -1);
    int next = 0;
    for (int i = 0; i < previousCount; ++i) {
        if (kept.at(i))
            positions[i] = next++;
    }

    m_history = history;

    // Leave unchanged rows out of the change set: an idle beat should not
    // make the view repaint or the proxy re-sort every row.
    int firstChanged = -1;
    int lastChanged = -1;
    for (const QPair<int, Applications::Row> &entry : matched) {
        const int index = positions.at(entry.first);
        if (sameRow(m_rows.at(index), entry.second))
            continue;
        m_rows[index] = entry.second;
        if (firstChanged < 0)
            firstChanged = index;
        lastChanged = index;
    }
    if (firstChanged >= 0)
        emit dataChanged(this->index(firstChanged, 0),
                         this->index(lastChanged, ColumnCount - 1));

    if (!added.isEmpty()) {
        const int first = int(m_rows.size());
        beginInsertRows(QModelIndex(), first, first + int(added.size()) - 1);
        m_rows.append(added);
        endInsertRows();
    }
}

const Applications::Row &ApplicationsPageTableModel::rowAt(int sourceRow) const
{
    return m_rows.at(sourceRow);
}

int ApplicationsPageTableModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : int(m_rows.size());
}

int ApplicationsPageTableModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : int(ColumnCount);
}

QVariant ApplicationsPageTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_rows.size())
        return {};

    const Applications::Row &row = m_rows.at(index.row());
    const int column = index.column();

    switch (role) {
    case Qt::DisplayRole:
        switch (column) {
        case Application:
            return applicationLabel(row);
        case Total:
            return formattedBytes(row.totalBytes);
        case Rule:
            return ruleText(row);
        case Activity:
            return QStringLiteral("↓ %1   ↑ %2")
                .arg(formattedRate(row.rxBytesPerSecond),
                     formattedRate(row.txBytesPerSecond));
        default:
            break;
        }
        break;

    case Qt::ToolTipRole:
        if (column == Application)
            return row.path.trimmed().isEmpty() ? row.name : row.path;
        if (column == Total)
            return QStringLiteral("Total data consumed this session: %1")
                .arg(formattedBytes(row.totalBytes));
        if (column == Rule)
            return QStringLiteral("Network rule for %1: %2")
                .arg(applicationLabel(row), ruleText(row));
        if (column == Activity)
            return QStringLiteral("Download %1 · Upload %2")
                .arg(formattedRate(row.rxBytesPerSecond),
                     formattedRate(row.txBytesPerSecond));
        break;

    case Qt::TextAlignmentRole:
        return int(Qt::AlignLeft | Qt::AlignVCenter);

    case Qt::ForegroundRole: {
        const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
        return Theme::qcolor(palette.textPrimary);
    }

    case SortRole:
        switch (column) {
        case Application:
            return applicationLabel(row).toLower();
        case Total:
            return QVariant::fromValue<qulonglong>(row.totalBytes);
        case Rule:
            if (ruleToken(row) == QLatin1String("block")) return QStringLiteral("0");
            if (ruleToken(row) == QLatin1String("ask")) return QStringLiteral("1");
            return QStringLiteral("2");
        case Activity:
            return QVariant::fromValue<qulonglong>(
                row.rxBytesPerSecond + row.txBytesPerSecond);
        default:
            break;
        }
        break;

    case NameRole:
        return row.name;
    case PublisherRole:
        return row.publisher;
    case PidRole:
        return row.pid;
    case IconRole:
        return row.icon;
    case RxRateRole:
        return QVariant::fromValue<qulonglong>(row.rxBytesPerSecond);
    case TxRateRole:
        return QVariant::fromValue<qulonglong>(row.txBytesPerSecond);
    case SparkRole: {
        QVariantList samples;
        const QVector<quint64> history = m_history.value(row.pid);
        samples.reserve(history.size());
        for (quint64 value : history)
            samples.append(QVariant::fromValue<qulonglong>(value));
        return samples;
    }
    case RuleRole:
        return ruleToken(row);
    case TotalRole:
        return formattedBytes(row.totalBytes);
    default:
        break;
    }
    return {};
}

QVariant ApplicationsPageTableModel::headerData(int section, Qt::Orientation orientation,
                                               int role) const
{
    if (orientation != Qt::Horizontal)
        return {};

    if (role == Qt::DisplayRole) {
        switch (section) {
        case Application: return QStringLiteral("Application");
        case Total:       return QStringLiteral("Total consumed");
        case Rule:        return QStringLiteral("Rule");
        case Activity:    return QStringLiteral("Activity");
        default:          return {};
        }
    }
    if (role == Qt::ToolTipRole && section == Total)
        return QStringLiteral("Total data consumed by this application this session.");
    if (role == Qt::ToolTipRole && section == Rule)
        return QStringLiteral("Allow, Ask or Block network access for this application.");
    if (role == Qt::ToolTipRole && section == Activity)
        return QStringLiteral("Live download and upload rates, with a 24-second sparkline.");
    if (role == Qt::TextAlignmentRole)
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    return {};
}

// ============================================================================
// Filtering and sorting
// ============================================================================

ApplicationsPageFilterModel::ApplicationsPageFilterModel(ApplicationsPageTableModel *source,
                                                        QObject *parent)
    : QSortFilterProxyModel(parent), m_source(source)
{
    setSourceModel(source);
    setDynamicSortFilter(true);
}

void ApplicationsPageFilterModel::setFilter(Applications::Filter filter)
{
    if (m_filter == filter)
        return;
    m_filter = filter;
    invalidateFilter();
}

void ApplicationsPageFilterModel::setQuery(const QString &query)
{
    const QString trimmed = query.trimmed();
    if (m_query == trimmed)
        return;
    m_query = trimmed;
    invalidateFilter();
}

bool ApplicationsPageFilterModel::filterAcceptsRow(int sourceRow, const QModelIndex &) const
{
    const Applications::Row &row = m_source->rowAt(sourceRow);
    if (!matchesFilter(row, m_filter))
        return false;
    if (m_query.isEmpty())
        return true;

    const QString needle = m_query.toLower();
    return applicationLabel(row).toLower().contains(needle)
           || row.name.toLower().contains(needle)
           || row.publisher.toLower().contains(needle)
           || row.path.toLower().contains(needle);
}

bool ApplicationsPageFilterModel::lessThan(const QModelIndex &left,
                                           const QModelIndex &right) const
{
    const QVariant lhs = left.data(ApplicationsPageTableModel::SortRole);
    const QVariant rhs = right.data(ApplicationsPageTableModel::SortRole);
    if (lhs.metaType().id() == QMetaType::ULongLong)
        return lhs.toULongLong() < rhs.toULongLong();
    return lhs.toString().compare(rhs.toString()) < 0;
}

// ============================================================================
// Cell delegates
// ============================================================================

ApplicationNameDelegate::ApplicationNameDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}

void ApplicationNameDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                                    const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    opt.text.clear();
    QStyle *style = opt.widget ? opt.widget->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &opt, painter, opt.widget);

    const QString label = index.data(Qt::DisplayRole).toString();
    const QString name = index.data(ApplicationsPageTableModel::NameRole).toString();
    const QString publisher =
        index.data(ApplicationsPageTableModel::PublisherRole).toString();
    const bool dark = ThemeManager::instance().isDark();
    const Theme::Palette palette = Theme::palette(dark);
    const QIcon icon = index.data(ApplicationsPageTableModel::IconRole).value<QIcon>();

    const QRect content = opt.rect.adjusted(Theme::Dim::SpaceLg, 0,
                                            -Theme::Dim::SpaceLg, 0);
    const QRect tile(content.left(), content.center().y() - kIconSize / 2,
                     kIconSize, kIconSize);

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    if (!icon.isNull()) {
        const qreal dpr = painter->device() ? painter->device()->devicePixelRatioF() : 1.0;
        const QPixmap pixmap = icon.pixmap(QSize(kIconSize, kIconSize), dpr);
        if (!pixmap.isNull()) {
            painter->setRenderHint(QPainter::SmoothPixmapTransform, true);
            painter->drawPixmap(tile, pixmap);
        }
    } else {
        const QColor accent = avatarColor(name, dark);
        QColor tileFill = accent;
        tileFill.setAlpha(dark ? 38 : 24);
        painter->setPen(QPen(QColor(accent.red(), accent.green(), accent.blue(), 130), 1));
        painter->setBrush(tileFill);
        painter->drawRoundedRect(QRectF(tile).adjusted(0.5, 0.5, -0.5, -0.5), 7, 7);

        QFont initials = opt.font;
        initials.setPixelSize(Theme::Type::Body);
        initials.setWeight(QFont::DemiBold);
        painter->setFont(initials);
        painter->setPen(accent);
        painter->drawText(tile, Qt::AlignCenter,
                          initialsFor(label.isEmpty() ? name : label));
    }

    const int textLeft = tile.right() + Theme::Dim::SpaceMd;
    const int textWidth = content.right() - textLeft;
    if (textWidth <= 0) {
        painter->restore();
        return;
    }

    QFont primary = opt.font;
    primary.setPixelSize(Theme::Type::Body);
    primary.setWeight(QFont::DemiBold);
    const QFontMetrics primaryMetrics(primary);

    QFont secondary = opt.font;
    secondary.setPixelSize(Theme::Type::Metadata);
    const QFontMetrics secondaryMetrics(secondary);

    const QString friendly = primaryMetrics.elidedText(label, Qt::ElideRight, textWidth);
    const QString subtitleSource =
        publisher.trimmed().isEmpty() ? QStringLiteral("Publisher unknown") : publisher;
    const QString subtitle = secondaryMetrics.elidedText(
        subtitleSource, Qt::ElideRight, textWidth);

    const int lineOne = primaryMetrics.height();
    const int lineTwo = secondaryMetrics.height();
    const int top = content.center().y() - (lineOne + lineTwo) / 2;

    painter->setFont(primary);
    painter->setPen(Theme::qcolor(palette.textPrimary));
    painter->drawText(QRect(textLeft, top, textWidth, lineOne),
                      Qt::AlignLeft | Qt::AlignVCenter, friendly);

    painter->setFont(secondary);
    painter->setPen(Theme::qcolor(palette.textMuted));
    painter->drawText(QRect(textLeft, top + lineOne, textWidth, lineTwo),
                      Qt::AlignLeft | Qt::AlignVCenter, subtitle);
    painter->restore();
}

QSize ApplicationNameDelegate::sizeHint(const QStyleOptionViewItem &option,
                                        const QModelIndex &index) const
{
    Q_UNUSED(option);
    Q_UNUSED(index);
    return QSize(280, kRowHeight);
}

RuleDelegate::RuleDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}

void RuleDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                         const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    opt.text.clear();
    QStyle *style = opt.widget ? opt.widget->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &opt, painter, opt.widget);

    const QString token = index.data(ApplicationsPageTableModel::RuleRole).toString();
    const QString label = index.data(Qt::DisplayRole).toString();
    const QColor accent = ruleColor(token);
    const QColor fill = ruleBackground(token);

    QFont font = opt.font;
    font.setPixelSize(Theme::Type::Metadata + 1);
    font.setWeight(QFont::DemiBold);
    const QFontMetrics metrics(font);

    const int chevron = 10;
    const int padding = Theme::Dim::SpaceMd;
    const int height = 28;
    const int width = padding * 2 + metrics.horizontalAdvance(label)
                      + Theme::Dim::SpaceSm + chevron;
    const QRect pill(opt.rect.left() + Theme::Dim::SpaceLg,
                     opt.rect.center().y() - height / 2, width, height);

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    painter->setPen(QPen(QColor(accent.red(), accent.green(), accent.blue(), 150), 1));
    painter->setBrush(fill);
    painter->drawRoundedRect(QRectF(pill).adjusted(0.5, 0.5, -0.5, -0.5), 7, 7);

    painter->setFont(font);
    painter->setPen(accent);
    painter->drawText(QRect(pill.left() + padding, pill.top(),
                            pill.width() - padding * 2 - chevron,
                            pill.height()),
                      Qt::AlignLeft | Qt::AlignVCenter, label);

    const int cx = pill.right() - padding;
    const int cy = pill.center().y();
    QPen chevronPen(accent, 1.4);
    chevronPen.setCapStyle(Qt::RoundCap);
    chevronPen.setJoinStyle(Qt::RoundJoin);
    painter->setPen(chevronPen);
    painter->drawLine(QPointF(cx - 4.5, cy - 2), QPointF(cx, cy + 2.5));
    painter->drawLine(QPointF(cx, cy + 2.5), QPointF(cx + 4.5, cy - 2));
    painter->restore();
}

QSize RuleDelegate::sizeHint(const QStyleOptionViewItem &option,
                             const QModelIndex &index) const
{
    Q_UNUSED(option);
    Q_UNUSED(index);
    return QSize(148, kRowHeight);
}

ActivityDelegate::ActivityDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}

void ActivityDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                             const QModelIndex &index) const
{
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    opt.text.clear();
    QStyle *style = opt.widget ? opt.widget->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &opt, painter, opt.widget);

    const quint64 rx = index.data(ApplicationsPageTableModel::RxRateRole).toULongLong();
    const quint64 tx = index.data(ApplicationsPageTableModel::TxRateRole).toULongLong();
    const QVariantList samples = index.data(ApplicationsPageTableModel::SparkRole).toList();
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());

    const QRect content = opt.rect.adjusted(Theme::Dim::SpaceMd, 0,
                                            -Theme::Dim::SpaceSm, 0);

    QFont rateFont = opt.font;
    rateFont.setPixelSize(Theme::Type::Metadata + 1);
    rateFont.setWeight(QFont::DemiBold);
    const QFontMetrics metrics(rateFont);
    const int lineHeight = metrics.height();
    const int top = content.center().y() - lineHeight;

    // The sparkline sits to the right of the rates. No disclosure chevron:
    // a row has no inline expand control, and drawing one made a plain
    // click look like a toggle.
    const int sparkLeft = content.right() - kSparkWidth;
    const QRect spark(sparkLeft, content.center().y() - 13, kSparkWidth, 26);

    const int textLeft = content.left();
    const int textWidth = qMax(40, sparkLeft - Theme::Dim::SpaceSm - textLeft);
    const QColor active = Theme::qcolor(palette.semanticSuccess);
    const QColor idle = Theme::qcolor(palette.textMuted);
    paintRate(painter, QRect(textLeft, top, textWidth, lineHeight), rx, false,
              rx > 0 ? active : idle, rateFont);
    paintRate(painter, QRect(textLeft, top + lineHeight, textWidth, lineHeight), tx,
              true, tx > 0 ? active : idle, rateFont);
    paintSparkline(painter, spark, samples,
                   Theme::qcolor(palette.chartDownload), idle);
}

QSize ActivityDelegate::sizeHint(const QStyleOptionViewItem &option,
                                 const QModelIndex &index) const
{
    Q_UNUSED(option);
    Q_UNUSED(index);
    return QSize(220, kRowHeight);
}

void ActivityDelegate::paintRate(QPainter *painter, const QRect &row, quint64 rate, bool up,
                                 const QColor &color, const QFont &font)
{
    const int arrow = 9;
    const QRect arrowRect(row.left(), row.center().y() - arrow / 2, arrow, arrow);
    QPen pen(color, 1.3);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    painter->setPen(pen);
    const qreal cx = arrowRect.center().x();
    if (up) {
        painter->drawLine(QPointF(cx, arrowRect.bottom() - 0.5),
                          QPointF(cx, arrowRect.top() + 0.5));
        painter->drawLine(QPointF(cx - 2.4, arrowRect.top() + 2.9),
                          QPointF(cx, arrowRect.top() + 0.5));
        painter->drawLine(QPointF(cx + 2.4, arrowRect.top() + 2.9),
                          QPointF(cx, arrowRect.top() + 0.5));
    } else {
        painter->drawLine(QPointF(cx, arrowRect.top() + 0.5),
                          QPointF(cx, arrowRect.bottom() - 0.5));
        painter->drawLine(QPointF(cx - 2.4, arrowRect.bottom() - 2.9),
                          QPointF(cx, arrowRect.bottom() - 0.5));
        painter->drawLine(QPointF(cx + 2.4, arrowRect.bottom() - 2.9),
                          QPointF(cx, arrowRect.bottom() - 0.5));
    }

    painter->setFont(font);
    painter->setPen(color);
    painter->drawText(QRect(row.left() + arrow + Theme::Dim::SpaceXs, row.top(),
                            row.width() - arrow - Theme::Dim::SpaceXs, row.height()),
                      Qt::AlignLeft | Qt::AlignVCenter, formattedRate(rate));
    painter->restore();
}

void ActivityDelegate::paintSparkline(QPainter *painter, const QRect &area,
                                      const QVariantList &samples, const QColor &color,
                                      const QColor &emptyColor)
{
    QVector<qreal> values;
    values.reserve(samples.size());
    qreal maximum = 0;
    for (const QVariant &sample : samples) {
        const qreal value = qreal(sample.toULongLong());
        values.append(value);
        maximum = qMax(maximum, value);
    }

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    if (values.size() < 2 || maximum <= 0) {
        QPen flat(emptyColor, 1.3);
        flat.setCapStyle(Qt::RoundCap);
        painter->setPen(flat);
        painter->drawLine(QPointF(area.left(), area.center().y()),
                          QPointF(area.right(), area.center().y()));
        painter->restore();
        return;
    }

    const qreal step = qreal(area.width()) / qreal(values.size() - 1);
    QPainterPath path;
    for (int i = 0; i < values.size(); ++i) {
        const qreal x = area.left() + i * step;
        const qreal y = area.bottom() - (values.at(i) / maximum) * area.height();
        if (i == 0)
            path.moveTo(x, y);
        else
            path.lineTo(x, y);
    }
    QPen pen(color, 1.5);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);
    painter->setPen(pen);
    painter->drawPath(path);
    painter->restore();
}
