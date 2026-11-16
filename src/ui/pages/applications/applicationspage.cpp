/**
 * @file    applicationspage.cpp
 * @author  Oasis
 */
#include "applicationspage.h"

#include "ui/components/emptystatewidget.h"
#include "ui/theme/colors.h"
#include "ui/theme/dimensions.h"
#include "ui/theme/thememanager.h"
#include "ui/theme/typography.h"

#include <QAbstractTableModel>
#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QFontMetrics>
#include <QFrame>
#include <QGridLayout>
#include <QHash>
#include <QScrollArea>
#include <QTabWidget>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>
#include <QPair>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollBar>
#include <QSizePolicy>
#include <QSortFilterProxyModel>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <QVector>

namespace {

constexpr int kRowHeight = 64;
constexpr int kIconSize = 32;
constexpr int kSparkPoints = 24;
constexpr int kSparkWidth = 60;

QString applicationLabel(const Applications::Row &row)
{
    return row.displayName.trimmed().isEmpty() ? row.name : row.displayName;
}

bool blockedRow(const Applications::Row &row)
{
    return row.rule == QLatin1String("block")
           || row.policyToken == QLatin1String("blocked");
}

QString ruleToken(const Applications::Row &row)
{
    if (row.rule == QLatin1String("ask")) return QStringLiteral("ask");
    if (blockedRow(row)) return QStringLiteral("block");
    return QStringLiteral("allow");
}

QString ruleText(const Applications::Row &row)
{
    const QString token = ruleToken(row);
    if (token == QLatin1String("ask")) return QStringLiteral("Ask");
    if (token == QLatin1String("block")) return QStringLiteral("Block");
    return QStringLiteral("Allow");
}

bool matchesFilter(const Applications::Row &row, Applications::Filter filter)
{
    switch (filter) {
    case Applications::Filter::All:
        return true;
    case Applications::Filter::Active:
        return !blockedRow(row)
               && row.rxBytesPerSecond + row.txBytesPerSecond > 0;
    case Applications::Filter::Idle:
        return !blockedRow(row)
               && row.rxBytesPerSecond + row.txBytesPerSecond == 0;
    case Applications::Filter::AllowRule:
        return ruleToken(row) == QLatin1String("allow");
    case Applications::Filter::AskRule:
        return ruleToken(row) == QLatin1String("ask");
    case Applications::Filter::BlockRule:
        return ruleToken(row) == QLatin1String("block");
    }
    return true;
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

QColor avatarColor(const QString &name, bool dark)
{
    static const char *colors[] = {
        "#4C8DFF", "#3FB982", "#E6AD4D", "#E36B70",
        "#62B5E8", "#A78BFA", "#F472B6", "#34D399"
    };
    const uint hash = qHash(name.toLower());
    QColor color = QColor::fromString(QString::fromLatin1(colors[hash % 8]));
    if (!dark)
        color = color.darker(115);
    return color;
}

QColor ruleColor(const QString &tone)
{
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
    if (tone == QLatin1String("ask"))
        return Theme::qcolor(palette.semanticWarning);
    if (tone == QLatin1String("block"))
        return Theme::qcolor(palette.semanticDanger);
    return Theme::qcolor(palette.semanticSuccess);
}

QColor ruleBackground(const QString &tone)
{
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
    if (tone == QLatin1String("ask"))
        return Theme::qcolor(palette.warningSubtle);
    if (tone == QLatin1String("block"))
        return Theme::qcolor(palette.dangerSubtle);
    return Theme::qcolor(palette.successSubtle);
}

QString ruleLabelForToken(const QString &rule)
{
    const QString token = rule.trimmed().toLower();
    if (token == QLatin1String("ask")) return QStringLiteral("Ask");
    if (token == QLatin1String("block")) return QStringLiteral("Block");
    return QStringLiteral("Allow");
}

QString ruleDescriptionForToken(const QString &rule)
{
    const QString token = rule.trimmed().toLower();
    if (token == QLatin1String("ask"))
        return QStringLiteral("Oasis asks before this application connects.");
    if (token == QLatin1String("block"))
        return QStringLiteral("Internet access is blocked.");
    return QStringLiteral("Internet access is allowed.");
}

QString cssColor(const QColor &color)
{
    return QStringLiteral("rgba(%1,%2,%3,%4)")
        .arg(color.red())
        .arg(color.green())
        .arg(color.blue())
        .arg(color.alphaF(), 0, 'f', 3);
}

void styleRuleButton(QPushButton *button, const QString &rule)
{
    if (!button)
        return;
    const QString token = rule.trimmed().toLower();
    const QColor accent = ruleColor(token);
    const QColor fill = ruleBackground(token);
    QColor border = accent;
    border.setAlpha(150);
    button->setText(ruleLabelForToken(token) + QStringLiteral("    ⌄"));
    button->setStyleSheet(
        QStringLiteral(
            "QPushButton { text-align: left; padding: 7px 12px;"
            " border-radius: 7px; border: 1px solid %1; background: %2;"
            " color: %3; font-weight: 600; }"
            "QPushButton:hover { border-color: %3; }")
            .arg(cssColor(border), cssColor(fill), accent.name()));
}

QString formattedBytes(quint64 bytes);

QString formattedRate(quint64 bytesPerSecond)
{
    if (bytesPerSecond == 0)
        return QStringLiteral("0 B/s");
    return formattedBytes(bytesPerSecond) + QStringLiteral("/s");
}

QString formattedBytes(quint64 bytes)
{
    const char *units[] = { "B", "KB", "MB", "GB", "TB" };
    double value = double(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    const int precision = (unit == 0 || value >= 10.0) ? 0 : 1;
    return QString::number(value, 'f', precision) + QLatin1Char(' ')
           + QString::fromLatin1(units[unit]);
}

QString orDash(const QString &text)
{
    return text.trimmed().isEmpty() ? QStringLiteral("—") : text.trimmed();
}

enum class Glyph { Search, Filter, Sort, More };

QIcon glyphIcon(Glyph glyph, const QColor &color)
{
    constexpr int logical = 18;
    constexpr int scale = 2;
    QPixmap pixmap(logical * scale, logical * scale);
    pixmap.setDevicePixelRatio(scale);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    QPen pen(color, 1.6);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);
    painter.setPen(pen);
    painter.setBrush(Qt::NoBrush);

    switch (glyph) {
    case Glyph::Search:
        painter.drawEllipse(QRectF(3.8, 3.8, 8.4, 8.4));
        painter.drawLine(QPointF(11.6, 11.6), QPointF(15.2, 15.2));
        break;
    case Glyph::Filter: {
        QPainterPath path;
        path.moveTo(2.8, 4.2);
        path.lineTo(15.2, 4.2);
        path.lineTo(10.4, 9.8);
        path.lineTo(10.4, 14.4);
        path.lineTo(7.6, 15.8);
        path.lineTo(7.6, 9.8);
        path.closeSubpath();
        painter.drawPath(path);
        break;
    }
    case Glyph::Sort:
        painter.drawLine(QPointF(5.6, 15.4), QPointF(5.6, 4.0));
        painter.drawLine(QPointF(3.2, 6.4), QPointF(5.6, 4.0));
        painter.drawLine(QPointF(8.0, 6.4), QPointF(5.6, 4.0));
        painter.drawLine(QPointF(12.4, 2.6), QPointF(12.4, 14.0));
        painter.drawLine(QPointF(10.0, 11.6), QPointF(12.4, 14.0));
        painter.drawLine(QPointF(14.8, 11.6), QPointF(12.4, 14.0));
        break;
    case Glyph::More:
        painter.setPen(Qt::NoPen);
        painter.setBrush(color);
        for (qreal x : { 4.2, 9.0, 13.8 })
            painter.drawEllipse(QPointF(x, 9.0), 1.35, 1.35);
        break;
    }
    return QIcon(pixmap);
}

QIcon dotIcon(const QColor &color)
{
    QPixmap pixmap(24, 24);
    pixmap.setDevicePixelRatio(2);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(Qt::NoPen);
    painter.setBrush(color);
    painter.drawEllipse(QPointF(6, 6), 3, 3);
    return QIcon(pixmap);
}

QString legendHtml()
{
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
    const QString text = Theme::qcolor(palette.textMuted).name();
    const QString allow = Theme::qcolor(palette.semanticSuccess).name();
    const QString ask = Theme::qcolor(palette.semanticWarning).name();
    const QString block = Theme::qcolor(palette.semanticDanger).name();
    return QStringLiteral(
               "<span style='color:%1'>●</span>&nbsp;"
               "<span style='color:%2'>Allow</span>&nbsp;&nbsp;&nbsp;"
               "<span style='color:%3'>●</span>&nbsp;"
               "<span style='color:%2'>Ask</span>&nbsp;&nbsp;&nbsp;"
               "<span style='color:%4'>●</span>&nbsp;"
               "<span style='color:%2'>Block</span>")
        .arg(allow, text, ask, block);
}

} // namespace

namespace Applications {

QString filterLabel(Filter filter)
{
    switch (filter) {
    case Filter::All:
        return QStringLiteral("All applications");
    case Filter::Active:
        return QStringLiteral("Active now");
    case Filter::Idle:
        return QStringLiteral("Idle");
    case Filter::AllowRule:
        return QStringLiteral("Rule · Allow");
    case Filter::AskRule:
        return QStringLiteral("Rule · Ask");
    case Filter::BlockRule:
        return QStringLiteral("Rule · Block");
    }
    return QStringLiteral("All applications");
}

} // namespace Applications

// ============================================================================
// Table model
// ============================================================================

class ApplicationsPageTableModel : public QAbstractTableModel
{
public:
    enum Column {
        Application = 0,
        Total,
        Rule,
        Activity,
        ColumnCount
    };

    enum Role {
        SortRole = Qt::UserRole + 1,
        NameRole,
        PublisherRole,
        PidRole,
        IconRole,
        RuleRole,
        TotalRole,
        RxRateRole,
        TxRateRole,
        SparkRole
    };

    explicit ApplicationsPageTableModel(QObject *parent = nullptr)
        : QAbstractTableModel(parent)
    {
    }

    void setRows(const QList<Applications::Row> &rows)
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

        beginResetModel();
        m_rows = rows;
        m_history = history;
        endResetModel();
    }

    const Applications::Row &rowAt(int sourceRow) const { return m_rows.at(sourceRow); }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : int(m_rows.size());
    }

    int columnCount(const QModelIndex &parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : int(ColumnCount);
    }

    QVariant data(const QModelIndex &index, int role) const override
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

    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
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

private:
    QList<Applications::Row> m_rows;
    QHash<quint32, QVector<quint64>> m_history;
};

// ============================================================================
// Filtering and sorting
// ============================================================================

class ApplicationsPageFilterModel : public QSortFilterProxyModel
{
public:
    explicit ApplicationsPageFilterModel(ApplicationsPageTableModel *source,
                                         QObject *parent = nullptr)
        : QSortFilterProxyModel(parent), m_source(source)
    {
        setSourceModel(source);
        setDynamicSortFilter(true);
    }

    void setFilter(Applications::Filter filter)
    {
        if (m_filter == filter)
            return;
        m_filter = filter;
        invalidateFilter();
    }

    void setQuery(const QString &query)
    {
        const QString trimmed = query.trimmed();
        if (m_query == trimmed)
            return;
        m_query = trimmed;
        invalidateFilter();
    }

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &) const override
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

    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override
    {
        const QVariant lhs = left.data(ApplicationsPageTableModel::SortRole);
        const QVariant rhs = right.data(ApplicationsPageTableModel::SortRole);
        if (lhs.metaType().id() == QMetaType::ULongLong)
            return lhs.toULongLong() < rhs.toULongLong();
        return lhs.toString().compare(rhs.toString()) < 0;
    }

private:
    ApplicationsPageTableModel *m_source = nullptr;
    Applications::Filter m_filter = Applications::Filter::All;
    QString m_query;
};

// ============================================================================
// Cell delegates
// ============================================================================

class ApplicationNameDelegate : public QStyledItemDelegate
{
public:
    explicit ApplicationNameDelegate(QObject *parent = nullptr)
        : QStyledItemDelegate(parent)
    {
    }

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
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

    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override
    {
        Q_UNUSED(option);
        Q_UNUSED(index);
        return QSize(280, kRowHeight);
    }
};

class RuleDelegate : public QStyledItemDelegate
{
public:
    explicit RuleDelegate(QObject *parent = nullptr)
        : QStyledItemDelegate(parent)
    {
    }

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
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

    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override
    {
        Q_UNUSED(option);
        Q_UNUSED(index);
        return QSize(148, kRowHeight);
    }
};

class ActivityDelegate : public QStyledItemDelegate
{
public:
    explicit ActivityDelegate(QObject *parent = nullptr)
        : QStyledItemDelegate(parent)
    {
    }

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
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

        // Sparkline and the drawer affordance sit to the right of the rates.
        const int chevronWidth = 8;
        const int chevronX = content.right() - chevronWidth;
        const int sparkLeft = chevronX - Theme::Dim::SpaceSm - kSparkWidth;
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

        QPen chevron(Theme::qcolor(palette.textMuted), 1.4);
        chevron.setCapStyle(Qt::RoundCap);
        chevron.setJoinStyle(Qt::RoundJoin);
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setPen(chevron);
        const int cy = content.center().y();
        painter->drawLine(QPointF(chevronX + 1, cy - 4), QPointF(chevronX + 5, cy));
        painter->drawLine(QPointF(chevronX + 5, cy), QPointF(chevronX + 1, cy + 4));
        painter->restore();
    }

    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override
    {
        Q_UNUSED(option);
        Q_UNUSED(index);
        return QSize(220, kRowHeight);
    }

private:
    static void paintRate(QPainter *painter, const QRect &row, quint64 rate, bool up,
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

    static void paintSparkline(QPainter *painter, const QRect &area,
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
};

// ============================================================================
// Page
// ============================================================================

ApplicationsPage::ApplicationsPage(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("applicationsPage"));

    auto *rootLayout = new QHBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    auto *content = new QWidget(this);
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(Theme::Dim::PagePaddingH, Theme::Dim::SpaceLg,
                               Theme::Dim::PagePaddingH, Theme::Dim::PagePaddingV);
    layout->setSpacing(Theme::Dim::SpaceLg);
    rootLayout->addWidget(content, 1);

    // ── Toolbar: search, filters, sort and page actions ─────────────────────
    m_actionsWidget = new QWidget(this);
    auto *toolbar = m_actionsWidget;
    auto *toolbarLayout = new QHBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(Theme::Dim::SpaceSm);

    m_search = new QLineEdit(toolbar);
    m_search->setPlaceholderText(QStringLiteral("Search applications…"));
    m_search->setClearButtonEnabled(true);
    m_search->setMinimumWidth(260);
    m_search->setMaximumWidth(340);
    m_search->setFixedHeight(Theme::Dim::InputHeight);
    m_search->setAccessibleName(QStringLiteral("Search applications"));
    m_searchAction = m_search->addAction(QIcon(), QLineEdit::LeadingPosition);
    toolbarLayout->addWidget(m_search);

    auto makeButton = [&](const QString &tooltip) {
        auto *button = new QPushButton(toolbar);
        button->setProperty("variant", QStringLiteral("ghost"));
        button->setFixedSize(Theme::Dim::ButtonHeight, Theme::Dim::ButtonHeight);
        button->setIconSize(QSize(18, 18));
        button->setCursor(Qt::PointingHandCursor);
        button->setToolTip(tooltip);
        button->setAccessibleName(tooltip);
        return button;
    };

    m_filterButton = makeButton(QStringLiteral("Filter applications"));
    m_sortButton = makeButton(QStringLiteral("Sort applications"));
    m_moreButton = makeButton(QStringLiteral("More actions"));
    toolbarLayout->addWidget(m_filterButton);
    toolbarLayout->addWidget(m_sortButton);
    toolbarLayout->addWidget(m_moreButton);

    connect(m_search, &QLineEdit::textChanged, this, &ApplicationsPage::applyQuery);
    connect(m_filterButton, &QPushButton::clicked, this, &ApplicationsPage::showFilterMenu);
    connect(m_sortButton, &QPushButton::clicked, this, &ApplicationsPage::showSortMenu);
    connect(m_moreButton, &QPushButton::clicked, this, &ApplicationsPage::showMoreMenu);

    // ── Table ───────────────────────────────────────────────────────────────
    m_model = new ApplicationsPageTableModel(this);
    m_proxy = new ApplicationsPageFilterModel(m_model, this);

    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSortingEnabled(true);
    m_table->sortByColumn(ApplicationsPageTableModel::Application, Qt::AscendingOrder);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setShowGrid(false);
    m_table->setWordWrap(false);
    m_table->setFrameShape(QFrame::NoFrame);
    m_table->setAlternatingRowColors(false);
    m_table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_table->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_table->verticalHeader()->hide();
    m_table->verticalHeader()->setDefaultSectionSize(kRowHeight);
    m_table->verticalHeader()->setMinimumSectionSize(kRowHeight);
    m_table->setItemDelegateForColumn(ApplicationsPageTableModel::Application,
                                      new ApplicationNameDelegate(m_table));
    m_table->setItemDelegateForColumn(ApplicationsPageTableModel::Rule,
                                      new RuleDelegate(m_table));
    m_table->setItemDelegateForColumn(ApplicationsPageTableModel::Activity,
                                      new ActivityDelegate(m_table));

    QHeaderView *header = m_table->horizontalHeader();
    header->setStretchLastSection(false);
    header->setHighlightSections(false);
    header->setSectionsClickable(true);
    header->setMinimumSectionSize(64);
    header->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    header->setSectionResizeMode(ApplicationsPageTableModel::Application,
                                 QHeaderView::Stretch);
    header->setSectionResizeMode(ApplicationsPageTableModel::Total,
                                 QHeaderView::ResizeToContents);
    header->setSectionResizeMode(ApplicationsPageTableModel::Rule,
                                 QHeaderView::Fixed);
    header->setSectionResizeMode(ApplicationsPageTableModel::Activity,
                                 QHeaderView::Fixed);
    m_table->setColumnWidth(ApplicationsPageTableModel::Rule, 148);
    m_table->setColumnWidth(ApplicationsPageTableModel::Activity, 220);

    // Row actions live on the row: a right-click menu, a click that opens the
    // details drawer, and a click on the rule that opens its menu.
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QTableView::customContextMenuRequested,
            this, &ApplicationsPage::showContextMenu);
    connect(m_table, &QTableView::clicked, this, [this](const QModelIndex &index) {
        if (!index.isValid())
            return;
        if (index.column() == ApplicationsPageTableModel::Rule) {
            showRuleMenu(index);
            return;
        }
        m_table->selectRow(index.row());
        Applications::Row row;
        if (rowForIndex(index, &row))
            emit detailsRequested(row.pid, row.path, row.name);
    });
    layout->addWidget(m_table, 1);

    // ── Empty state ─────────────────────────────────────────────────────────
    m_emptyHost = new QWidget(this);
    auto *emptyLayout = new QVBoxLayout(m_emptyHost);
    emptyLayout->setContentsMargins(0, 0, 0, 0);
    m_empty = new EmptyStateWidget(m_emptyHost);
    emptyLayout->addStretch(1);
    emptyLayout->addWidget(m_empty, 0, Qt::AlignHCenter);
    emptyLayout->addStretch(1);
    m_emptyHost->hide();
    layout->addWidget(m_emptyHost, 1);

    // ── Footer: count and rule legend ───────────────────────────────────────
    m_footer = new QWidget(this);
    auto *footerLayout = new QHBoxLayout(m_footer);
    footerLayout->setContentsMargins(Theme::Dim::SpaceXs, 0,
                                     Theme::Dim::SpaceXs, 0);
    m_footerCount = new QLabel(m_footer);
    m_footerCount->setProperty("uiRole", QStringLiteral("muted"));
    footerLayout->addWidget(m_footerCount);
    footerLayout->addStretch(1);
    m_legend = new QLabel(m_footer);
    m_legend->setTextFormat(Qt::RichText);
    footerLayout->addWidget(m_legend);
    layout->addWidget(m_footer);

    auto *drawer = buildDrawer();
    m_drawer->hide();
    rootLayout->addWidget(drawer);

    connect(&ThemeManager::instance(), &ThemeManager::themeChanged, this,
            [this](ThemeManager::Mode) {
        refreshThemeIcons();
        refreshFooter();
    });

    refreshThemeIcons();
    refreshFooter();
    refreshEmptyState();
}

QWidget *ApplicationsPage::buildDrawer()
{
    m_drawer = new QFrame(this);
    m_drawer->setObjectName(QStringLiteral("applicationDrawer"));
    m_drawer->setFixedWidth(320);

    auto *layout = new QVBoxLayout(m_drawer);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto *header = new QWidget(m_drawer);
    auto *headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceLg,
                                     Theme::Dim::SpaceMd, Theme::Dim::SpaceSm);
    headerLayout->setSpacing(Theme::Dim::SpaceMd);

    m_drawerIcon = new QLabel(header);
    m_drawerIcon->setFixedSize(32, 32);
    headerLayout->addWidget(m_drawerIcon, 0, Qt::AlignVCenter);

    m_drawerName = new QLabel(header);
    m_drawerName->setObjectName(QStringLiteral("drawerAppName"));
    m_drawerName->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_drawerName->setWordWrap(false);
    headerLayout->addWidget(m_drawerName, 1, Qt::AlignVCenter);

    auto *close = new QPushButton(QStringLiteral("✕"), header);
    close->setProperty("variant", QStringLiteral("ghost"));
    close->setFixedSize(28, 28);
    close->setCursor(Qt::PointingHandCursor);
    close->setToolTip(QStringLiteral("Close details"));
    close->setAccessibleName(QStringLiteral("Close details"));
    headerLayout->addWidget(close, 0, Qt::AlignVCenter);
    layout->addWidget(header);

    m_drawerTabs = new QTabWidget(m_drawer);
    m_drawerTabs->setDocumentMode(true);
    m_drawerTabs->setTabPosition(QTabWidget::North);
    m_drawerTabs->addTab(buildDetailsTab(), QStringLiteral("Details"));
    m_drawerTabs->addTab(buildConnectionsTab(), QStringLiteral("Connections"));
    m_drawerTabs->addTab(buildRulesTab(), QStringLiteral("Rules"));
    layout->addWidget(m_drawerTabs, 1);

    connect(close, &QPushButton::clicked, this, &ApplicationsPage::closeDetails);
    return m_drawer;
}

QWidget *ApplicationsPage::buildDetailsTab()
{
    auto *page = new QWidget(m_drawer);
    auto *pageLayout = new QVBoxLayout(page);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(0);

    auto *scroll = new QScrollArea(page);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    pageLayout->addWidget(scroll);

    auto *content = new QWidget;
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceMd,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    layout->setSpacing(Theme::Dim::SpaceMd);
    scroll->setWidget(content);

    auto *facts = new QGridLayout;
    facts->setHorizontalSpacing(Theme::Dim::SpaceMd);
    facts->setVerticalSpacing(Theme::Dim::SpaceSm);
    facts->setColumnStretch(1, 1);

    auto addFact = [&](int row, const QString &label, QLabel **target, bool wrap) {
        auto *key = new QLabel(label, content);
        key->setProperty("uiRole", QStringLiteral("muted"));
        auto *value = new QLabel(content);
        value->setProperty("uiRole", QStringLiteral("rowValue"));
        value->setWordWrap(wrap);
        value->setTextInteractionFlags(Qt::TextSelectableByMouse);
        value->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        facts->addWidget(key, row, 0, Qt::AlignTop);
        facts->addWidget(value, row, 1, Qt::AlignTop);
        *target = value;
    };
    addFact(0, QStringLiteral("Publisher"), &m_drawerPublisher, false);
    addFact(1, QStringLiteral("Version"), &m_drawerVersion, false);
    addFact(2, QStringLiteral("Installed"), &m_drawerInstalled, false);
    addFact(3, QStringLiteral("Path"), &m_drawerPath, true);
    layout->addLayout(facts);

    auto *ruleHeading = new QLabel(QStringLiteral("Rule"), content);
    ruleHeading->setProperty("uiRole", QStringLiteral("cardHeading"));
    layout->addWidget(ruleHeading);

    m_drawerRuleButton = new QPushButton(content);
    m_drawerRuleButton->setFixedHeight(Theme::Dim::ButtonHeight);
    m_drawerRuleButton->setCursor(Qt::PointingHandCursor);
    m_drawerRuleButton->setToolTip(QStringLiteral("Change the network rule for this application."));
    layout->addWidget(m_drawerRuleButton);
    connect(m_drawerRuleButton, &QPushButton::clicked, this, [this]() {
        if (!m_detailsOpen)
            return;
        showRuleMenuFor(m_details.pid, m_details.path, m_details.name, m_details.rule,
                        m_drawerRuleButton->mapToGlobal(
                            QPoint(0, m_drawerRuleButton->height() + Theme::Dim::SpaceXs)));
    });

    m_ruleHint = new QLabel(content);
    m_ruleHint->setProperty("uiRole", QStringLiteral("muted"));
    m_ruleHint->setWordWrap(true);
    layout->addWidget(m_ruleHint);

    auto *statistics = new QLabel(QStringLiteral("Statistics"), content);
    statistics->setProperty("uiRole", QStringLiteral("cardHeading"));
    layout->addWidget(statistics);

    auto *session = new QLabel(QStringLiteral("This session"), content);
    session->setProperty("uiRole", QStringLiteral("muted"));
    layout->addWidget(session);

    auto *sessionGrid = new QGridLayout;
    sessionGrid->setHorizontalSpacing(Theme::Dim::SpaceMd);
    sessionGrid->setVerticalSpacing(Theme::Dim::SpaceSm);
    auto addStat = [&](QGridLayout *grid, int row, const QString &label, QLabel **target) {
        auto *key = new QLabel(label, content);
        key->setProperty("uiRole", QStringLiteral("muted"));
        auto *value = new QLabel(QStringLiteral("0 B"), content);
        value->setProperty("uiRole", QStringLiteral("rowValue"));
        value->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        grid->addWidget(key, row, 0);
        grid->addWidget(value, row, 1);
        *target = value;
    };
    addStat(sessionGrid, 0, QStringLiteral("Uploaded"), &m_sessionUploaded);
    addStat(sessionGrid, 1, QStringLiteral("Downloaded"), &m_sessionDownloaded);
    addStat(sessionGrid, 2, QStringLiteral("Total"), &m_sessionTotal);
    layout->addLayout(sessionGrid);

    auto *week = new QLabel(QStringLiteral("Last 7 days"), content);
    week->setProperty("uiRole", QStringLiteral("rowTitle"));
    layout->addWidget(week);

    auto *weekGrid = new QGridLayout;
    weekGrid->setHorizontalSpacing(Theme::Dim::SpaceMd);
    weekGrid->setVerticalSpacing(Theme::Dim::SpaceSm);
    addStat(weekGrid, 0, QStringLiteral("Uploaded"), &m_weekUploaded);
    addStat(weekGrid, 1, QStringLiteral("Downloaded"), &m_weekDownloaded);
    addStat(weekGrid, 2, QStringLiteral("Total"), &m_weekTotal);
    layout->addLayout(weekGrid);

    auto *lastActivity = new QLabel(QStringLiteral("Last activity"), content);
    lastActivity->setProperty("uiRole", QStringLiteral("cardHeading"));
    layout->addWidget(lastActivity);

    auto *activityGrid = new QGridLayout;
    activityGrid->setHorizontalSpacing(Theme::Dim::SpaceMd);
    activityGrid->setVerticalSpacing(Theme::Dim::SpaceSm);
    addStat(activityGrid, 0, QStringLiteral("Active"), &m_lastActive);
    addStat(activityGrid, 1, QStringLiteral("Connections"), &m_lastConnections);
    addStat(activityGrid, 2, QStringLiteral("Remote addresses"), &m_lastRemoteAddresses);
    layout->addLayout(activityGrid);

    layout->addStretch(1);
    return page;
}

QWidget *ApplicationsPage::buildConnectionsTab()
{
    auto *page = new QWidget(m_drawer);
    auto *pageLayout = new QVBoxLayout(page);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(0);

    auto *scroll = new QScrollArea(page);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    pageLayout->addWidget(scroll);

    auto *content = new QWidget;
    auto *layout = new QVBoxLayout(content);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceMd,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    layout->setSpacing(Theme::Dim::SpaceSm);
    scroll->setWidget(content);

    m_connectionsEmpty = new QLabel(
        QStringLiteral("No connections observed for this application."), content);
    m_connectionsEmpty->setProperty("uiRole", QStringLiteral("muted"));
    m_connectionsEmpty->setWordWrap(true);
    layout->addWidget(m_connectionsEmpty);

    m_connectionsLayout = new QVBoxLayout;
    m_connectionsLayout->setSpacing(Theme::Dim::SpaceSm);
    layout->addLayout(m_connectionsLayout);
    layout->addStretch(1);
    return page;
}

QWidget *ApplicationsPage::buildRulesTab()
{
    auto *page = new QWidget(m_drawer);
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(Theme::Dim::SpaceLg, Theme::Dim::SpaceLg,
                               Theme::Dim::SpaceLg, Theme::Dim::SpaceLg);
    layout->setSpacing(Theme::Dim::SpaceMd);

    auto *heading = new QLabel(QStringLiteral("Rule"), page);
    heading->setProperty("uiRole", QStringLiteral("cardHeading"));
    layout->addWidget(heading);

    m_rulesRuleButton = new QPushButton(page);
    m_rulesRuleButton->setFixedHeight(Theme::Dim::ButtonHeight);
    m_rulesRuleButton->setCursor(Qt::PointingHandCursor);
    layout->addWidget(m_rulesRuleButton);
    connect(m_rulesRuleButton, &QPushButton::clicked, this, [this]() {
        if (!m_detailsOpen)
            return;
        showRuleMenuFor(m_details.pid, m_details.path, m_details.name, m_details.rule,
                        m_rulesRuleButton->mapToGlobal(
                            QPoint(0, m_rulesRuleButton->height() + Theme::Dim::SpaceXs)));
    });

    m_rulesDescription = new QLabel(page);
    m_rulesDescription->setProperty("uiRole", QStringLiteral("muted"));
    m_rulesDescription->setWordWrap(true);
    layout->addWidget(m_rulesDescription);

    auto *note = new QLabel(
        QStringLiteral("Rules set here apply to this executable. Broader publisher "
                       "and group policies still apply."),
        page);
    note->setProperty("uiRole", QStringLiteral("muted"));
    note->setWordWrap(true);
    layout->addWidget(note);
    layout->addStretch(1);
    return page;
}

void ApplicationsPage::showDetails(const Applications::Details &details)
{
    m_details = details;
    m_detailsOpen = true;
    populateDetails();
    if (m_drawerTabs)
        m_drawerTabs->setCurrentIndex(0);
    m_drawer->show();
    m_drawer->raise();
}

void ApplicationsPage::closeDetails()
{
    m_detailsOpen = false;
    if (m_drawer)
        m_drawer->hide();
}

void ApplicationsPage::populateDetails()
{
    const QString label = m_details.displayName.trimmed().isEmpty()
        ? m_details.name : m_details.displayName;
    m_drawerName->setText(orDash(label));
    m_drawerPublisher->setText(orDash(m_details.publisher));
    m_drawerVersion->setText(orDash(m_details.version));
    m_drawerInstalled->setText(m_details.installedAt.isValid()
                                   ? m_details.installedAt.toLocalTime().toString(
                                         QStringLiteral("M/d/yyyy"))
                                   : QStringLiteral("—"));
    m_drawerPath->setText(orDash(m_details.path));

    if (!m_details.icon.isNull()) {
        const qreal dpr = m_drawerIcon->devicePixelRatioF();
        m_drawerIcon->setPixmap(m_details.icon.pixmap(QSize(32, 32), dpr));
    } else {
        m_drawerIcon->clear();
    }

    m_sessionUploaded->setText(formattedBytes(m_details.uploadedBytes));
    m_sessionDownloaded->setText(formattedBytes(m_details.downloadedBytes));
    m_sessionTotal->setText(
        formattedBytes(m_details.uploadedBytes + m_details.downloadedBytes));
    m_weekUploaded->setText(formattedBytes(m_details.weeklyUploadedBytes));
    m_weekDownloaded->setText(formattedBytes(m_details.weeklyDownloadedBytes));
    m_weekTotal->setText(
        formattedBytes(m_details.weeklyUploadedBytes + m_details.weeklyDownloadedBytes));

    const Applications::Row *row = nullptr;
    for (const Applications::Row &candidate : m_rows) {
        if (candidate.pid == m_details.pid) {
            row = &candidate;
            break;
        }
    }
    if (row) {
        m_lastActive->setText(blockedRow(*row) ? QStringLiteral("Blocked")
                              : (row->rxBytesPerSecond + row->txBytesPerSecond > 0
                                     ? QStringLiteral("now") : QStringLiteral("—")));
    } else {
        m_lastActive->setText(QStringLiteral("—"));
    }
    m_lastConnections->setText(QString::number(m_details.connectionCount));
    m_lastRemoteAddresses->setText(QString::number(m_details.remoteAddressCount));

    while (QLayoutItem *item = m_connectionsLayout->takeAt(0)) {
        delete item->widget();
        delete item;
    }
    m_connectionsEmpty->setVisible(m_details.endpoints.isEmpty());
    QWidget *connectionsHost = m_connectionsLayout->parentWidget();
    for (const QString &endpoint : m_details.endpoints) {
        auto *line = new QLabel(endpoint, connectionsHost);
        line->setProperty("uiRole", QStringLiteral("rowValue"));
        line->setWordWrap(true);
        line->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_connectionsLayout->addWidget(line);
    }

    applyDetailsRule(m_details.rule);
}

void ApplicationsPage::applyDetailsRule(const QString &rule)
{
    m_details.rule = rule;
    styleRuleButton(m_drawerRuleButton, rule);
    styleRuleButton(m_rulesRuleButton, rule);
    if (m_ruleHint)
        m_ruleHint->setText(ruleDescriptionForToken(rule));
    if (m_rulesDescription)
        m_rulesDescription->setText(ruleDescriptionForToken(rule));
}

void ApplicationsPage::setRows(const QList<Applications::Row> &rows)
{
    quint32 selectedPid = 0;
    if (m_table->currentIndex().isValid())
        selectedPid = m_table->currentIndex().data(ApplicationsPageTableModel::PidRole).toUInt();
    const int scroll = m_table->verticalScrollBar()->value();

    m_rows = rows;
    m_model->setRows(rows);

    if (m_detailsOpen) {
        for (const Applications::Row &row : m_rows) {
            if (row.pid != m_details.pid)
                continue;
            if (m_drawerName)
                m_drawerName->setText(applicationLabel(row));
            if (m_drawerPublisher)
                m_drawerPublisher->setText(orDash(row.publisher));
            if (m_drawerPath && !row.path.trimmed().isEmpty())
                m_drawerPath->setText(row.path.trimmed());
            if (!row.icon.isNull() && m_drawerIcon) {
                m_drawerIcon->setPixmap(row.icon.pixmap(
                    QSize(32, 32), m_drawerIcon->devicePixelRatioF()));
            }
            if (m_lastActive) {
                m_lastActive->setText(
                    blockedRow(row) ? QStringLiteral("Blocked")
                    : (row.rxBytesPerSecond + row.txBytesPerSecond > 0
                           ? QStringLiteral("now") : QStringLiteral("—")));
            }
            const QString rule = ruleToken(row);
            if (rule != m_details.rule)
                applyDetailsRule(rule);
            break;
        }
    }

    if (selectedPid != 0) {
        for (int row = 0; row < m_model->rowCount(); ++row) {
            if (m_model->rowAt(row).pid != selectedPid)
                continue;
            const QModelIndex index = m_proxy->mapFromSource(m_model->index(row, 0));
            if (index.isValid()) {
                m_table->setCurrentIndex(index);
                m_table->selectionModel()->select(
                    index, QItemSelectionModel::ClearAndSelect
                               | QItemSelectionModel::Rows);
            }
            break;
        }
    }

    // A reset re-lays the view; restore the scroll offset once it has settled.
    QTimer::singleShot(0, m_table, [this, scroll]() {
        m_table->verticalScrollBar()->setValue(scroll);
    });

    refreshFooter();
    refreshEmptyState();
}

void ApplicationsPage::applyFilter(Applications::Filter filter)
{
    m_filter = filter;
    m_proxy->setFilter(filter);
    refreshFooter();
    refreshEmptyState();
}

void ApplicationsPage::applyQuery(const QString &query)
{
    m_proxy->setQuery(query);
    refreshFooter();
    refreshEmptyState();
}

void ApplicationsPage::refreshEmptyState()
{
    const bool empty = m_proxy->rowCount() == 0;
    m_table->setVisible(!empty);
    m_footer->setVisible(!empty);
    m_emptyHost->setVisible(empty);
    if (!empty)
        return;

    if (m_rows.isEmpty()) {
        m_empty->setTitle(QStringLiteral("No applications found"));
        m_empty->setDetail(
            QStringLiteral("Applications appear here once Oasis observes network "
                           "activity. Start monitoring to populate the list."));
    } else {
        m_empty->setTitle(QStringLiteral("No applications found"));
        m_empty->setDetail(
            QStringLiteral("Try adjusting your search or filters."));
    }
}

void ApplicationsPage::refreshFooter()
{
    if (!m_footerCount || !m_legend)
        return;
    const int visible = m_proxy->rowCount();
    const int total = int(m_rows.size());
    if (visible == total) {
        m_footerCount->setText(
            QStringLiteral("%1 %2")
                .arg(total)
                .arg(total == 1 ? QStringLiteral("application")
                                : QStringLiteral("applications")));
    } else {
        m_footerCount->setText(
            QStringLiteral("Showing %1 of %2 applications").arg(visible).arg(total));
    }
    m_legend->setText(legendHtml());
}

void ApplicationsPage::refreshThemeIcons()
{
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
    const QColor primary = Theme::qcolor(palette.textSecondary);
    const QColor muted = Theme::qcolor(palette.textMuted);
    if (m_filterButton)
        m_filterButton->setIcon(glyphIcon(Glyph::Filter, primary));
    if (m_sortButton)
        m_sortButton->setIcon(glyphIcon(Glyph::Sort, primary));
    if (m_moreButton)
        m_moreButton->setIcon(glyphIcon(Glyph::More, primary));
    if (m_searchAction)
        m_searchAction->setIcon(glyphIcon(Glyph::Search, muted));
    if (m_detailsOpen)
        applyDetailsRule(m_details.rule);
}

void ApplicationsPage::showFilterMenu()
{
    QMenu menu(this);
    QActionGroup group(&menu);
    group.setExclusive(true);

    const QList<Applications::Filter> filters = {
        Applications::Filter::All,
        Applications::Filter::Active,
        Applications::Filter::Idle,
        Applications::Filter::AllowRule,
        Applications::Filter::AskRule,
        Applications::Filter::BlockRule
    };
    for (Applications::Filter filter : filters) {
        QAction *action = menu.addAction(Applications::filterLabel(filter));
        action->setCheckable(true);
        action->setChecked(filter == m_filter);
        action->setData(int(filter));
        group.addAction(action);
    }
    connect(&group, &QActionGroup::triggered, this, [this](QAction *action) {
        applyFilter(static_cast<Applications::Filter>(action->data().toInt()));
    });

    menu.exec(m_filterButton->mapToGlobal(
        QPoint(0, m_filterButton->height() + Theme::Dim::SpaceXs)));
}

void ApplicationsPage::showSortMenu()
{
    QHeaderView *header = m_table->horizontalHeader();
    const int currentColumn = header->sortIndicatorSection();
    const Qt::SortOrder currentOrder = header->sortIndicatorOrder();

    QMenu menu(this);
    QActionGroup columnGroup(&menu);
    columnGroup.setExclusive(true);

    const QList<QPair<QString, int>> columns = {
        { QStringLiteral("Application"), ApplicationsPageTableModel::Application },
        { QStringLiteral("Total consumed"), ApplicationsPageTableModel::Total },
        { QStringLiteral("Rule"), ApplicationsPageTableModel::Rule },
        { QStringLiteral("Activity"), ApplicationsPageTableModel::Activity }
    };
    for (const auto &column : columns) {
        QAction *action = menu.addAction(column.first);
        action->setCheckable(true);
        action->setChecked(column.second == currentColumn);
        action->setData(column.second);
        columnGroup.addAction(action);
    }
    connect(&columnGroup, &QActionGroup::triggered, this, [this](QAction *action) {
        m_table->sortByColumn(action->data().toInt(),
                              m_table->horizontalHeader()->sortIndicatorOrder());
    });

    menu.addSeparator();
    QActionGroup orderGroup(&menu);
    orderGroup.setExclusive(true);
    QAction *ascending = menu.addAction(QStringLiteral("Ascending"));
    ascending->setCheckable(true);
    ascending->setChecked(currentOrder == Qt::AscendingOrder);
    orderGroup.addAction(ascending);
    QAction *descending = menu.addAction(QStringLiteral("Descending"));
    descending->setCheckable(true);
    descending->setChecked(currentOrder == Qt::DescendingOrder);
    orderGroup.addAction(descending);
    connect(&orderGroup, &QActionGroup::triggered, this, [this](QAction *action) {
        m_table->sortByColumn(m_table->horizontalHeader()->sortIndicatorSection(),
                              action->text() == QLatin1String("Descending")
                                  ? Qt::DescendingOrder : Qt::AscendingOrder);
    });

    menu.exec(m_sortButton->mapToGlobal(
        QPoint(0, m_sortButton->height() + Theme::Dim::SpaceXs)));
}

void ApplicationsPage::showMoreMenu()
{
    QMenu menu(this);
    QAction *policies = menu.addAction(QStringLiteral("Manage policies"));
    menu.addSeparator();
    QAction *clear = menu.addAction(QStringLiteral("Clear search and filters"));

    QAction *chosen = menu.exec(m_moreButton->mapToGlobal(
        QPoint(0, m_moreButton->height() + Theme::Dim::SpaceXs)));
    if (!chosen)
        return;
    if (chosen == policies) {
        emit policiesRequested();
    } else if (chosen == clear) {
        m_search->clear();
        applyFilter(Applications::Filter::All);
    }
}

void ApplicationsPage::showRuleMenu(const QModelIndex &index)
{
    Applications::Row row;
    if (!rowForIndex(index, &row))
        return;

    m_table->selectRow(index.row());
    const QRect cell = m_table->visualRect(index);
    showRuleMenuFor(row.pid, row.path, row.name, ruleToken(row),
                    m_table->viewport()->mapToGlobal(cell.bottomLeft() + QPoint(0, 2)));
}

void ApplicationsPage::showRuleMenuFor(quint32 pid, const QString &path,
                                       const QString &name, const QString &rule,
                                       const QPoint &globalPos)
{
    QMenu menu(this);
    QActionGroup group(&menu);
    group.setExclusive(true);

    const QString current = rule.trimmed().toLower();
    const QList<QPair<QString, QString>> rules = {
        { QStringLiteral("allow"), QStringLiteral("Allow") },
        { QStringLiteral("ask"), QStringLiteral("Ask") },
        { QStringLiteral("block"), QStringLiteral("Block") }
    };
    for (const auto &entry : rules) {
        QAction *action = menu.addAction(dotIcon(ruleColor(entry.first)), entry.second);
        action->setCheckable(true);
        action->setChecked(current == entry.first);
        action->setData(entry.first);
        group.addAction(action);
    }

    QAction *chosen = menu.exec(globalPos);
    if (!chosen)
        return;
    const QString chosenRule = chosen->data().toString();
    if (m_detailsOpen && m_details.pid == pid)
        applyDetailsRule(chosenRule);
    emit ruleChangeRequested(pid, path, name, chosenRule);
}

bool ApplicationsPage::rowForIndex(const QModelIndex &index, Applications::Row *row) const
{
    if (!row || !index.isValid())
        return false;

    const QModelIndex source = m_proxy->mapToSource(index);
    if (!source.isValid() || source.row() < 0 || source.row() >= m_model->rowCount())
        return false;

    *row = m_model->rowAt(source.row());
    return true;
}

void ApplicationsPage::showContextMenu(const QPoint &pos)
{
    const QModelIndex index = m_table->indexAt(pos);
    Applications::Row row;
    if (!rowForIndex(index, &row))
        return;

    m_table->selectRow(index.row());

    QMenu menu(this);
    QAction *details = menu.addAction(QStringLiteral("Details"));
    QAction *traffic = menu.addAction(QStringLiteral("Manage traffic"));
    QAction *policy = menu.addAction(QStringLiteral("Create policy"));
    menu.addSeparator();
    QAction *activity = menu.addAction(QStringLiteral("Inspect activity"));

    QAction *chosen = menu.exec(m_table->viewport()->mapToGlobal(pos));
    if (!chosen)
        return;

    if (chosen == details)
        emit detailsRequested(row.pid, row.path, row.name);
    else if (chosen == traffic)
        emit trafficRequested(row.pid, row.path, row.name);
    else if (chosen == policy)
        emit policyRequested(row.pid, row.path, row.name);
    else if (chosen == activity)
        emit activityRequested(row.pid, row.path, row.name);
}
