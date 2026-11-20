/**
 * @file    applicationspage_p.h
 * @brief   Private prelude for the Applications page: shared formatting helpers
 *          and the row-model / delegate declarations used by
 *          applicationspage.cpp and applicationspage_models.cpp.
 *
 * Not part of the page's public interface.
 */
#pragma once

#include "applicationspage.h"

#include "ui/theme/colors.h"
#include "ui/theme/dimensions.h"
#include "ui/theme/thememanager.h"
#include "ui/theme/typography.h"

#include <QAbstractTableModel>
#include <QApplication>
#include <QColor>
#include <QFontMetrics>
#include <QIcon>
#include <QList>
#include <QHash>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QSize>
#include <QSortFilterProxyModel>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QVariant>
#include <QVector>

namespace ApplicationsPageDetail {

constexpr int kRowHeight = 64;
constexpr int kIconSize = 32;
constexpr int kSparkPoints = 24;
constexpr int kSparkWidth = 60;

inline QString applicationLabel(const Applications::Row &row)
{
    return row.displayName.trimmed().isEmpty() ? row.name : row.displayName;
}

inline bool blockedRow(const Applications::Row &row)
{
    return row.rule == QLatin1String("block")
           || row.policyToken == QLatin1String("blocked");
}

inline QString ruleToken(const Applications::Row &row)
{
    if (row.rule == QLatin1String("ask")) return QStringLiteral("ask");
    if (blockedRow(row)) return QStringLiteral("block");
    return QStringLiteral("allow");
}

inline QString ruleText(const Applications::Row &row)
{
    const QString token = ruleToken(row);
    if (token == QLatin1String("ask")) return QStringLiteral("Ask");
    if (token == QLatin1String("block")) return QStringLiteral("Block");
    return QStringLiteral("Allow");
}

inline bool matchesFilter(const Applications::Row &row, Applications::Filter filter)
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

/// Row identity across beats. A live pid keeps its row even while the
/// executable metadata is still resolving; rows without an owner all share
/// pid 0, so those fall back to the executable they point at.
inline QString rowIdentity(const Applications::Row &row)
{
    if (row.pid != 0)
        return QStringLiteral("pid:%1").arg(row.pid);
    return QStringLiteral("no-pid:%1|%2").arg(row.name, row.path);
}

inline bool sameRow(const Applications::Row &a, const Applications::Row &b)
{
    return a.pid == b.pid && a.name == b.name && a.displayName == b.displayName
           && a.publisher == b.publisher && a.path == b.path
           && a.icon.cacheKey() == b.icon.cacheKey()
           && a.rxBytesPerSecond == b.rxBytesPerSecond
           && a.txBytesPerSecond == b.txBytesPerSecond && a.totalBytes == b.totalBytes
           && a.activity == b.activity && a.policy == b.policy
           && a.policyToken == b.policyToken && a.identity == b.identity
           && a.rule == b.rule;
}

inline QString initialsFor(const QString &label)
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

inline QColor avatarColor(const QString &name, bool dark)
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

inline QColor ruleColor(const QString &tone)
{
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
    if (tone == QLatin1String("ask"))
        return Theme::qcolor(palette.semanticWarning);
    if (tone == QLatin1String("block"))
        return Theme::qcolor(palette.semanticDanger);
    return Theme::qcolor(palette.semanticSuccess);
}

inline QColor ruleBackground(const QString &tone)
{
    const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
    if (tone == QLatin1String("ask"))
        return Theme::qcolor(palette.warningSubtle);
    if (tone == QLatin1String("block"))
        return Theme::qcolor(palette.dangerSubtle);
    return Theme::qcolor(palette.successSubtle);
}

inline QString ruleLabelForToken(const QString &rule)
{
    const QString token = rule.trimmed().toLower();
    if (token == QLatin1String("ask")) return QStringLiteral("Ask");
    if (token == QLatin1String("block")) return QStringLiteral("Block");
    return QStringLiteral("Allow");
}

inline QString ruleDescriptionForToken(const QString &rule)
{
    const QString token = rule.trimmed().toLower();
    if (token == QLatin1String("ask"))
        return QStringLiteral("Oasis asks before this application connects.");
    if (token == QLatin1String("block"))
        return QStringLiteral("Internet access is blocked.");
    return QStringLiteral("Internet access is allowed.");
}

inline QString cssColor(const QColor &color)
{
    return QStringLiteral("rgba(%1,%2,%3,%4)")
        .arg(color.red())
        .arg(color.green())
        .arg(color.blue())
        .arg(color.alphaF(), 0, 'f', 3);
}

inline void styleRuleButton(QPushButton *button, const QString &rule)
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

inline QString formattedRate(quint64 bytesPerSecond)
{
    if (bytesPerSecond == 0)
        return QStringLiteral("0 B/s");
    return formattedBytes(bytesPerSecond) + QStringLiteral("/s");
}

inline QString formattedBytes(quint64 bytes)
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

inline QString orDash(const QString &text)
{
    return text.trimmed().isEmpty() ? QStringLiteral("—") : text.trimmed();
}

enum class Glyph { Search, Filter, Sort, More };

inline QIcon glyphIcon(Glyph glyph, const QColor &color)
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

inline QIcon dotIcon(const QColor &color)
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

inline QString legendHtml()
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
} // namespace ApplicationsPageDetail

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

    explicit ApplicationsPageTableModel(QObject *parent = nullptr);

    void setRows(const QList<Applications::Row> &rows);
    const Applications::Row &rowAt(int sourceRow) const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

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
                                         QObject *parent = nullptr);

    void setFilter(Applications::Filter filter);
    void setQuery(const QString &query);

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &) const override;
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override;

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
    explicit ApplicationNameDelegate(QObject *parent = nullptr);

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override;
};

class RuleDelegate : public QStyledItemDelegate
{
public:
    explicit RuleDelegate(QObject *parent = nullptr);

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override;
};

class ActivityDelegate : public QStyledItemDelegate
{
public:
    explicit ActivityDelegate(QObject *parent = nullptr);

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override;

private:
    static void paintRate(QPainter *painter, const QRect &row, quint64 rate, bool up,
                          const QColor &color, const QFont &font);
    static void paintSparkline(QPainter *painter, const QRect &area,
                               const QVariantList &samples, const QColor &color,
                               const QColor &emptyColor);
};
