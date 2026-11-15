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
#include <QApplication>
#include <QButtonGroup>
#include <QFontMetrics>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPainter>
#include <QRegularExpression>
#include <QScrollBar>
#include <QSortFilterProxyModel>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace {

QString formatBytes(quint64 bytes)
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

QString formatRate(quint64 bytesPerSecond)
{
    if (bytesPerSecond == 0)
        return QStringLiteral("0 B/s");
    return formatBytes(bytesPerSecond) + QStringLiteral("/s");
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

bool unresolved(const Applications::Row &row)
{
    return row.identity.compare(QStringLiteral("Unknown"), Qt::CaseInsensitive) == 0
           || row.identity.compare(QStringLiteral("Possible"), Qt::CaseInsensitive) == 0
           || row.publisher.trimmed().isEmpty()
           || row.path.trimmed().isEmpty();
}

bool matchesFilter(const Applications::Row &row, Applications::Filter filter)
{
    switch (filter) {
    case Applications::Filter::All:
        return true;
    case Applications::Filter::Active:
        return row.rxBytesPerSecond + row.txBytesPerSecond > 0;
    case Applications::Filter::Background:
        return row.activity.compare(QStringLiteral("Background"), Qt::CaseInsensitive) == 0;
    case Applications::Filter::SystemServices:
        return row.activity.compare(QStringLiteral("System"), Qt::CaseInsensitive) == 0;
    case Applications::Filter::Restricted:
        return row.policyToken.compare(QStringLiteral("none"), Qt::CaseInsensitive) != 0;
    case Applications::Filter::Unresolved:
        return unresolved(row);
    }
    return true;
}

} // namespace

namespace Applications {

QString filterLabel(Filter filter)
{
    switch (filter) {
    case Filter::All:
        return QStringLiteral("All");
    case Filter::Active:
        return QStringLiteral("Active");
    case Filter::Background:
        return QStringLiteral("Background");
    case Filter::SystemServices:
        return QStringLiteral("System services");
    case Filter::Restricted:
        return QStringLiteral("Restricted");
    case Filter::Unresolved:
        return QStringLiteral("Unresolved");
    }
    return QStringLiteral("All");
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
        Publisher,
        Download,
        Upload,
        Total,
        Activity,
        Policy,
        Identity,
        ColumnCount
    };

    enum Role {
        SortRole = Qt::UserRole + 1,
        ToneRole,
        NameRole,
        PublisherRole,
        PidRole
    };

    explicit ApplicationsPageTableModel(QObject *parent = nullptr)
        : QAbstractTableModel(parent)
    {
    }

    void setRows(const QList<Applications::Row> &rows)
    {
        beginResetModel();
        m_rows = rows;
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
                return row.displayName.trimmed().isEmpty() ? row.name : row.displayName;
            case Publisher:
                return row.publisher.trimmed().isEmpty()
                           ? QStringLiteral("Unknown publisher") : row.publisher;
            case Download:
                return formatRate(row.rxBytesPerSecond);
            case Upload:
                return formatRate(row.txBytesPerSecond);
            case Total:
                return formatBytes(row.totalBytes);
            case Activity:
                return row.activity;
            case Policy:
                return row.policy;
            case Identity:
                return row.identity;
            default:
                break;
            }
            break;

        case Qt::TextAlignmentRole:
            if (column == Download || column == Upload || column == Total)
                return int(Qt::AlignRight | Qt::AlignVCenter);
            return int(Qt::AlignLeft | Qt::AlignVCenter);

        case Qt::ForegroundRole: {
            const Theme::Palette palette = Theme::palette(ThemeManager::instance().isDark());
            if (column == Download || column == Upload) {
                const bool active = (column == Download ? row.rxBytesPerSecond
                                                        : row.txBytesPerSecond) > 0;
                return Theme::qcolor(active ? palette.textPrimary : palette.textMuted);
            }
            if (column == Publisher) {
                return Theme::qcolor(row.publisher.trimmed().isEmpty()
                                         ? palette.textSecondary : palette.textPrimary);
            }
            if (column == Policy) {
                if (row.policyToken == QLatin1String("blocked"))
                    return Theme::qcolor(palette.semanticDanger);
                if (row.policyToken == QLatin1String("restricted"))
                    return Theme::qcolor(palette.semanticWarning);
                return Theme::qcolor(palette.textSecondary);
            }
            return Theme::qcolor(palette.textPrimary);
        }

        case Qt::FontRole: {
            QFont font = QApplication::font();
            if (column == Total)
                font.setWeight(QFont::DemiBold);
            else if (column == Publisher && row.publisher.trimmed().isEmpty())
                font.setItalic(true);
            return font;
        }

        case SortRole:
            switch (column) {
            case Application:
                return (row.displayName.trimmed().isEmpty() ? row.name : row.displayName)
                    .toLower();
            case Publisher:
                return row.publisher.trimmed().isEmpty()
                           ? QString(1, QChar(0xFFFF)) : row.publisher.toLower();
            case Download:
                return QVariant::fromValue<qulonglong>(row.rxBytesPerSecond);
            case Upload:
                return QVariant::fromValue<qulonglong>(row.txBytesPerSecond);
            case Total:
                return QVariant::fromValue<qulonglong>(row.totalBytes);
            case Activity:
                return row.activity.toLower();
            case Policy:
                // Blocked outranks throttled, which outranks no policy.
                if (row.policyToken == QLatin1String("blocked")) return QStringLiteral("0");
                if (row.policyToken == QLatin1String("restricted")) return QStringLiteral("1");
                return QStringLiteral("2");
            case Identity:
                return row.identity.toLower();
            default:
                break;
            }
            break;

        case ToneRole:
            if (column == Activity) {
                if (row.activity == QLatin1String("Foreground")) return QStringLiteral("success");
                if (row.activity == QLatin1String("Background")) return QStringLiteral("warning");
                if (row.activity == QLatin1String("System")) return QStringLiteral("info");
                return QStringLiteral("unknown");
            }
            if (column == Identity) {
                if (row.identity == QLatin1String("Confirmed")) return QStringLiteral("success");
                if (row.identity == QLatin1String("Likely")) return QStringLiteral("info");
                if (row.identity == QLatin1String("Possible")) return QStringLiteral("warning");
                return QStringLiteral("unknown");
            }
            break;

        case NameRole:
            return row.name;
        case PublisherRole:
            return row.publisher;
        case PidRole:
            return row.pid;
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
            case Publisher:   return QStringLiteral("Publisher");
            case Download:    return QStringLiteral("Download");
            case Upload:      return QStringLiteral("Upload");
            case Total:       return QStringLiteral("Total");
            case Activity:    return QStringLiteral("Activity");
            case Policy:      return QStringLiteral("Policy");
            case Identity:    return QStringLiteral("Identity");
            default:          return {};
            }
        }
        if (role == Qt::TextAlignmentRole) {
            const bool numeric = section == Download || section == Upload || section == Total;
            return int((numeric ? Qt::AlignRight : Qt::AlignLeft) | Qt::AlignVCenter);
        }
        return {};
    }

private:
    QList<Applications::Row> m_rows;
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
        const QString label = row.displayName.trimmed().isEmpty() ? row.name : row.displayName;
        return label.toLower().contains(needle)
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

        const QRect content = opt.rect.adjusted(Theme::Dim::SpaceMd, 2,
                                                -Theme::Dim::SpaceMd, -2);
        const int tileSize = 22;
        const QRect tile(content.left(), content.center().y() - tileSize / 2,
                         tileSize, tileSize);

        const QColor accent = avatarColor(name, dark);
        QColor tileFill = accent;
        tileFill.setAlpha(dark ? 38 : 24);

        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setPen(QPen(QColor(accent.red(), accent.green(), accent.blue(), 130), 1));
        painter->setBrush(tileFill);
        painter->drawRoundedRect(QRectF(tile).adjusted(0.5, 0.5, -0.5, -0.5), 6, 6);

        QFont initials = opt.font;
        initials.setPixelSize(Theme::Type::Metadata - 1);
        initials.setWeight(QFont::DemiBold);
        painter->setFont(initials);
        painter->setPen(accent);
        painter->drawText(tile, Qt::AlignCenter,
                          initialsFor(label.isEmpty() ? name : label));

        const int textLeft = tile.right() + Theme::Dim::SpaceSm + 2;
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

        const QString friendly = primaryMetrics.elidedText(
            label, Qt::ElideRight, textWidth);
        const QString subtitleSource =
            (label.compare(name, Qt::CaseInsensitive) != 0)
                ? name
                : (publisher.trimmed().isEmpty() ? QStringLiteral("Publisher unknown")
                                                 : publisher);
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
        return QSize(240, Theme::Dim::RowStandard);
    }
};

class BadgeDelegate : public QStyledItemDelegate
{
public:
    explicit BadgeDelegate(QObject *parent = nullptr)
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

        const QString text = index.data(Qt::DisplayRole).toString();
        if (text.isEmpty())
            return;

        const bool dark = ThemeManager::instance().isDark();
        const Theme::Palette palette = Theme::palette(dark);
        const QString tone = index.data(ApplicationsPageTableModel::ToneRole).toString();

        QColor foreground = Theme::qcolor(palette.textSecondary);
        QColor background = Theme::qcolor(palette.surfaceHover);
        if (tone == QLatin1String("success")) {
            foreground = Theme::qcolor(palette.semanticSuccess);
            background = Theme::qcolor(palette.successSubtle);
        } else if (tone == QLatin1String("warning")) {
            foreground = Theme::qcolor(palette.semanticWarning);
            background = Theme::qcolor(palette.warningSubtle);
        } else if (tone == QLatin1String("danger")) {
            foreground = Theme::qcolor(palette.semanticDanger);
            background = Theme::qcolor(palette.dangerSubtle);
        } else if (tone == QLatin1String("info")) {
            foreground = Theme::qcolor(palette.semanticInfo);
            background = Theme::qcolor(palette.infoSubtle);
        }

        QFont font = opt.font;
        font.setPixelSize(Theme::Type::Metadata);
        font.setWeight(QFont::DemiBold);
        const QFontMetrics metrics(font);

        const int dot = 6;
        const int gap = 6;
        const int padding = Theme::Dim::SpaceSm;
        const int height = Theme::Dim::BadgeHeight;
        const int width = padding * 2 + dot + gap + metrics.horizontalAdvance(text);

        QRect pill(opt.rect.left() + Theme::Dim::SpaceMd,
                   opt.rect.center().y() - height / 2, width, height);
        if (pill.right() > opt.rect.right() - Theme::Dim::SpaceSm)
            pill.setRight(opt.rect.right() - Theme::Dim::SpaceSm);

        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setPen(Qt::NoPen);
        painter->setBrush(background);
        painter->drawRoundedRect(pill, Theme::Dim::RadiusBadge, Theme::Dim::RadiusBadge);

        painter->setBrush(foreground);
        painter->drawEllipse(QRect(pill.left() + padding,
                                   pill.center().y() - dot / 2, dot, dot));

        painter->setFont(font);
        painter->setPen(foreground);
        painter->drawText(QRect(pill.left() + padding + dot + gap, pill.top(),
                                pill.width() - padding * 2 - dot - gap, pill.height()),
                          Qt::AlignLeft | Qt::AlignVCenter, text);
        painter->restore();
    }

    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override
    {
        QFont font = option.font;
        font.setPixelSize(Theme::Type::Metadata);
        font.setWeight(QFont::DemiBold);
        const QFontMetrics metrics(font);
        return QSize(metrics.horizontalAdvance(index.data(Qt::DisplayRole).toString())
                         + Theme::Dim::SpaceMd * 2 + 6 + 6 + Theme::Dim::SpaceSm * 2,
                     Theme::Dim::RowStandard);
    }
};

// ============================================================================
// Page
// ============================================================================

ApplicationsPage::ApplicationsPage(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("applicationsPage"));

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(Theme::Dim::PagePaddingH, Theme::Dim::PagePaddingV,
                               Theme::Dim::PagePaddingH, Theme::Dim::PagePaddingV);
    layout->setSpacing(Theme::Dim::SpaceLg);

    // ── Toolbar: search + filter pills ─────────────────────────────────────
    auto *toolbar = new QWidget(this);
    auto *toolbarLayout = new QHBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(Theme::Dim::SpaceMd);

    m_search = new QLineEdit(toolbar);
    m_search->setPlaceholderText(QStringLiteral("Search applications…"));
    m_search->setClearButtonEnabled(true);
    m_search->setMinimumWidth(220);
    m_search->setMaximumWidth(320);
    m_search->setFixedHeight(Theme::Dim::InputHeight);
    m_search->setAccessibleName(QStringLiteral("Search applications"));
    toolbarLayout->addWidget(m_search);

    auto *group = new QButtonGroup(this);
    group->setExclusive(true);
    const QList<Applications::Filter> filters = {
        Applications::Filter::All,
        Applications::Filter::Active,
        Applications::Filter::Background,
        Applications::Filter::SystemServices,
        Applications::Filter::Restricted,
        Applications::Filter::Unresolved
    };
    for (Applications::Filter filter : filters) {
        auto *button = new QToolButton(toolbar);
        button->setProperty("uiRole", QStringLiteral("filterPill"));
        button->setCheckable(true);
        button->setCursor(Qt::PointingHandCursor);
        group->addButton(button, int(filter));
        toolbarLayout->addWidget(button);
        m_filterButtons.append(button);
    }
    m_filterButtons.value(0)->setChecked(true);
    toolbarLayout->addStretch(1);

    connect(group, &QButtonGroup::idClicked, this, [this](int id) {
        applyFilter(static_cast<Applications::Filter>(id));
    });
    connect(m_search, &QLineEdit::textChanged, this, &ApplicationsPage::applyQuery);

    layout->addWidget(toolbar);

    // ── Table ───────────────────────────────────────────────────────────────
    m_model = new ApplicationsPageTableModel(this);
    m_proxy = new ApplicationsPageFilterModel(m_model, this);

    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSortingEnabled(true);
    m_table->sortByColumn(ApplicationsPageTableModel::Total, Qt::DescendingOrder);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setShowGrid(false);
    m_table->setWordWrap(false);
    m_table->setFrameShape(QFrame::NoFrame);
    m_table->setAlternatingRowColors(false);
    m_table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_table->verticalHeader()->hide();
    m_table->verticalHeader()->setDefaultSectionSize(Theme::Dim::RowStandard);
    m_table->verticalHeader()->setMinimumSectionSize(Theme::Dim::RowStandard);
    m_table->setItemDelegateForColumn(ApplicationsPageTableModel::Application,
                                      new ApplicationNameDelegate(m_table));
    m_table->setItemDelegateForColumn(ApplicationsPageTableModel::Activity,
                                      new BadgeDelegate(m_table));
    m_table->setItemDelegateForColumn(ApplicationsPageTableModel::Identity,
                                      new BadgeDelegate(m_table));

    QHeaderView *header = m_table->horizontalHeader();
    header->setStretchLastSection(false);
    header->setHighlightSections(false);
    header->setSectionsClickable(true);
    header->setMinimumSectionSize(72);
    header->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    header->setSectionResizeMode(ApplicationsPageTableModel::Application,
                                 QHeaderView::Stretch);
    header->setSectionResizeMode(ApplicationsPageTableModel::Publisher,
                                 QHeaderView::Stretch);
    for (int column = ApplicationsPageTableModel::Download;
         column < ApplicationsPageTableModel::ColumnCount; ++column) {
        header->setSectionResizeMode(column, QHeaderView::ResizeToContents);
    }
    // Row actions live on the row, not in the row: a right-click menu and the
    // spec's double-click shortcut, both routed through the shell's existing
    // detail, throttle and policy entry points.
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QTableView::customContextMenuRequested,
            this, &ApplicationsPage::showContextMenu);
    connect(m_table, &QTableView::doubleClicked, this, [this](const QModelIndex &index) {
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

    // ── Footer ──────────────────────────────────────────────────────────────
    m_footer = new QWidget(this);
    auto *footerLayout = new QHBoxLayout(m_footer);
    footerLayout->setContentsMargins(Theme::Dim::SpaceXs, 0,
                                     Theme::Dim::SpaceXs, 0);
    m_footerCount = new QLabel(m_footer);
    m_footerCount->setProperty("uiRole", QStringLiteral("muted"));
    footerLayout->addWidget(m_footerCount);
    footerLayout->addStretch(1);
    auto *hint = new QLabel(QStringLiteral("Live · updates every second"), m_footer);
    hint->setProperty("uiRole", QStringLiteral("muted"));
    footerLayout->addWidget(hint);
    layout->addWidget(m_footer);

    refreshCounts();
    refreshFooter();
    refreshEmptyState();
}

void ApplicationsPage::setRows(const QList<Applications::Row> &rows)
{
    quint32 selectedPid = 0;
    if (m_table->currentIndex().isValid())
        selectedPid = m_table->currentIndex().data(ApplicationsPageTableModel::PidRole).toUInt();
    const int scroll = m_table->verticalScrollBar()->value();

    m_rows = rows;
    m_model->setRows(rows);
    refreshCounts();

    if (selectedPid != 0) {
        for (int row = 0; row < m_model->rowCount(); ++row) {
            if (m_model->rowAt(row).pid != selectedPid)
                continue;
            const QModelIndex index = m_proxy->mapFromSource(
                m_model->index(row, 0));
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

int ApplicationsPage::applicationCount() const
{
    return int(m_rows.size());
}

int ApplicationsPage::visibleApplicationCount() const
{
    return m_proxy->rowCount();
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

void ApplicationsPage::refreshCounts()
{
    Applications::Counts counts;
    for (const Applications::Row &row : m_rows) {
        ++counts.all;
        if (row.rxBytesPerSecond + row.txBytesPerSecond > 0)
            ++counts.active;
        if (row.activity == QLatin1String("Background"))
            ++counts.background;
        if (row.activity == QLatin1String("System"))
            ++counts.systemServices;
        if (row.policyToken != QLatin1String("none"))
            ++counts.restricted;
        if (unresolved(row))
            ++counts.unresolved;
    }

    const QList<int> values = {
        counts.all, counts.active, counts.background,
        counts.systemServices, counts.restricted, counts.unresolved
    };
    for (int i = 0; i < m_filterButtons.size() && i < values.size(); ++i) {
        const Applications::Filter filter = static_cast<Applications::Filter>(i);
        m_filterButtons.at(i)->setText(
            QStringLiteral("%1 · %2").arg(Applications::filterLabel(filter))
                                     .arg(values.at(i)));
    }
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
        m_empty->setTitle(QStringLiteral("No applications yet"));
        m_empty->setDetail(
            QStringLiteral("Applications appear here once Oasis observes network "
                           "activity. Start monitoring to populate the list."));
    } else {
        m_empty->setTitle(QStringLiteral("No matching applications"));
        m_empty->setDetail(
            QStringLiteral("No application matches this search and filter. "
                           "Clear the search or choose another filter."));
    }
}

void ApplicationsPage::refreshFooter()
{
    if (!m_footerCount)
        return;
    const int visible = m_proxy->rowCount();
    const int total = int(m_rows.size());
    m_footerCount->setText(
        QStringLiteral("Showing %1 of %2 %3")
            .arg(visible)
            .arg(total)
            .arg(total == 1 ? QStringLiteral("application")
                            : QStringLiteral("applications")));
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
