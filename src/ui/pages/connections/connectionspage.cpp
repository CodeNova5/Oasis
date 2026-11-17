/**
 * @file    connectionspage.cpp
 * @author  Oasis
 */
#include "connectionspage.h"

#include "ui/components/emptystatewidget.h"
#include "ui/theme/colors.h"
#include "ui/theme/thememanager.h"

#include <QAbstractTableModel>
#include <QBrush>
#include <QButtonGroup>
#include <QColor>
#include <QComboBox>
#include <QFont>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLayoutItem>
#include <QLineEdit>
#include <QPainter>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QScrollBar>
#include <QSizePolicy>
#include <QSortFilterProxyModel>
#include <QStackedWidget>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QTableView>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace {

enum Column {
    Destination = 0,
    Application,
    PortProtocol,
    Evidence,
    Rate,
    Data,
    Confidence,
    ColumnCount
};

enum Role {
    SortRole = Qt::UserRole + 1,
    IdRole,
    PidRole,
    PathRole,
    NameRole
};

QString applicationLabel(const Connections::Row &row)
{
    return row.displayName.trimmed().isEmpty() ? row.appName : row.displayName;
}

QFont tabularFont(QFont font)
{
    font.setFeature(QFont::Tag("tnum"), 1);
    return font;
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

QString badgeStatusFor(int confidenceRank)
{
    switch (confidenceRank) {
    case 3: return QStringLiteral("active");
    case 2: return QStringLiteral("pending");
    case 1: return QStringLiteral("degraded");
    default: break;
    }
    return QStringLiteral("unknown");
}

QString evidenceForRow(const Connections::Row &row)
{
    QStringList lines;
    lines << QStringLiteral("%1 · %2").arg(row.evidenceLabel, row.confidence);
    QStringList seen;
    for (const Connections::Endpoint &endpoint : row.endpoints) {
        for (const QString &line : endpoint.evidence) {
            if (!seen.contains(line)) {
                seen.append(line);
                lines << QStringLiteral("• %1").arg(line);
            }
        }
    }
    if (seen.isEmpty()) {
        lines << (row.hasDomain
                      ? QStringLiteral("The name was observed without a recorded evidence detail.")
                      : QStringLiteral("No DNS answer or visible TLS SNI named this destination. "
                                       "Reverse-DNS guessing is disabled."));
    }
    return lines.join(QLatin1Char('\n'));
}

QLabel *addKeyValue(QGridLayout *grid, int row, int column,
                    const QString &caption, QWidget *parent)
{
    auto *box = new QFrame(parent);
    box->setProperty("uiRole", QStringLiteral("elevated"));
    auto *layout = new QVBoxLayout(box);
    layout->setContentsMargins(10, 8, 10, 8);
    layout->setSpacing(2);

    auto *captionLabel = new QLabel(caption, box);
    captionLabel->setProperty("uiRole", QStringLiteral("muted"));

    auto *valueLabel = new QLabel(QStringLiteral("—"), box);
    valueLabel->setProperty("uiRole", QStringLiteral("rowValue"));
    valueLabel->setWordWrap(true);
    valueLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    valueLabel->setFont(tabularFont(valueLabel->font()));

    layout->addWidget(captionLabel);
    layout->addWidget(valueLabel);
    grid->addWidget(box, row, column);
    return valueLabel;
}

void repolish(QWidget *widget)
{
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
}

void clearLayout(QLayout *layout)
{
    while (QLayoutItem *item = layout->takeAt(0)) {
        if (QWidget *widget = item->widget())
            widget->deleteLater();
        delete item;
    }
}

} // namespace

// ─── Table model ────────────────────────────────────────────────────────────
class ConnectionsTableModel : public QAbstractTableModel
{
public:
    explicit ConnectionsTableModel(QObject *parent = nullptr)
        : QAbstractTableModel(parent)
    {
    }

    void setGroups(const QList<Connections::Row> &groups)
    {
        beginResetModel();
        m_rows = groups;
        endResetModel();
    }

    const Connections::Row &rowAt(int row) const { return m_rows.at(row); }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : int(m_rows.size());
    }

    int columnCount(const QModelIndex &parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : int(ColumnCount);
    }

    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override
    {
        if (orientation != Qt::Horizontal)
            return {};
        if (role == Qt::TextAlignmentRole
            && (section == Rate || section == Data)) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        if (role != Qt::DisplayRole)
            return {};
        switch (section) {
        case Destination:    return QStringLiteral("Domain / Destination");
        case Application:    return QStringLiteral("Application");
        case PortProtocol:   return QStringLiteral("Port / Protocol");
        case Evidence:       return QStringLiteral("Evidence");
        case Rate:           return QStringLiteral("Current rate");
        case Data:           return QStringLiteral("Data");
        case Confidence:     return QStringLiteral("Confidence");
        default: break;
        }
        return {};
    }

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override
    {
        if (!index.isValid() || index.row() < 0 || index.row() >= m_rows.size())
            return {};

        const Connections::Row &row = m_rows.at(index.row());
        const int column = index.column();

        switch (role) {
        case Qt::DisplayRole:
            switch (column) {
            case Destination:   return row.destination;
            case Application:   return applicationLabel(row);
            case PortProtocol:  return row.ports;
            case Evidence:      return row.evidenceLabel;
            case Rate:          return Connections::formatRate(row.bytesPerSecond());
            case Data:          return Connections::formatBytes(row.totalBytes());
            case Confidence:    return row.confidence;
            default: break;
            }
            break;

        case Qt::DecorationRole:
            if (column == Application && !row.icon.isNull())
                return row.icon;
            break;

        case Qt::ToolTipRole:
            switch (column) {
            case Destination:
                if (row.hasDomain) {
                    return row.domainNames.size() > 1
                        ? QStringLiteral("Observed names: %1").arg(
                              row.domainNames.join(QStringLiteral(", ")))
                        : QStringLiteral("Observed hostname: %1").arg(row.domainNames.join(QString()));
                }
                return QStringLiteral("No verified hostname. Reverse-DNS guessing is disabled.");
            case Application:
                return row.path.trimmed().isEmpty() ? row.appName : row.path;
            case PortProtocol:
                return QStringLiteral("%1 endpoint(s)").arg(row.endpointCount);
            case Evidence:
                return evidenceForRow(row);
            case Rate:
                return QStringLiteral("Download %1 · Upload %2")
                    .arg(Connections::formatRate(row.rxBytesPerSecond),
                         Connections::formatRate(row.txBytesPerSecond));
            case Data:
                return QStringLiteral("Downloaded %1 · Uploaded %2")
                    .arg(Connections::formatBytes(row.rxBytes),
                         Connections::formatBytes(row.txBytes));
            default:
                break;
            }
            break;

        case Qt::TextAlignmentRole:
            if (column == Rate || column == Data)
                return int(Qt::AlignRight | Qt::AlignVCenter);
            return int(Qt::AlignLeft | Qt::AlignVCenter);

        case Qt::FontRole:
            if (column == Destination) {
                QFont font = tabularFont(QFont());
                font.setBold(row.hasDomain);
                font.setItalic(!row.hasDomain);
                return font;
            }
            if (column == PortProtocol || column == Rate || column == Data)
                return tabularFont(QFont());
            break;

        case Qt::ForegroundRole:
            if (column == Confidence) {
                const Theme::Palette palette =
                    Theme::palette(ThemeManager::instance().isDark());
                switch (row.confidenceRank) {
                case 3: return QBrush(Theme::qcolor(palette.semanticSuccess));
                case 2: return QBrush(Theme::qcolor(palette.semanticInfo));
                case 1: return QBrush(Theme::qcolor(palette.semanticWarning));
                default: break;
                }
                return QBrush(Theme::qcolor(palette.textMuted));
            }
            break;

        case SortRole:
            switch (column) {
            case Destination:  return row.destination.toLower();
            case Application:  return applicationLabel(row).toLower();
            case PortProtocol: {
                quint16 port = 0;
                for (const Connections::Endpoint &endpoint : row.endpoints) {
                    if (port == 0 || endpoint.port < port)
                        port = endpoint.port;
                }
                return int(port);
            }
            case Evidence:     return row.confidenceRank;
            case Rate:         return QVariant::fromValue<qulonglong>(row.bytesPerSecond());
            case Data:         return QVariant::fromValue<qulonglong>(row.totalBytes());
            case Confidence:   return row.confidenceRank;
            default: break;
            }
            break;

        case IdRole:   return row.id;
        case PidRole:  return row.pid;
        case PathRole: return row.path;
        case NameRole: return row.appName;
        default:
            break;
        }
        return {};
    }

private:
    QList<Connections::Row> m_rows;
};

// ─── Filter proxy ───────────────────────────────────────────────────────────
class ConnectionsFilterProxy : public QSortFilterProxyModel
{
public:
    explicit ConnectionsFilterProxy(QObject *parent = nullptr)
        : QSortFilterProxyModel(parent)
    {
        setDynamicSortFilter(true);
        setSortRole(SortRole);
    }

    void setConnectionFilter(Connections::Filter filter)
    {
        if (m_filter == filter)
            return;
        m_filter = filter;
        invalidate();
    }

    void setSourceKey(const QString &key)
    {
        if (m_sourceKey == key)
            return;
        m_sourceKey = key;
        invalidate();
    }

    void setQuery(const QString &query)
    {
        if (m_query == query)
            return;
        m_query = query;
        invalidate();
    }

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &) const override
    {
        const auto *model = static_cast<const ConnectionsTableModel *>(sourceModel());
        if (!model || sourceRow < 0 || sourceRow >= model->rowCount())
            return false;
        const Connections::Row &row = model->rowAt(sourceRow);
        return Connections::matchesFilter(row, m_filter)
               && Connections::matchesSource(row, m_sourceKey)
               && Connections::matchesQuery(row, m_query);
    }

private:
    Connections::Filter m_filter = Connections::Filter::All;
    QString m_sourceKey = QStringLiteral("all");
    QString m_query;
};

// A QSS ::item border applies to every cell, so the row's accent bar is drawn
// once, on the first column, after the standard item painting.
class ConnectionRowDelegate : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
    {
        QStyleOptionViewItem opt(option);
        initStyleOption(&opt, index);
        QStyledItemDelegate::paint(painter, opt, index);

        if (index.column() == 0 && (opt.state & QStyle::State_Selected)) {
            painter->save();
            painter->setPen(Qt::NoPen);
            painter->setBrush(QColor(76, 141, 255));
            painter->drawRect(QRect(opt.rect.left(), opt.rect.top(), 2,
                                    opt.rect.height()));
            painter->restore();
        }
    }
};

// ─── Page ───────────────────────────────────────────────────────────────────
ConnectionsPage::ConnectionsPage(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("connectionsPage"));

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(24, 12, 24, 16);
    root->setSpacing(12);

    buildBanner(root);
    buildToolbar(root);
    buildDrawer(this);
    buildTable(root);

    clearDrawer();
    refreshPills();
    refreshBanner();
    refreshFooter();
    refreshEmptyState();
}

void ConnectionsPage::buildBanner(QVBoxLayout *root)
{
    m_banner = new QFrame(this);
    m_banner->setProperty("uiRole", QStringLiteral("banner"));
    m_banner->setProperty("severity", QStringLiteral("info"));

    auto *layout = new QHBoxLayout(m_banner);
    layout->setContentsMargins(12, 6, 8, 6);
    layout->setSpacing(8);

    m_bannerText = new QLabel(m_banner);
    m_bannerText->setWordWrap(true);
    m_bannerText->setProperty("uiRole", QStringLiteral("secondary"));

    m_bannerAction = new QPushButton(QStringLiteral("Show IP-only"), m_banner);
    m_bannerAction->setProperty("uiRole", QStringLiteral("link"));
    m_bannerAction->setCursor(Qt::PointingHandCursor);

    auto *dismiss = new QPushButton(QStringLiteral("×"), m_banner);
    dismiss->setProperty("uiRole", QStringLiteral("link"));
    dismiss->setCursor(Qt::PointingHandCursor);
    dismiss->setFixedSize(24, 24);
    dismiss->setStyleSheet(QStringLiteral("text-align: center; padding: 0;"));
    dismiss->setToolTip(QStringLiteral("Dismiss this notice"));

    layout->addWidget(m_bannerText, 1);
    layout->addWidget(m_bannerAction, 0, Qt::AlignVCenter);
    layout->addWidget(dismiss, 0, Qt::AlignVCenter);
    m_banner->hide();
    root->addWidget(m_banner);

    connect(m_bannerAction, &QPushButton::clicked, this, [this]() {
        setFilter(Connections::Filter::IpAddresses);
    });
    connect(dismiss, &QPushButton::clicked, this, [this]() {
        m_bannerDismissed = true;
        m_banner->hide();
    });
}

void ConnectionsPage::buildToolbar(QVBoxLayout *root)
{
    auto *toolbar = new QHBoxLayout(this);
    toolbar->setSpacing(8);

    m_search = new QLineEdit(this);
    m_search->setPlaceholderText(QStringLiteral("Search domain, IP, or app..."));
    m_search->setClearButtonEnabled(true);
    m_search->setMinimumWidth(280);
    m_search->setMaximumWidth(360);
    toolbar->addWidget(m_search);

    m_pillGroup = new QButtonGroup(this);
    m_pillGroup->setExclusive(true);
    const Connections::Filter filters[] = {
        Connections::Filter::All,
        Connections::Filter::Domains,
        Connections::Filter::IpAddresses,
        Connections::Filter::Unknown
    };
    for (Connections::Filter filter : filters) {
        auto *button = new QToolButton(this);
        button->setText(Connections::filterLabel(filter));
        button->setCheckable(true);
        button->setAutoRaise(true);
        button->setCursor(Qt::PointingHandCursor);
        button->setProperty("uiRole", QStringLiteral("filterPill"));
        m_pillGroup->addButton(button, int(filter));
        toolbar->addWidget(button);
    }
    if (QAbstractButton *all = m_pillGroup->button(int(Connections::Filter::All)))
        all->setChecked(true);

    toolbar->addStretch(1);

    m_source = new QComboBox(this);
    m_source->addItem(QStringLiteral("All attribution sources"), QStringLiteral("all"));
    m_source->addItem(QStringLiteral("DNS + TLS"), QStringLiteral("dns+tls"));
    m_source->addItem(QStringLiteral("DNS only"), QStringLiteral("dns"));
    m_source->addItem(QStringLiteral("TLS SNI only"), QStringLiteral("tls"));
    m_source->addItem(QStringLiteral("No name (IP only)"), QStringLiteral("none"));
    m_source->setMinimumWidth(190);
    toolbar->addWidget(m_source);

    m_refreshButton = new QPushButton(QStringLiteral("Refresh"), this);
    m_refreshButton->setProperty("variant", QStringLiteral("ghost"));
    toolbar->addWidget(m_refreshButton);

    root->addLayout(toolbar);

    connect(m_search, &QLineEdit::textChanged, this, [this](const QString &) {
        applyFilters();
    });
    connect(m_pillGroup, &QButtonGroup::idClicked, this, [this](int id) {
        setFilter(static_cast<Connections::Filter>(id));
    });
    connect(m_source, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int) { applyFilters(); });
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        emit refreshRequested();
    });
}

void ConnectionsPage::buildTable(QVBoxLayout *root)
{
    m_stack = new QStackedWidget(this);

    m_tableCard = new QFrame(this);
    m_tableCard->setProperty("uiRole", QStringLiteral("card"));
    auto *cardLayout = new QVBoxLayout(m_tableCard);
    cardLayout->setContentsMargins(0, 0, 0, 0);
    cardLayout->setSpacing(0);

    m_model = new ConnectionsTableModel(this);
    m_proxy = new ConnectionsFilterProxy(this);
    m_proxy->setSourceModel(m_model);

    m_table = new QTableView(m_tableCard);
    m_table->setObjectName(QStringLiteral("connectionsTable"));
    m_table->setModel(m_proxy);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->setWordWrap(false);
    m_table->setSortingEnabled(true);
    m_table->setIconSize(QSize(18, 18));
    m_table->setTextElideMode(Qt::ElideRight);
    m_table->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_table->setFont(tabularFont(m_table->font()));
    m_table->setItemDelegate(new ConnectionRowDelegate(m_table));
    m_table->setStyleSheet(QStringLiteral(
        "QTableView#connectionsTable::item:hover {"
        " background-color: rgba(76, 141, 255, 7%); }"
        "QTableView#connectionsTable::item:selected {"
        " background-color: rgba(76, 141, 255, 14%); }"));
    m_table->verticalHeader()->hide();
    m_table->verticalHeader()->setDefaultSectionSize(40);
    QHeaderView *header = m_table->horizontalHeader();
    header->setHighlightSections(false);
    header->setMinimumSectionSize(90);
    header->setSectionResizeMode(Destination, QHeaderView::Stretch);
    header->setSectionResizeMode(Application, QHeaderView::Interactive);
    header->setSectionResizeMode(PortProtocol, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(Evidence, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(Rate, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(Data, QHeaderView::ResizeToContents);
    header->setSectionResizeMode(Confidence, QHeaderView::ResizeToContents);
    header->resizeSection(Application, 170);
    m_table->sortByColumn(Rate, Qt::DescendingOrder);
    cardLayout->addWidget(m_table, 1);

    auto *footer = new QFrame(m_tableCard);
    auto *footerLayout = new QHBoxLayout(footer);
    footerLayout->setContentsMargins(12, 8, 12, 8);
    footerLayout->setSpacing(8);

    m_footerCount = new QLabel(QStringLiteral("0 destinations"), footer);
    m_footerCount->setProperty("uiRole", QStringLiteral("muted"));

    m_footerNote = new QLabel(
        QStringLiteral("Unverified domains are never guessed via reverse-DNS"),
        footer);
    m_footerNote->setProperty("uiRole", QStringLiteral("muted"));

    footerLayout->addWidget(m_footerCount);
    footerLayout->addStretch(1);
    footerLayout->addWidget(m_footerNote);
    cardLayout->addWidget(footer);

    m_stack->addWidget(m_tableCard);

    m_empty = new EmptyStateWidget(m_stack);
    m_stack->addWidget(m_empty);
    m_stack->setCurrentWidget(m_tableCard);

    connect(m_empty, &EmptyStateWidget::actionTriggered, this, [this]() {
        if (m_emptyFiltered)
            clearFilters();
        else
            emit refreshRequested();
    });

    connect(m_table->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex &current, const QModelIndex &) {
        if (!current.isValid()) {
            clearDrawer();
            return;
        }
        const QModelIndex source = m_proxy->mapToSource(current);
        if (!source.isValid()) {
            clearDrawer();
            return;
        }
        showRow(m_model->rowAt(source.row()));
    });

    connect(m_table, &QTableView::doubleClicked, this,
            [this](const QModelIndex &index) {
        const QModelIndex source = m_proxy->mapToSource(index);
        if (!source.isValid())
            return;
        const Connections::Row &row = m_model->rowAt(source.row());
        emit detailsRequested(row.pid, row.path, row.appName);
    });

    auto *split = new QHBoxLayout;
    split->setSpacing(16);
    split->addWidget(m_stack, 1);
    split->addWidget(m_drawer, 0);
    root->addLayout(split, 1);
}

void ConnectionsPage::buildDrawer(QWidget *parent)
{
    m_drawer = new QFrame(parent);
    m_drawer->setProperty("uiRole", QStringLiteral("card"));
    m_drawer->setFixedWidth(410);

    auto *layout = new QVBoxLayout(m_drawer);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto *header = new QWidget(m_drawer);
    auto *headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(16, 14, 16, 12);
    headerLayout->setSpacing(8);

    m_drawerTitle = new QLabel(QStringLiteral("Connection Inspector"), header);
    m_drawerTitle->setProperty("uiRole", QStringLiteral("cardHeading"));
    m_drawerTitle->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_drawerTitle->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_drawerTitle->setFont(tabularFont(m_drawerTitle->font()));

    m_drawerBadge = new QLabel(QStringLiteral("No selection"), header);
    m_drawerBadge->setProperty("uiRole", QStringLiteral("badge"));
    m_drawerBadge->setProperty("status", QStringLiteral("unknown"));
    m_drawerBadge->setAlignment(Qt::AlignCenter);

    headerLayout->addWidget(m_drawerTitle, 1);
    headerLayout->addWidget(m_drawerBadge, 0, Qt::AlignTop);
    layout->addWidget(header);

    auto *divider = new QFrame(m_drawer);
    divider->setProperty("uiRole", QStringLiteral("divider"));
    layout->addWidget(divider);

    auto *scroll = new QScrollArea(m_drawer);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    auto *body = new QWidget(scroll);
    auto *bodyLayout = new QVBoxLayout(body);
    bodyLayout->setContentsMargins(16, 14, 16, 14);
    bodyLayout->setSpacing(12);

    auto addSection = [body, bodyLayout](const QString &title) {
        auto *label = new QLabel(title, body);
        label->setProperty("uiRole", QStringLiteral("kpiLabel"));
        bodyLayout->addWidget(label);
    };

    // Parent application
    addSection(QStringLiteral("Application"));
    auto *appCard = new QFrame(body);
    appCard->setProperty("uiRole", QStringLiteral("elevated"));
    auto *appLayout = new QHBoxLayout(appCard);
    appLayout->setContentsMargins(10, 10, 10, 10);
    appLayout->setSpacing(10);

    m_appIcon = new QLabel(appCard);
    m_appIcon->setFixedSize(32, 32);
    m_appIcon->setAlignment(Qt::AlignCenter);
    m_appIcon->setProperty("uiRole", QStringLiteral("avatar"));

    auto *appText = new QVBoxLayout;
    appText->setContentsMargins(0, 0, 0, 0);
    appText->setSpacing(2);
    m_appName = new QLabel(QStringLiteral("No connection selected"), appCard);
    m_appName->setProperty("uiRole", QStringLiteral("rowTitle"));
    m_appName->setWordWrap(true);
    m_appMeta = new QLabel(
        QStringLiteral("Select a row to inspect its destination and evidence."),
        appCard);
    m_appMeta->setProperty("uiRole", QStringLiteral("muted"));
    m_appMeta->setWordWrap(true);
    appText->addWidget(m_appName);
    appText->addWidget(m_appMeta);

    appLayout->addWidget(m_appIcon, 0, Qt::AlignTop);
    appLayout->addLayout(appText, 1);
    bodyLayout->addWidget(appCard);

    // Evidence sits above the destination details so the reason a name is
    // Confirmed, Possible or Unknown is visible without scrolling.
    addSection(QStringLiteral("Attribution source & evidence"));
    auto *evidenceCard = new QFrame(body);
    evidenceCard->setProperty("uiRole", QStringLiteral("elevated"));
    auto *evidenceLayout = new QVBoxLayout(evidenceCard);
    evidenceLayout->setContentsMargins(12, 10, 12, 10);
    evidenceLayout->setSpacing(4);
    m_evidenceTitle = new QLabel(QStringLiteral("Attribution evidence"), evidenceCard);
    m_evidenceTitle->setProperty("uiRole", QStringLiteral("rowTitle"));
    m_evidenceTitle->setWordWrap(true);
    m_evidenceDetail = new QLabel(
        QStringLiteral("Select a connection to see how its name was established."),
        evidenceCard);
    m_evidenceDetail->setProperty("uiRole", QStringLiteral("muted"));
    m_evidenceDetail->setWordWrap(true);
    m_evidenceDetail->setTextInteractionFlags(Qt::TextSelectableByMouse);
    evidenceLayout->addWidget(m_evidenceTitle);
    evidenceLayout->addWidget(m_evidenceDetail);
    bodyLayout->addWidget(evidenceCard);

    // Destination: the drawer title is the hostname (or raw IP), so one
    // Endpoint value replaces the duplicate Hostname and Remote IP boxes.
    addSection(QStringLiteral("Destination"));
    auto *destinationCard = new QFrame(body);
    destinationCard->setProperty("uiRole", QStringLiteral("card"));
    auto *destinationGrid = new QGridLayout(destinationCard);
    destinationGrid->setContentsMargins(0, 0, 0, 0);
    destinationGrid->setSpacing(8);
    m_endpointDetailValue = addKeyValue(destinationGrid, 0, 0,
                                        QStringLiteral("Endpoint"), destinationCard);
    m_directionValue = addKeyValue(destinationGrid, 0, 1,
                                   QStringLiteral("Direction"), destinationCard);
    bodyLayout->addWidget(destinationCard);

    // Session telemetry
    addSection(QStringLiteral("Session telemetry"));
    auto *telemetryCard = new QFrame(body);
    telemetryCard->setProperty("uiRole", QStringLiteral("card"));
    auto *telemetryGrid = new QGridLayout(telemetryCard);
    telemetryGrid->setContentsMargins(0, 0, 0, 0);
    telemetryGrid->setSpacing(8);
    m_rateValue = addKeyValue(telemetryGrid, 0, 0, QStringLiteral("Current rate"),
                              telemetryCard);
    m_dataValue = addKeyValue(telemetryGrid, 0, 1, QStringLiteral("Data transferred"),
                              telemetryCard);
    m_downloadValue = addKeyValue(telemetryGrid, 1, 0, QStringLiteral("Downloaded"),
                                  telemetryCard);
    m_uploadValue = addKeyValue(telemetryGrid, 1, 1, QStringLiteral("Uploaded"),
                                telemetryCard);
    m_packetsValue = addKeyValue(telemetryGrid, 2, 0, QStringLiteral("Packets"),
                                 telemetryCard);
    m_endpointValue = addKeyValue(telemetryGrid, 2, 1, QStringLiteral("Endpoints"),
                                  telemetryCard);
    bodyLayout->addWidget(telemetryCard);

    // Endpoints inside the grouped row
    addSection(QStringLiteral("Endpoints"));
    auto *endpointsCard = new QFrame(body);
    endpointsCard->setProperty("uiRole", QStringLiteral("elevated"));
    m_endpointsLayout = new QVBoxLayout(endpointsCard);
    m_endpointsLayout->setContentsMargins(12, 10, 12, 10);
    m_endpointsLayout->setSpacing(6);
    bodyLayout->addWidget(endpointsCard);

    // Policy scope note
    auto *policyCard = new QFrame(body);
    policyCard->setProperty("uiRole", QStringLiteral("elevated"));
    auto *policyLayout = new QVBoxLayout(policyCard);
    policyLayout->setContentsMargins(10, 8, 10, 8);
    m_policyNote = new QLabel(
        QStringLiteral("Traffic limits, blocks and firewall rules apply to the "
                       "application executable, not to a single IP."),
        policyCard);
    m_policyNote->setProperty("uiRole", QStringLiteral("muted"));
    m_policyNote->setWordWrap(true);
    policyLayout->addWidget(m_policyNote);
    bodyLayout->addWidget(policyCard);

    bodyLayout->addStretch(1);
    scroll->setWidget(body);
    layout->addWidget(scroll, 1);

    auto *footer = new QFrame(m_drawer);
    auto *footerLayout = new QVBoxLayout(footer);
    footerLayout->setContentsMargins(16, 12, 16, 12);
    footerLayout->setSpacing(8);

    m_trafficButton = new QPushButton(QStringLiteral("Manage app traffic"), footer);
    m_trafficButton->setProperty("variant", QStringLiteral("primary"));
    m_detailsButton = new QPushButton(QStringLiteral("Application details"), footer);

    auto *actionRow = new QHBoxLayout;
    actionRow->setSpacing(8);
    actionRow->addWidget(m_trafficButton, 1);
    actionRow->addWidget(m_detailsButton, 1);

    footerLayout->addLayout(actionRow);
    layout->addWidget(footer);

    connect(m_trafficButton, &QPushButton::clicked, this, [this]() {
        if (m_hasSelection)
            emit trafficRequested(m_selected.pid, m_selected.path, m_selected.appName);
    });
    connect(m_detailsButton, &QPushButton::clicked, this, [this]() {
        if (m_hasSelection)
            emit detailsRequested(m_selected.pid, m_selected.path, m_selected.appName);
    });
}

void ConnectionsPage::setGroups(const QList<Connections::Row> &groups)
{
    const QString keepId = selectedId();
    const int scroll = m_table ? m_table->verticalScrollBar()->value() : 0;

    m_groups = groups;
    m_model->setGroups(groups);

    refreshPills();
    refreshBanner();
    refreshFooter();

    if (m_proxy->rowCount() > 0) {
        selectGroup(keepId);
        m_table->verticalScrollBar()->setValue(scroll);
        QTimer::singleShot(0, this, [this, scroll]() {
            m_table->verticalScrollBar()->setValue(scroll);
        });
    } else {
        clearDrawer();
    }
    refreshEmptyState();
}

void ConnectionsPage::setMonitoringActive(bool active)
{
    m_monitoringActive = active;
    refreshEmptyState();
}

void ConnectionsPage::setFilter(Connections::Filter filter)
{
    const QString keepId = selectedId();
    m_filter = filter;
    if (QAbstractButton *button = m_pillGroup->button(int(filter)))
        button->setChecked(true);
    m_proxy->setConnectionFilter(filter);
    if (m_proxy->rowCount() > 0)
        selectGroup(keepId);
    refreshEmptyState();
    refreshFooter();
}

void ConnectionsPage::clearFilters()
{
    m_filter = Connections::Filter::All;
    if (QAbstractButton *button = m_pillGroup->button(int(Connections::Filter::All)))
        button->setChecked(true);
    m_proxy->setConnectionFilter(Connections::Filter::All);
    if (m_source)
        m_source->setCurrentIndex(0);
    if (m_search)
        m_search->clear();
    applyFilters();
}

void ConnectionsPage::applyFilters()
{
    if (!m_proxy)
        return;
    const QString keepId = selectedId();
    m_proxy->setQuery(m_search ? m_search->text() : QString());
    m_proxy->setSourceKey(m_source ? m_source->currentData().toString()
                                   : QStringLiteral("all"));
    if (m_proxy->rowCount() > 0)
        selectGroup(keepId);
    refreshEmptyState();
    refreshFooter();
}

void ConnectionsPage::refreshPills()
{
    if (!m_pillGroup)
        return;
    const Connections::Filter filters[] = {
        Connections::Filter::All,
        Connections::Filter::Domains,
        Connections::Filter::IpAddresses,
        Connections::Filter::Unknown
    };
    for (Connections::Filter filter : filters) {
        int count = 0;
        for (const Connections::Row &row : m_groups) {
            if (Connections::matchesFilter(row, filter))
                ++count;
        }
        if (QAbstractButton *button = m_pillGroup->button(int(filter))) {
            button->setText(QStringLiteral("%1  %2")
                                .arg(Connections::filterLabel(filter))
                                .arg(count));
        }
    }
}

void ConnectionsPage::refreshBanner()
{
    if (!m_banner)
        return;
    int ipOnly = 0;
    quint64 bytes = 0;
    for (const Connections::Row &row : m_groups) {
        if (!row.hasDomain) {
            ++ipOnly;
            bytes += row.totalBytes();
        }
    }
    if (ipOnly == 0) {
        m_banner->hide();
        m_bannerDismissed = false;
        m_bannerUnknownCount = 0;
        return;
    }
    if (m_bannerDismissed && m_bannerUnknownCount == ipOnly) {
        m_banner->hide();
        return;
    }
    if (m_bannerUnknownCount != ipOnly) {
        m_bannerDismissed = false;
        m_bannerUnknownCount = ipOnly;
    }
    m_bannerText->setText(
        QStringLiteral("%1 destination%2 (%3) without a verified hostname · shown by IP")
            .arg(ipOnly)
            .arg(ipOnly == 1 ? QString() : QStringLiteral("s"))
            .arg(Connections::formatBytes(bytes)));
    m_banner->show();
}

void ConnectionsPage::refreshFooter()
{
    if (!m_footerCount || !m_proxy)
        return;
    int endpoints = 0;
    for (const Connections::Row &row : m_groups)
        endpoints += row.endpointCount;
    m_footerCount->setText(
        QStringLiteral("Showing %1 of %2 destinations · %3 endpoints")
            .arg(m_proxy->rowCount())
            .arg(m_groups.size())
            .arg(endpoints));
}

void ConnectionsPage::refreshEmptyState()
{
    if (!m_stack || !m_proxy || !m_empty)
        return;

    if (m_proxy->rowCount() > 0) {
        m_stack->setCurrentWidget(m_tableCard);
        m_emptyFiltered = false;
        return;
    }

    if (!m_groups.isEmpty()) {
        m_emptyFiltered = true;
        m_empty->setTitle(QStringLiteral("No matching connections"));
        m_empty->setDetail(
            QStringLiteral("No destination matches the current search or filters."));
        m_empty->setAction(QStringLiteral("Clear filters"));
    } else {
        m_emptyFiltered = false;
        m_empty->setTitle(QStringLiteral("No connections observed"));
        m_empty->setDetail(
            m_monitoringActive
                ? QStringLiteral("Traffic will appear here as applications connect. "
                                 "Every destination is named only from observed DNS or "
                                 "TLS SNI evidence.")
                : QStringLiteral("Monitoring is stopped. Start capture to collect "
                                 "destination evidence."));
        m_empty->setAction(QStringLiteral("Refresh"));
    }

    clearDrawer();
    m_stack->setCurrentWidget(m_empty);
}

QString ConnectionsPage::selectedId() const
{
    return m_hasSelection ? m_selected.id : QString();
}

void ConnectionsPage::selectGroup(const QString &id)
{
    if (!m_proxy || m_proxy->rowCount() == 0) {
        clearDrawer();
        return;
    }

    int target = -1;
    if (!id.isEmpty()) {
        for (int row = 0; row < m_proxy->rowCount(); ++row) {
            const QModelIndex index = m_proxy->index(row, 0);
            if (index.data(IdRole).toString() == id) {
                target = row;
                break;
            }
        }
    }
    if (target < 0)
        target = 0;

    const QModelIndex index = m_proxy->index(target, 0);
    if (!index.isValid()) {
        clearDrawer();
        return;
    }
    m_table->setCurrentIndex(index);
    m_table->selectionModel()->select(
        index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);

    const QModelIndex source = m_proxy->mapToSource(index);
    if (source.isValid())
        showRow(m_model->rowAt(source.row()));
}

void ConnectionsPage::showRow(const Connections::Row &row)
{
    m_selected = row;
    m_hasSelection = true;

    m_drawerTitle->setText(row.destination);
    m_drawerTitle->setToolTip(row.destination);

    m_drawerBadge->setText(row.confidence);
    m_drawerBadge->setProperty("status", badgeStatusFor(row.confidenceRank));
    repolish(m_drawerBadge);

    const QPixmap icon = row.icon.pixmap(QSize(28, 28), devicePixelRatioF());
    if (!icon.isNull()) {
        m_appIcon->setPixmap(icon);
        m_appIcon->setText(QString());
    } else {
        m_appIcon->setPixmap(QPixmap());
        m_appIcon->setText(initialsFor(applicationLabel(row)));
    }

    m_appName->setText(applicationLabel(row));
    QStringList meta;
    if (!row.appName.trimmed().isEmpty())
        meta << row.appName;
    if (!row.publisher.trimmed().isEmpty())
        meta << row.publisher;
    if (!row.policy.trimmed().isEmpty() && row.policy != QLatin1String("None"))
        meta << QStringLiteral("Policy: %1").arg(row.policy);
    if (!row.activity.trimmed().isEmpty())
        meta << row.activity;
    m_appMeta->setText(meta.isEmpty() ? QStringLiteral("Identity not resolved")
                                      : meta.join(QStringLiteral(" · ")));
    m_appMeta->setToolTip(row.path);

    QStringList endpointParts;
    if (!row.addresses.isEmpty())
        endpointParts << row.addresses.join(QStringLiteral(", "));
    if (!row.ports.trimmed().isEmpty())
        endpointParts << row.ports;
    m_endpointDetailValue->setText(endpointParts.isEmpty()
                                       ? QStringLiteral("—")
                                       : endpointParts.join(QStringLiteral(" · ")));
    m_directionValue->setText(row.direction);

    m_evidenceTitle->setText(
        row.hasDomain
            ? QStringLiteral("%1 · %2").arg(row.evidenceLabel, row.confidence)
            : QStringLiteral("No evidence · Unknown"));

    QStringList evidenceLines;
    QStringList seen;
    for (const Connections::Endpoint &endpoint : row.endpoints) {
        for (const QString &line : endpoint.evidence) {
            if (!seen.contains(line)) {
                seen.append(line);
                evidenceLines << QStringLiteral("• %1").arg(line);
            }
        }
    }
    if (row.hasDomain) {
        if (row.domainNames.size() > 1) {
            evidenceLines.prepend(
                QStringLiteral("Observed names: %1")
                    .arg(row.domainNames.join(QStringLiteral(", "))));
        }
        if (evidenceLines.isEmpty())
            evidenceLines << QStringLiteral("The name was observed without a recorded "
                                            "evidence detail.");
    } else {
        evidenceLines << QStringLiteral(
            "No DNS answer or visible TLS SNI named this destination. "
            "Reverse-DNS guessing is disabled, so the raw address is shown instead.");
    }
    m_evidenceDetail->setText(evidenceLines.join(QLatin1Char('\n')));

    m_rateValue->setText(Connections::formatRate(row.bytesPerSecond()));
    m_dataValue->setText(Connections::formatBytes(row.totalBytes()));
    m_downloadValue->setText(Connections::formatBytes(row.rxBytes));
    m_uploadValue->setText(Connections::formatBytes(row.txBytes));
    m_packetsValue->setText(QString::number(row.packets));
    m_endpointValue->setText(QString::number(row.endpointCount));

    clearLayout(m_endpointsLayout);
    if (row.endpoints.isEmpty()) {
        auto *empty = new QLabel(QStringLiteral("No sockets recorded."));
        empty->setProperty("uiRole", QStringLiteral("muted"));
        m_endpointsLayout->addWidget(empty);
    } else {
        constexpr int kShownEndpoints = 12;
        int shown = 0;
        for (const Connections::Endpoint &endpoint : row.endpoints) {
            if (shown == kShownEndpoints)
                break;
            auto *endpointCard = new QFrame;
            endpointCard->setProperty("uiRole", QStringLiteral("card"));
            auto *endpointLayout = new QVBoxLayout(endpointCard);
            endpointLayout->setContentsMargins(8, 6, 8, 6);
            endpointLayout->setSpacing(2);

            auto *primary = new QLabel(
                QStringLiteral("%1:%2 · %3")
                    .arg(endpoint.address)
                    .arg(endpoint.port)
                    .arg(endpoint.protocol));
            primary->setProperty("uiRole", QStringLiteral("rowValue"));
            primary->setFont(tabularFont(primary->font()));

            QStringList details;
            details << Connections::sourceLabel(endpoint.source);
            details << Connections::confidenceLabel(endpoint.confidence);
            details << QStringLiteral("↓ %1  ↑ %2")
                           .arg(Connections::formatRate(endpoint.rxBytesPerSecond),
                                Connections::formatRate(endpoint.txBytesPerSecond));
            details << Connections::formatBytes(endpoint.rxBytes + endpoint.txBytes);

            auto *secondary = new QLabel(details.join(QStringLiteral(" · ")));
            secondary->setProperty("uiRole", QStringLiteral("muted"));
            secondary->setWordWrap(true);

            endpointLayout->addWidget(primary);
            endpointLayout->addWidget(secondary);
            m_endpointsLayout->addWidget(endpointCard);
            ++shown;
        }
        if (row.endpoints.size() > kShownEndpoints) {
            auto *more = new QLabel(
                QStringLiteral("and %1 more endpoint(s)")
                    .arg(row.endpoints.size() - kShownEndpoints));
            more->setProperty("uiRole", QStringLiteral("muted"));
            m_endpointsLayout->addWidget(more);
        }
    }

    m_policyNote->setText(
        QStringLiteral("Policy scope: traffic limits, blocks and firewall rules "
                       "apply to %1, not to a single IP, so rotating addresses stay "
                       "covered.")
            .arg(applicationLabel(row)));

    refreshDrawerActions();
}

void ConnectionsPage::clearDrawer()
{
    m_hasSelection = false;
    m_selected = Connections::Row();

    if (!m_drawer)
        return;

    m_drawerTitle->setText(QStringLiteral("Connection Inspector"));
    m_drawerTitle->setToolTip(QString());
    m_drawerBadge->setText(QStringLiteral("No selection"));
    m_drawerBadge->setProperty("status", QStringLiteral("unknown"));
    repolish(m_drawerBadge);

    m_appIcon->setPixmap(QPixmap());
    m_appIcon->setText(QStringLiteral("—"));
    m_appName->setText(QStringLiteral("No connection selected"));
    m_appMeta->setText(
        QStringLiteral("Select a row to inspect its destination and evidence."));
    m_appMeta->setToolTip(QString());

    m_endpointDetailValue->setText(QStringLiteral("—"));
    m_directionValue->setText(QStringLiteral("—"));
    m_evidenceTitle->setText(QStringLiteral("Attribution evidence"));
    m_evidenceDetail->setText(
        QStringLiteral("Select a connection to see how its name was established."));

    m_rateValue->setText(QStringLiteral("—"));
    m_dataValue->setText(QStringLiteral("—"));
    m_downloadValue->setText(QStringLiteral("—"));
    m_uploadValue->setText(QStringLiteral("—"));
    m_packetsValue->setText(QStringLiteral("—"));
    m_endpointValue->setText(QStringLiteral("—"));

    clearLayout(m_endpointsLayout);
    auto *empty = new QLabel(QStringLiteral("No endpoints selected."));
    empty->setProperty("uiRole", QStringLiteral("muted"));
    m_endpointsLayout->addWidget(empty);

    m_policyNote->setText(
        QStringLiteral("Traffic limits, blocks and firewall rules apply to the "
                       "application executable, not to a single IP."));
    refreshDrawerActions();
}

void ConnectionsPage::refreshDrawerActions()
{
    const bool canAct = m_hasSelection
                        && (m_selected.pid != 0
                            || !m_selected.path.trimmed().isEmpty());
    m_trafficButton->setEnabled(canAct);
    m_detailsButton->setEnabled(canAct);

    if (canAct) {
        m_trafficButton->setToolTip(
            QStringLiteral("Open the bandwidth limit for %1.").arg(m_selected.appName));
        m_detailsButton->setToolTip(
            QStringLiteral("Open identity, destinations, policies and audit history."));
    } else {
        const QString reason = m_hasSelection
            ? QStringLiteral("The executable path for this connection is not available.")
            : QStringLiteral("Select a connection first.");
        m_trafficButton->setToolTip(reason);
        m_detailsButton->setToolTip(reason);
    }
}
