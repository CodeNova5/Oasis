/**
 * @file    networkwidgettable.cpp
 * @author  Oasis
 *
 * Process table for NetworkWidget: the properties dialog, the row context
 * menu, filtering/expanding, and process path/icon resolution.
 */
#include "networkwidget_p.h"

// ============================================================================
// ── Process Properties Dialog Implementation ──
// ============================================================================
ProcessInfoDialog::ProcessInfoDialog(const QString &name, quint32 pid, const QString &path,
                                     const QString &rx, const QString &tx, const QString &total, const QString &pkts,
                                     const QIcon &icon, QWidget *parent)
    : QDialog(parent), m_path(path)
{
    setWindowTitle("Process Properties");
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    setMinimumWidth(520);

    // ── Dynamic Theme Palette ──
    bool isDark = ThemeManager::instance().isDark();

    QString bg       = isDark ? "#1F2328" : "#F6F8FA";
    QString fg       = isDark ? "#E6EDF3" : "#24292E";
    QString border   = isDark ? "#30363D" : "#D0D7DE";
    QString btnBg    = isDark ? "#21262D" : "#EBECF0";
    QString btnHover = isDark ? "#30363D" : "#F3F4F6";
    QString textMuted= isDark ? "#8B949E" : "#57606A";
    QString selectBg = isDark ? "#1F6FEB" : "#0969DA";

    setStyleSheet(QString(
                      "QDialog { background-color: %1; color: %2; }"
                      "QLabel { color: %2; font-size: 10pt; }"
                      "QLineEdit { background: transparent; border: none; color: %2; font-size: 10pt; selection-background-color: %7; selection-color: #FFFFFF; }"
                      "QPushButton { background-color: %4; border: 1px solid %3; border-radius: 6px; padding: 6px 16px; color: %2; font-weight: bold; }"
                      "QPushButton:hover { background-color: %5; }"
                      "QPushButton:disabled { color: %6; background-color: %1; }"
                      "QGroupBox { border: 1px solid %3; border-radius: 6px; margin-top: 12px; font-weight: bold; color: %2; }"
                      "QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; left: 10px; }"
                      ).arg(bg, fg, border, btnBg, btnHover, textMuted, selectBg));

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    // ── Header (Icon, Name, Type) ──
    QHBoxLayout *headerLayout = new QHBoxLayout();
    QLabel *iconLabel = new QLabel();
    iconLabel->setPixmap(icon.pixmap(150, 150));
    headerLayout->addWidget(iconLabel);

    QVBoxLayout *nameLayout = new QVBoxLayout();
    QLineEdit *nameEdit = new QLineEdit(name);
    nameEdit->setReadOnly(true);
    nameEdit->setStyleSheet("font-size: 13pt; font-weight: bold;");

    QString typeStr = "Application (EXE)";
    if (pid == 0 || pid == 4) typeStr = "System OS / Kernel Overhead";
    else if (name.startsWith("Service:")) typeStr = "Windows Service";

    QLabel *typeLabel = new QLabel(typeStr);
    typeLabel->setStyleSheet(QString("color: %1;").arg(textMuted));

    nameLayout->addWidget(nameEdit);
    nameLayout->addWidget(typeLabel);
    nameLayout->addStretch();

    headerLayout->addLayout(nameLayout);
    headerLayout->addStretch();
    mainLayout->addLayout(headerLayout);

    QFrame *line = new QFrame();
    line->setFrameShape(QFrame::HLine);
    line->setStyleSheet(QString("background-color: %1;").arg(border));
    mainLayout->addWidget(line);

    // ── Process Info ──
    QFormLayout *formLayout = new QFormLayout();
    formLayout->setSpacing(12);

    QLineEdit *pidEdit = new QLineEdit(QString::number(pid));
    pidEdit->setReadOnly(true);
    formLayout->addRow("<b>Process ID:</b>", pidEdit);

    QLineEdit *pathEdit = new QLineEdit(path.isEmpty() ? "N/A (System / Protected)" : path);
    pathEdit->setReadOnly(true);
    pathEdit->setCursorPosition(0);
    formLayout->addRow("<b>File Path:</b>", pathEdit);

    mainLayout->addLayout(formLayout);

    // ── Traffic Stats ──
    QGroupBox *usageGroup = new QGroupBox(" Network Traffic Usage ");
    QFormLayout *usageLayout = new QFormLayout(usageGroup);
    usageLayout->setContentsMargins(15, 20, 15, 15);
    usageLayout->setSpacing(10);

    auto createStatEdit = [](const QString& text) {
        QLineEdit *le = new QLineEdit(text);
        le->setReadOnly(true);
        return le;
    };

    usageLayout->addRow("<b>Download Speed:</b>", createStatEdit(rx));
    usageLayout->addRow("<b>Upload Speed:</b>", createStatEdit(tx));
    usageLayout->addRow("<b>Total Consumed:</b>", createStatEdit(total));
    usageLayout->addRow("<b>Total Packets:</b>", createStatEdit(pkts));
    mainLayout->addWidget(usageGroup);

    // ── Action Buttons ──
    QHBoxLayout *btnLayout = new QHBoxLayout();
    QPushButton *btnOpenLoc = new QPushButton("📂 Open File Location");
    QPushButton *btnClose = new QPushButton("Close");

    if (path.isEmpty() || pid == 0 || pid == 4) btnOpenLoc->setEnabled(false);

    btnLayout->addWidget(btnOpenLoc);
    btnLayout->addStretch();
    btnLayout->addWidget(btnClose);

    mainLayout->addLayout(btnLayout);

    connect(btnOpenLoc, &QPushButton::clicked, this, &ProcessInfoDialog::onOpenLocation);
    connect(btnClose, &QPushButton::clicked, this, &QDialog::accept);
}

void ProcessInfoDialog::onOpenLocation() {
    if (m_path.isEmpty()) return;
    QFileInfo fi(m_path);
    if (fi.exists()) {
        QString param = QString("/select,\"%1\"").arg(QDir::toNativeSeparators(m_path));
        QProcess::startDetached("explorer.exe", {param});
    } else {
        QMessageBox::warning(this, "Not Found", "The executable no longer exists at this path.");
    }
}

void NetworkWidget::onTreeViewContextMenu(const QPoint &pos)
{
    QModelIndex proxyIdx = ui->treeView->indexAt(pos);
    if (!proxyIdx.isValid()) return;

    QModelIndex idx = m_proxy->mapToSource(proxyIdx);

    quint32 pid = idx.data(Qt::UserRole).toUInt();
    QString name = idx.data(Qt::UserRole + 1).toString();
    bool isProcessNode = idx.data(Qt::UserRole + 2).toBool();

    QMenu menu(this);

    // ── Context Menu Styling ──
    bool isDark = ThemeManager::instance().isDark();
    if (isDark) {
        menu.setStyleSheet(
            "QMenu { background-color: #1F2328; color: #E6EDF3; border: 1px solid #30363D; padding: 4px; border-radius: 6px; }"
            "QMenu::item { padding: 6px 24px 6px 24px; border-radius: 4px; margin: 1px 4px; }"
            "QMenu::item:selected { background-color: #238636; color: #FFFFFF; }"
            "QMenu::separator { height: 1px; background: #21262D; margin: 4px 10px; }"
            );
    } else {
        menu.setStyleSheet(
            "QMenu { background-color: #FFFFFF; color: #24292E; border: 1px solid #D0D7DE; padding: 4px; border-radius: 6px; }"
            "QMenu::item { padding: 6px 24px 6px 24px; border-radius: 4px; margin: 1px 4px; }"
            "QMenu::item:selected { background-color: #0969DA; color: #FFFFFF; }"
            "QMenu::separator { height: 1px; background: #D1D5DA; margin: 4px 10px; }"
            );
    }

    if (pid != 0 && pid != 4) {
        QAction *actKill = menu.addAction("☠ Kill Process (End Task)");
        connect(actKill, &QAction::triggered, this, [this, pid]() {
            if (QMessageBox::question(this, "Kill Process", QString("Are you sure you want to forcibly terminate PID %1?").arg(pid)) == QMessageBox::Yes) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }
                else { QMessageBox::warning(this, "Error", "Access Denied. Make sure you run as Administrator."); }
            }
        });
        menu.addSeparator();
    }

    if (isProcessNode) {
        QAction *actInfo = menu.addAction("ℹ Process Properties...");
        connect(actInfo, &QAction::triggered, this, [this, idx, pid, name]() {
            QString path = getExactProcessPath(pid, name);

            QString rx = idx.siblingAtColumn(6).data().toString(); // COL_RX
            QString tx = idx.siblingAtColumn(7).data().toString(); // COL_TX
            QString total = idx.siblingAtColumn(8).data().toString(); // COL_BYTES
            QString pkts = idx.siblingAtColumn(9).data().toString();  // COL_PKTS

            QVariant iconVar = idx.siblingAtColumn(0).data(Qt::DecorationRole); // COL_NAME
            QIcon icon;
            if (!iconVar.isNull()) {
                QPixmap pm = iconVar.value<QPixmap>();
                if (!pm.isNull()) icon = QIcon(pm);
            }
            if (icon.isNull()) icon = qApp->style()->standardIcon(QStyle::SP_ComputerIcon);

            ProcessInfoDialog dlg(name, pid, path, rx, tx, total, pkts, icon, this);
            dlg.exec();
        });

        // NG-052: one view with identity, usage, destinations, related
        // processes, policy state, and audit history, from which every action
        // below is also available. The evidence is captured now, so the dialog
        // describes the row that was right-clicked even after a refresh.
        const QString rowPath = getExactProcessPath(pid, name);
        QAction *actDetails = menu.addAction("🔍 Details & evidence...");
        connect(actDetails, &QAction::triggered, this, [this, pid, name, rowPath]() {
            showApplicationDetails(pid, rowPath, name);
        });

        // NG-016: inspect the activity group this process was grouped into and
        // edit its members without touching any configuration file.
        const QString groupId = idx.data(Qt::UserRole + 7).toString();
        if (!groupId.isEmpty()) {
            QAction *actGroup = menu.addAction("🔗 Activity group...");
            connect(actGroup, &QAction::triggered, this, [this, groupId]() {
                GroupDetailDialog dlg(m_monitor, groupId, m_bandwidthGuard, this);
                dlg.exec();
            });
        }

        // NG-022: create a policy with an explicit scope. The dialog explains
        // the breadth and risk of the chosen scope before it is saved, and a
        // group policy targets the group id so future members inherit it.
        QAction *actPolicy = menu.addAction("🛡 Create policy...");
        connect(actPolicy, &QAction::triggered, this, [this, pid, name, groupId]() {
            createPolicyForTarget(policyTargetFor(pid, name,
                                                  getExactProcessPath(pid, name), groupId));
        });

        // NG-042/NG-043: show the deterministic recommendation for this row and
        // let the user record whether it was useful, incorrect, or unwanted.
        // The evidence is captured before the menu's event loop can change the
        // model, so the dialog always describes the row that was right-clicked.
        QAction *actRecommend = menu.addAction("💡 Recommendation...");
        connect(actRecommend, &QAction::triggered, this, [this, pid, name, rowPath]() {
            showRecommendationFor(pid, name, rowPath);
        });

        // NG-046: review an optional AI explanation and approve the local
        // recommendation as one ordinary user policy with an explicit scope
        // and duration. Rejecting the dialog writes nothing.
        QAction *actApproval = menu.addAction("🧠 Review AI explanation & approve policy...");
        connect(actApproval, &QAction::triggered, this, [this, pid, name, rowPath]() {
            showApprovalFor(pid, name, rowPath);
        });

        menu.addSeparator();
        QAction *actExempt = menu.addAction("Ignore bandwidth alerts for 2 hours");
        connect(actExempt, &QAction::triggered, this, [this, name]() {
            m_bandwidthGuard->exemptProcess(name, 2 * 60 * 60);
        });

        const QString procPath = getExactProcessPath(pid, name);
        const bool internetBlocked = !procPath.isEmpty() && m_firewall->isBlocked(procPath);
        QAction *actNet = menu.addAction(internetBlocked
            ? "🌐 Restore internet access"
            : "🚫 Block internet access");
        connect(actNet, &QAction::triggered, this, [this, name, procPath]() {
            toggleInternetAccess(name, procPath);
        });

        QMenu *classificationMenu = menu.addMenu("Classify process");
        QAction *actAskFirst = classificationMenu->addAction("Ask before any future action");
        connect(actAskFirst, &QAction::triggered, this, [this, name]() {
            m_bandwidthGuard->setCategoryOverride(name, ProcessCategory::AskFirst);
        });
        QAction *actUpdater = classificationMenu->addAction("Treat as updater candidate");
        connect(actUpdater, &QAction::triggered, this, [this, name]() {
            m_bandwidthGuard->setCategoryOverride(name, ProcessCategory::AutoCandidate);
        });

        menu.addSeparator();
        QAction *actThrottle = menu.addAction(throttleActionText(procPath));
        actThrottle->setToolTip(QDir::toNativeSeparators(procPath));
        connect(actThrottle, &QAction::triggered, this, [this, pid, name]() {
            requestThrottle(pid, name);
        });
    } else {
        QAction *actCopy = menu.addAction("📋 Copy Connection Details");
        connect(actCopy, &QAction::triggered, this, [name]() {
            QApplication::clipboard()->setText(name);
        });
    }

    menu.exec(ui->treeView->viewport()->mapToGlobal(pos));
}

void NetworkWidget::onFilterChanged(const QString &text) { m_proxy->setFilterFixedString(text); if (!text.isEmpty()) ui->treeView->expandAll(); }

void NetworkWidget::onClearTable()
{
    m_bandwidthGuard->reset();
    m_model->clear();
    m_totalPkts = 0;
    ui->lblPackets->setText("0");
    m_iconCache.clear();
    m_dashboardPathCache.clear();
    ui->btnExpandAll->setText("Expand All");
    refreshDashboard();
}

void NetworkWidget::onExpandAll()
{
    if (ui->btnExpandAll->text().contains("Expand")) {
        ui->treeView->expandAll();
        ui->btnExpandAll->setText("Collapse All");
    } else {
        ui->treeView->collapseAll();
        ui->btnExpandAll->setText("Expand All");
    }
}

QString NetworkWidget::getExactProcessPath(quint32 pid, const QString &procName)
{
    if (pid == 0 || pid == 4) return QString();

    QString result;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        wchar_t path[MAX_PATH] = {};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
            result = QString::fromWCharArray(path, static_cast<int>(size));
        }
        CloseHandle(hProc);
    }

    if (result.isEmpty() && !procName.isEmpty()) {
        wchar_t sysDir[MAX_PATH] = {};
        GetSystemDirectoryW(sysDir, MAX_PATH);
        QString fallback = QString::fromWCharArray(sysDir) + "\\" + procName;
        if (QFileInfo::exists(fallback)) return fallback;
    }

    return result;
}

QIcon NetworkWidget::getIconByPid(quint32 pid, const QString &procName)
{
    QString fullPath = getExactProcessPath(pid, procName);
    SHFILEINFOW sfi = {};
    QIcon icon;

    // The Applications table renders 32 px icons, so ask the shell for the
    // large (32 px) image instead of scaling its 16 px small icon up.
    if (!fullPath.isEmpty()) {
        if (SHGetFileInfoW(fullPath.toStdWString().c_str(), 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_LARGEICON)) {
            if (sfi.hIcon) { icon = iconFromHICON(sfi.hIcon); DestroyIcon(sfi.hIcon); return icon; }
        }
    }

    if (SHGetFileInfoW(procName.toStdWString().c_str(), FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_LARGEICON | SHGFI_USEFILEATTRIBUTES)) {
            if (sfi.hIcon) { icon = iconFromHICON(sfi.hIcon); DestroyIcon(sfi.hIcon); }
    }
    return icon;
}

QIcon NetworkWidget::genericExecutableIcon() const
{
    if (!m_genericExecutableIcon.isNull())
        return m_genericExecutableIcon;

    // Ask the shell what an application icon looks like without needing a real
    // file on disk; SHGFI_USEFILEATTRIBUTES makes the extension sufficient.
    SHFILEINFOW sfi = {};
    if (SHGetFileInfoW(L"application.exe", FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi),
                       SHGFI_ICON | SHGFI_LARGEICON | SHGFI_USEFILEATTRIBUTES)
        && sfi.hIcon) {
        m_genericExecutableIcon = iconFromHICON(sfi.hIcon);
        DestroyIcon(sfi.hIcon);
    }
    if (m_genericExecutableIcon.isNull())
        m_genericExecutableIcon = style()->standardIcon(QStyle::SP_FileIcon);
    return m_genericExecutableIcon;
}



