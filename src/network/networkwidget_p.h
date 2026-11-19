/**
 * @file    networkwidget_p.h
 * @author  Oasis
 *
 * Private prelude for the NetworkWidget implementation units. It carries the
 * includes they all need; it is not installed and must not be included from
 * a header exposed to other modules.
 */
#pragma once

#include "networkwidget.h"
#include "ui_networkwidget.h"
#include "groupdetaildialog.h"
#include "applicationdetaildialog.h"
#include "dashboardpanel.h"
#include "topconsumers.h"
#include "enforcementcoordinator.h"
#include "policyeditordialog.h"
#include "policylistdialog.h"
#include "policyreconcile.h"
#include "policyreconcileservice.h"
#include "bandwidthlimitsdialog.h"
#include "recommendationdialog.h"
#include "aiapprovaldialog.h"
#include "attribution/aiapproval.h"
#include "attribution/attributionconfidence.h"
#include "attribution/openaiadapter.h"
#include "identity/applicationidentity.h"

// ── Theme Manager ──
#include "ui/theme/thememanager.h"

#include <QHeaderView>
#include <QMessageBox>
#include <QMetaObject>
#include <QSet>
#include <QStyle>
#include <QApplication>
#include <QMenu>
#include <QClipboard>
#include <QDateTime>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QGroupBox>
#include <QDir>
#include <QProcess>
#include <QFileInfo>
#include <QUuid>
#include <QFrame>
#include <QLineEdit>
#include <QPalette>
#include <QVariant>
#include <QPixmap>
#include <QTimer>

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <shellapi.h>
#include <psapi.h>
#include "core/windowsicon.h"
#include "core/guitiming.h"
#include "firewall/firewallmanager.h"
