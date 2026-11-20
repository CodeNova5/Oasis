/**
 * @file    policiespage.cpp
 * @author  Oasis
 */
#include "policiespage.h"

#include "ui/components/emptystatewidget.h"
#include "ui/components/metriccard.h"
#include "ui/theme/dimensions.h"

#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QString>
#include <QVBoxLayout>

PoliciesPage::PoliciesPage(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("policiesPage"));

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::Dim::PagePaddingH, 20,
                             Theme::Dim::PagePaddingH, 0);
    root->setSpacing(Theme::Dim::SpaceLg);

    // The mock puts Verify and Create in the page header; the shell keeps the
    // header for the title, so this page hosts them in its own body toolbar.
    buildToolbar(root);
    buildMetrics(root);
    buildContent(root);
}

void PoliciesPage::buildToolbar(QVBoxLayout *root)
{
    auto *toolbar = new QHBoxLayout;
    toolbar->setContentsMargins(0, 0, 0, 0);
    toolbar->setSpacing(Theme::Dim::SpaceSm);

    toolbar->addStretch(1);

    m_verifyButton = new QPushButton(QStringLiteral("Verify rules"), this);
    m_verifyButton->setFixedHeight(Theme::Dim::ButtonHeight);
    m_verifyButton->setCursor(Qt::PointingHandCursor);
    m_verifyButton->setEnabled(false);
    m_verifyButton->setToolTip(QStringLiteral("Not available yet."));
    toolbar->addWidget(m_verifyButton);

    m_createButton = new QPushButton(QStringLiteral("Create policy"), this);
    m_createButton->setProperty("variant", QStringLiteral("primary"));
    m_createButton->setFixedHeight(Theme::Dim::ButtonHeight);
    m_createButton->setCursor(Qt::PointingHandCursor);
    m_createButton->setEnabled(false);
    m_createButton->setToolTip(QStringLiteral("Not available yet."));
    toolbar->addWidget(m_createButton);

    connect(m_verifyButton, &QPushButton::clicked,
            this, &PoliciesPage::verifyRequested);
    connect(m_createButton, &QPushButton::clicked,
            this, &PoliciesPage::createRequested);

    root->addLayout(toolbar);
}

void PoliciesPage::buildMetrics(QVBoxLayout *root)
{
    auto *grid = new QGridLayout;
    grid->setContentsMargins(0, 0, 0, 0);
    grid->setHorizontalSpacing(Theme::Dim::SpaceMd);
    grid->setVerticalSpacing(Theme::Dim::SpaceMd);

    m_activeCard = new MetricCard(QStringLiteral("Active"), this);
    m_activeCard->setCaption(QStringLiteral("enforced right now"));

    m_scheduledCard = new MetricCard(QStringLiteral("Scheduled / Paused"), this);
    m_scheduledCard->setCaption(QStringLiteral("window / disabled / expired"));

    m_storedOnlyCard = new MetricCard(QStringLiteral("Stored only"), this);
    m_storedOnlyCard->setCaption(QStringLiteral("saved without a live rule"));

    MetricCard *cards[] = {m_activeCard, m_scheduledCard, m_storedOnlyCard};
    for (int column = 0; column < 3; ++column) {
        grid->addWidget(cards[column], 0, column);
        grid->setColumnStretch(column, 1);
    }

    root->addLayout(grid);
}

void PoliciesPage::buildContent(QVBoxLayout *root)
{
    // Empty state: no policy is stored yet.
    m_emptyHost = new QWidget(this);
    auto *emptyLayout = new QVBoxLayout(m_emptyHost);
    emptyLayout->setContentsMargins(0, 0, 0, 0);
    emptyLayout->setSpacing(0);

    m_empty = new EmptyStateWidget(m_emptyHost);
    m_empty->setTitle(QStringLiteral("No policies configured yet"));
    m_empty->setDetail(QStringLiteral(
        "Policies cap an application's bandwidth, block its traffic, or exempt "
        "it from limits. Counts above update as soon as a policy is stored."));
    // The action stays hidden while the create flow is not wired to this page.
    emptyLayout->addStretch(1);
    emptyLayout->addWidget(m_empty, 0, Qt::AlignHCenter);
    emptyLayout->addStretch(1);

    // Policies exist: the row-by-row list is a later phase, so the page says
    // what is true now instead of showing a table it cannot act on.
    m_storedCard = new QFrame(this);
    m_storedCard->setProperty("uiRole", QStringLiteral("card"));
    m_storedCard->setMaximumWidth(560);
    auto *cardLayout = new QVBoxLayout(m_storedCard);
    cardLayout->setContentsMargins(Theme::Dim::SpaceXl, Theme::Dim::SpaceXl,
                                   Theme::Dim::SpaceXl, Theme::Dim::SpaceXl);
    cardLayout->setSpacing(Theme::Dim::SpaceSm);

    m_storedTitle = new QLabel(m_storedCard);
    m_storedTitle->setProperty("uiRole", QStringLiteral("sectionHeading"));
    m_storedTitle->setWordWrap(true);

    m_storedDetail = new QLabel(m_storedCard);
    m_storedDetail->setProperty("uiRole", QStringLiteral("emptyText"));
    m_storedDetail->setWordWrap(true);

    cardLayout->addWidget(m_storedTitle);
    cardLayout->addWidget(m_storedDetail);

    m_storedCardHost = new QWidget(this);
    auto *storedLayout = new QVBoxLayout(m_storedCardHost);
    storedLayout->setContentsMargins(0, 0, 0, 0);
    storedLayout->setSpacing(0);
    storedLayout->addStretch(1);
    storedLayout->addWidget(m_storedCard, 0, Qt::AlignHCenter);
    storedLayout->addStretch(1);

    root->addWidget(m_emptyHost, 1);
    root->addWidget(m_storedCardHost, 1);

    refreshContent();
}

void PoliciesPage::setSummary(const Policies::Summary &summary)
{
    m_summary = summary;

    m_activeCard->setValue(QString::number(summary.active));
    m_scheduledCard->setValue(QString::number(summary.scheduledPaused));
    m_storedOnlyCard->setValue(QString::number(summary.storedOnly));

    refreshContent();
}

void PoliciesPage::refreshContent()
{
    if (!m_emptyHost || !m_storedCardHost)
        return;

    const bool hasPolicies = m_summary.total > 0;
    m_emptyHost->setVisible(!hasPolicies);
    m_storedCardHost->setVisible(hasPolicies);

    if (!hasPolicies)
        return;

    m_storedTitle->setText(QStringLiteral("%1 stored %2")
        .arg(m_summary.total)
        .arg(m_summary.total == 1 ? QStringLiteral("policy")
                                  : QStringLiteral("policies")));
    m_storedDetail->setText(QStringLiteral(
        "These rules stay enforced in the background. The policy table and its "
        "actions are being rebuilt on this screen."));
}
