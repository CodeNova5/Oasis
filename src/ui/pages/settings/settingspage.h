/**
 * @file    settingspage.h
 * @brief   Screen 09 — Settings (SCREENS_SPEC.md), detection profile first.
 *
 * Presentation only: the page reports which profile the user picked and shows
 * the numbers that profile applies. Saving and reconfiguring the detector is
 * the host's job (see MainWindow), so the page can be reviewed in isolation.
 *
 * @author  Oasis
 */
#pragma once

#include <QWidget>

#include "activity/detectionprofile.h"

class QButtonGroup;
class QLabel;
class QRadioButton;

class SettingsPage : public QWidget
{
    Q_OBJECT
public:
    explicit SettingsPage(QWidget *parent = nullptr);

    Activity::DetectionProfile detectionProfile() const { return m_profile; }
    void setDetectionProfile(Activity::DetectionProfile profile);

signals:
    void detectionProfileChanged(Activity::DetectionProfile profile);

private:
    void buildDetectionCard(QWidget *content);

    QButtonGroup *m_profileGroup = nullptr;
    QList<QRadioButton *> m_profileButtons;
    QLabel *m_profileStatus = nullptr;
    Activity::DetectionProfile m_profile = Activity::DetectionProfile::Balanced;
};
