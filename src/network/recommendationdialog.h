/**
 * @file    recommendationdialog.h
 * @brief   Recommendation and local feedback view (NG-042/NG-043).
 *
 * Shows one deterministic recommendation with its evidence, confidence,
 * expected effect, and reversal action, and lets the user record whether it was
 * useful, incorrect, or unwanted. The verdict is stored on this device only and
 * immediately changes the recommendation shown by the engine.
 */
#pragma once

#include <QDialog>

#include "attribution/recommendationengine.h"
#include "attribution/recommendationfeedback.h"

class QButtonGroup;
class QLabel;
class QPushButton;

class RecommendationDialog : public QDialog
{
    Q_OBJECT
public:
    RecommendationDialog(const RecommendationContext &context,
                         const RecommendationEngine &engine,
                         RecommendationFeedbackStore *feedbackStore,
                         QWidget *parent = nullptr);

private:
    void refresh();
    void setFeedback(RecommendationFeedback feedback);
    QString feedbackStatusText() const;

    RecommendationContext m_context;
    const RecommendationEngine *m_engine = nullptr;
    RecommendationFeedbackStore *m_store = nullptr;
    Recommendation m_recommendation;

    QLabel       *m_title   = nullptr;
    QLabel       *m_meta    = nullptr;
    QLabel       *m_body    = nullptr;
    QLabel       *m_status  = nullptr;
    QButtonGroup *m_group   = nullptr;
    QPushButton  *m_useful  = nullptr;
    QPushButton  *m_incorrect = nullptr;
    QPushButton  *m_unwanted  = nullptr;
    QPushButton  *m_clear     = nullptr;
};
