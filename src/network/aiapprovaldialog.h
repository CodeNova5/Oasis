/**
 * @file    aiapprovaldialog.h
 * @brief   AI approval flow (NG-046): review the local recommendation and an
 *          optional AI explanation, then approve or reject one policy with an
 *          explicit scope and duration.
 * @author  Ali Sakkaf
 *
 * Nothing is sent to a provider until the user presses the send button, and the
 * exact bounded context is shown first. Nothing is written until the user
 * presses Approve policy: rejection closes the dialog and leaves stored policies
 * and enforcement state untouched.
 *
 * The policy's action, rate, and schedule come from the deterministic NG-042
 * recommendation. The provider contributes explanation text only, so it cannot
 * choose or widen an enforcement action.
 */
#pragma once

#include <QDialog>

#include "attribution/aiapproval.h"
#include "attribution/aiprovider.h"
#include "attribution/recommendationengine.h"
#include "network/policy.h"

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
template <typename T> class QFutureWatcher;

class AiApprovalDialog : public QDialog
{
    Q_OBJECT
public:
    AiApprovalDialog(const RecommendationContext &context,
                     const RecommendationEngine &engine,
                     AiAssistant *assistant,
                     QWidget *parent = nullptr);

    /// True once Approve policy succeeded.
    bool wasApproved() const { return m_approved; }
    NetworkPolicy approvedPolicy() const { return m_policy; }

    void accept() override;

private:
    void buildUi();
    void applyProviderSettingsToUi();
    void saveProviderSettings();
    void requestExplanation();
    void onExplanationReady();
    void updateScopeDescription();
    void updateApprovalState();

    RecommendationContext m_context;
    const RecommendationEngine *m_engine = nullptr;
    AiAssistant *m_assistant = nullptr;
    Recommendation m_recommendation;
    QList<AiApprovalScopeOption> m_scopeOptions;

    bool m_approved = false;
    bool m_explanationUsed = false;
    NetworkPolicy m_policy;

    QLabel *m_title = nullptr;
    QLabel *m_meta = nullptr;
    QLabel *m_body = nullptr;

    QPlainTextEdit *m_contextPreview = nullptr;
    QPlainTextEdit *m_explanation = nullptr;
    QLabel *m_explanationStatus = nullptr;
    QPushButton *m_askAi = nullptr;

    QCheckBox *m_aiEnabled = nullptr;
    QLineEdit *m_endpoint = nullptr;
    QLineEdit *m_model = nullptr;
    QLabel *m_providerStatus = nullptr;

    QComboBox *m_scopeCombo = nullptr;
    QLabel *m_scopeRisk = nullptr;
    QLabel *m_actionText = nullptr;
    QComboBox *m_durationCombo = nullptr;
    QLabel *m_durationText = nullptr;
    QLineEdit *m_note = nullptr;
    QPushButton *m_approve = nullptr;

    QFutureWatcher<AiAssistResult> *m_watcher = nullptr;
};
