/**
 * @file    openaiadapter.h
 * @brief   Opt-in OpenAI-compatible provider adapter (NG-045).
 * @author  Oasis
 *
 * The adapter is vendor-neutral: the user supplies the full chat-completions
 * URL and model, and the key comes from an environment variable so it is never
 * written to QSettings, a log, or the context document. Only the bounded NG-044
 * payload is posted; the reply is reduced to explanation text.
 *
 * `explain()` blocks until the reply arrives or the configured timeout expires,
 * so a UI caller must run it off the GUI thread.
 */
#pragma once

#include "attribution/aiprovider.h"

class OpenAiCompatibleProvider : public AiProvider
{
public:
    QString name() const override;

    AiProviderResponse explain(const AiContextPayload &payload,
                               const AiProviderSettings &settings) override;

    /// Environment variable holding the bearer token. A key is never persisted.
    static QString apiKeyEnvironmentVariable();

    /// Instructions sent with every request. They forbid inventing evidence and
    /// forbid proposing or applying a policy.
    static QString systemPrompt();

    /// Hard cap on the raw reply body before parsing.
    static int maxResponseBytes();
};
