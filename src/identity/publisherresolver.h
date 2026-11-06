/**
 * @file    publisherresolver.h
 * @brief   Authenticode signer and publisher resolution (NG-011).
 *
 * Verifies the embedded Authenticode signature of an executable through the
 * Windows trust APIs and reports the signer subject, publisher, certificate
 * thumbprint, and the certificate timestamp. Verification never throws and
 * never blocks observation: an unreadable or unsupported file is reported as
 * `Unavailable` (ApplicationIdentity::SignerStatus::Unknown) with a message.
 *
 * Only local evidence is used. Revocation is not fetched from the network so a
 * monitoring refresh cannot be stalled by a slow certificate server.
 */
#pragma once

#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <QHash>

#include "network/policy.h"

namespace NetGuard {

// Evidence gathered from the embedded Authenticode signature.
struct PublisherEvidence
{
    // Signed: signature verified. Unsigned: no embedded signature. Invalid:
    // a signature exists but is not trusted or does not match the file.
    // Unknown: evidence could not be gathered (unavailable).
    ApplicationIdentity::SignerStatus status = ApplicationIdentity::SignerStatus::Unknown;
    QString publisher;          // Signer subject common name (CN)
    QString organization;       // Signer subject organization (O)
    QString certificateSubject; // Full signer subject, for support output
    QByteArray certificateThumbprint; // SHA-1 of the signer certificate (DER)
    QDateTime timestamp;        // Certificate timestamp, invalid when unsigned
    quint32 errorCode = 0;      // Win32/HRESULT behind a failure or unknown state
    QString message;            // Human-readable explanation

    bool verified() const { return status == ApplicationIdentity::SignerStatus::Signed; }
};

// "signed", "unsigned", "invalid", or "unavailable".
QString signerStatusName(ApplicationIdentity::SignerStatus status);

class PublisherResolver
{
public:
    PublisherEvidence resolve(const QString &canonicalPath);

    int cachedCount() const { return m_cache.size(); }
    void clearCache() { m_cache.clear(); }

private:
    PublisherEvidence verify(const QString &canonicalPath);

    // Signature verification hashes the whole file, so results are reused for
    // the lifetime of the session. Definitive evidence only; an invalid or
    // unavailable signature is re-checked because the file may be replaced.
    QHash<QString, PublisherEvidence> m_cache;
};

} // namespace NetGuard

Q_DECLARE_METATYPE(NetGuard::PublisherEvidence)
