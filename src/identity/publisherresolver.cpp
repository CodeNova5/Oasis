/**
 * @file    publisherresolver.cpp
 * @brief   Authenticode signer and publisher resolution (NG-011).
 */

#include "identity/publisherresolver.h"

#include <QDir>
#include <QTimeZone>
#include <QVector>

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

#include <string>

namespace Oasis {
namespace {

// pvTypePara for CERT_NAME_ATTR_TYPE is an ANSI OID string, not a wide one.
QString certificateName(const CERT_CONTEXT *cert, const char *oid)
{
    if (!cert) return QString();

    const DWORD chars = ::CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0,
                                             const_cast<char *>(oid), nullptr, 0);
    if (chars <= 1) return QString();

    QVector<wchar_t> buffer(static_cast<int>(chars), L'\0');
    if (::CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0,
                             const_cast<char *>(oid),
                             buffer.data(), chars) <= 1) {
        return QString();
    }
    return QString::fromWCharArray(buffer.constData()).trimmed();
}

QDateTime toDateTime(const FILETIME &ft)
{
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return QDateTime();

    SYSTEMTIME st{};
    if (!::FileTimeToSystemTime(&ft, &st)) return QDateTime();

    if (st.wYear < 1601 || st.wMonth < 1 || st.wMonth > 12
        || st.wDay < 1 || st.wDay > 31 || st.wHour > 23
        || st.wMinute > 59 || st.wSecond > 59) {
        return QDateTime();
    }
    const QDate date(static_cast<int>(st.wYear), static_cast<int>(st.wMonth),
                     static_cast<int>(st.wDay));
    const QTime time(static_cast<int>(st.wHour), static_cast<int>(st.wMinute),
                     static_cast<int>(st.wSecond),
                     static_cast<int>(st.wMilliseconds));
    if (!date.isValid() || !time.isValid()) return QDateTime();
    return QDateTime(date, time, QTimeZone::UTC);
}

// Fills the signer evidence from the trust-provider state that WinVerifyTrust
// already built, so no certificate store is walked a second time.
void readSignerEvidence(const CRYPT_PROVIDER_DATA *providerData, PublisherEvidence &evidence)
{
    if (!providerData || providerData->csSigners < 1) return;

    CRYPT_PROVIDER_SGNR *signer =
        ::WTHelperGetProvSignerFromChain(const_cast<CRYPT_PROVIDER_DATA *>(providerData), 0, FALSE, 0);
    if (!signer) return;

    // Zeroed unless the signer carried a countersignature from a timestamping
    // authority, in which case this is the time the signature is valid as of.
    evidence.timestamp = toDateTime(signer->sftVerifyAsOf);

    CRYPT_PROVIDER_CERT *providerCert = ::WTHelperGetProvCertFromChain(signer, 0);
    if (!providerCert || !providerCert->pCert) return;

    const CERT_CONTEXT *cert = providerCert->pCert;
    evidence.publisher = certificateName(cert, "2.5.4.3");       // CN
    evidence.organization = certificateName(cert, "2.5.4.10");   // O
    evidence.certificateSubject = certificateName(cert, "2.5.4.3");

    DWORD hashLength = 0;
    if (::CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, nullptr, &hashLength)
        && hashLength > 0) {
        QByteArray hash(static_cast<int>(hashLength), '\0');
        if (::CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID,
                                               hash.data(), &hashLength)) {
            evidence.certificateThumbprint = hash;
        }
    }
}

WINTRUST_DATA makeVerifyData(DWORD unionChoice)
{
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = unionChoice;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    // Local evidence only: a slow certificate server must never stall a refresh.
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    data.dwUIContext = WTD_UICONTEXT_EXECUTE;
    return data;
}

struct TrustResult
{
    LONG status = ERROR_SUCCESS;
    PublisherEvidence evidence;
};

TrustResult runTrustCheck(WINTRUST_DATA &data)
{
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    TrustResult result;
    result.status = ::WinVerifyTrust(nullptr, &policy, &data);
    result.evidence.errorCode = static_cast<quint32>(result.status);

    readSignerEvidence(::WTHelperProvDataFromStateData(data.hWVTStateData), result.evidence);

    // Releasing the state frees the provider data read above.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(nullptr, &policy, &data);
    return result;
}

bool isNoSignatureResult(LONG status)
{
    return status == static_cast<LONG>(TRUST_E_NOSIGNATURE)
        || status == static_cast<LONG>(TRUST_E_SUBJECT_FORM_UNKNOWN)
        || status == static_cast<LONG>(TRUST_E_PROVIDER_UNKNOWN);
}

// The file has a signature, but the trust chain could not be completed with
// local evidence only. That is not the same as a bad signature.
bool isUnverifiedResult(LONG status)
{
    // The file itself could not be read: that is unavailable evidence, not a
    // bad signature.
    const LONG ioErrors[] = {
        static_cast<LONG>(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)),
        static_cast<LONG>(HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)),
        static_cast<LONG>(HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)),
        static_cast<LONG>(HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION)),
        static_cast<LONG>(HRESULT_FROM_WIN32(ERROR_LOCK_VIOLATION))
    };
    for (LONG error : ioErrors)
        if (status == error) return true;

    return status == static_cast<LONG>(CERT_E_CHAINING)
        || status == static_cast<LONG>(CRYPT_E_NOT_FOUND)
        || status == static_cast<LONG>(CRYPT_E_FILE_ERROR)
        || status == static_cast<LONG>(TRUST_E_CERT_SIGNATURE)
        || status == static_cast<LONG>(CRYPT_E_REVOCATION_OFFLINE);
}

// Windows inbox binaries usually carry no embedded signature; they are signed
// through a catalog in CatRoot. Catalog membership is found by hashing the file
// and asking the catalog administrator, so no catalog path is guessed.
TrustResult runCatalogCheck(HANDLE file, const QString &path, bool &catalogFound)
{
    catalogFound = false;
    TrustResult result;
    result.status = static_cast<LONG>(TRUST_E_NOSIGNATURE);

    HCATADMIN admin = nullptr;
    if (!::CryptCATAdminAcquireContext(&admin, nullptr, 0) || !admin)
        return result;

    const std::wstring native = QDir::toNativeSeparators(path).toStdWString();

    DWORD hashSize = 0;
    ::CryptCATAdminCalcHashFromFileHandle(file, &hashSize, nullptr, 0);
    QByteArray hash(static_cast<int>(hashSize), '\0');
    if (hashSize == 0
        || !::CryptCATAdminCalcHashFromFileHandle(
               file, &hashSize, reinterpret_cast<BYTE *>(hash.data()), 0)) {
        ::CryptCATAdminReleaseContext(admin, 0);
        return result;
    }

    HCATINFO catalog =
        ::CryptCATAdminEnumCatalogFromHash(admin, reinterpret_cast<BYTE *>(hash.data()),
                                          hashSize, 0, nullptr);
    if (!catalog) {
        ::CryptCATAdminReleaseContext(admin, 0);
        return result;
    }
    catalogFound = true;

    CATALOG_INFO catalogInfo{};
    catalogInfo.cbStruct = sizeof(catalogInfo);
    if (!::CryptCATCatalogInfoFromContext(catalog, &catalogInfo, 0)) {
        ::CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
        ::CryptCATAdminReleaseContext(admin, 0);
        return result;
    }

    // The catalog member tag is the file hash as uppercase hex.
    const QString tagText = QString::fromLatin1(hash.toHex().toUpper());
    const std::wstring tag = tagText.toStdWString();

    WINTRUST_CATALOG_INFO catalogVerification{};
    catalogVerification.cbStruct = sizeof(catalogVerification);
    catalogVerification.dwCatalogVersion = 0;
    catalogVerification.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
    catalogVerification.pcwszMemberTag = tag.c_str();
    catalogVerification.pcwszMemberFilePath = native.c_str();
    catalogVerification.hMemberFile = file;
    catalogVerification.pbCalculatedFileHash = reinterpret_cast<BYTE *>(hash.data());
    catalogVerification.cbCalculatedFileHash = hashSize;

    WINTRUST_DATA data = makeVerifyData(WTD_CHOICE_CATALOG);
    data.pCatalog = &catalogVerification;
    result = runTrustCheck(data);

    ::CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
    ::CryptCATAdminReleaseContext(admin, 0);
    return result;
}

} // namespace

QString signerStatusName(ApplicationIdentity::SignerStatus status)
{
    switch (status) {
    case ApplicationIdentity::SignerStatus::Unsigned: return QStringLiteral("unsigned");
    case ApplicationIdentity::SignerStatus::Signed:   return QStringLiteral("signed");
    case ApplicationIdentity::SignerStatus::Invalid:  return QStringLiteral("invalid");
    case ApplicationIdentity::SignerStatus::Unknown:  break;
    }
    return QStringLiteral("unavailable");
}

PublisherEvidence PublisherResolver::resolve(const QString &canonicalPath)
{
    PublisherEvidence evidence;
    if (canonicalPath.trimmed().isEmpty()) {
        evidence.status = ApplicationIdentity::SignerStatus::Unknown;
        evidence.message = QStringLiteral("No executable path; signature not checked.");
        return evidence;
    }

    const QString key = QDir::cleanPath(QDir::toNativeSeparators(canonicalPath.trimmed())).toLower();
    const auto cached = m_cache.constFind(key);
    if (cached != m_cache.constEnd()) return cached.value();

    evidence = verify(canonicalPath);

    const bool definitive = evidence.status == ApplicationIdentity::SignerStatus::Signed
                         || evidence.status == ApplicationIdentity::SignerStatus::Unsigned;
    if (definitive) {
        if (m_cache.size() >= 512) m_cache.clear(); // bounded (NG-062)
        m_cache.insert(key, evidence);
    }
    return evidence;
}

PublisherEvidence PublisherResolver::verify(const QString &canonicalPath)
{
    PublisherEvidence evidence;
    evidence.status = ApplicationIdentity::SignerStatus::Unknown;

    const std::wstring native = QDir::toNativeSeparators(canonicalPath).toStdWString();
    if (native.empty()) {
        evidence.message = QStringLiteral("No executable path; signature not checked.");
        return evidence;
    }

    HANDLE file = ::CreateFileW(native.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        evidence.errorCode = ::GetLastError();
        evidence.message = QStringLiteral("Could not open the file for signature checking "
                                          "(Win32 error %1).").arg(evidence.errorCode);
        return evidence;
    }

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.hFile = file;

    WINTRUST_DATA data = makeVerifyData(WTD_CHOICE_FILE);
    data.pFile = &fileInfo;
    TrustResult trust = runTrustCheck(data);
    QString source = QStringLiteral("embedded signature");

    if (isNoSignatureResult(trust.status)) {
        bool catalogFound = false;
        const TrustResult catalog = runCatalogCheck(file, canonicalPath, catalogFound);
        if (catalogFound && !isNoSignatureResult(catalog.status)) {
            trust = catalog;
            source = QStringLiteral("catalog signature");
        }
    }

    ::CloseHandle(file);

    trust.evidence.status = ApplicationIdentity::SignerStatus::Unknown;
    if (trust.status == ERROR_SUCCESS) {
        trust.evidence.status = ApplicationIdentity::SignerStatus::Signed;
        trust.evidence.message = trust.evidence.publisher.isEmpty()
            ? QStringLiteral("Signature verified (%1).").arg(source)
            : QStringLiteral("Signature verified (%1), signed by %2.")
                  .arg(source, trust.evidence.publisher);
    } else if (isNoSignatureResult(trust.status)) {
        trust.evidence.status = ApplicationIdentity::SignerStatus::Unsigned;
        trust.evidence.message =
            QStringLiteral("File has no Authenticode signature, embedded or in a catalog.");
    } else if (isUnverifiedResult(trust.status)) {
        trust.evidence.message = QStringLiteral("Signature present but not verifiable with local "
                                                "trust data (HRESULT 0x%1).")
                                     .arg(static_cast<quint32>(trust.status), 8, 16, QLatin1Char('0'));
    } else {
        trust.evidence.status = ApplicationIdentity::SignerStatus::Invalid;
        trust.evidence.message = QStringLiteral("Authenticode signature is invalid (HRESULT 0x%1).")
                                     .arg(static_cast<quint32>(trust.status), 8, 16, QLatin1Char('0'));
    }

    if (trust.evidence.status != ApplicationIdentity::SignerStatus::Signed) {
        // A signer read from an untrusted chain is not a publisher. Keep only
        // the state, the error code, and the explanation.
        trust.evidence.publisher.clear();
        trust.evidence.organization.clear();
        trust.evidence.certificateSubject.clear();
        trust.evidence.certificateThumbprint.clear();
        trust.evidence.timestamp = QDateTime();
    }

    return trust.evidence;
}

} // namespace Oasis
