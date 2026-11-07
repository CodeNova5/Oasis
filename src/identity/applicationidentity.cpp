/**
 * @file    applicationidentity.cpp
 * @brief   Canonical application identity resolver (NG-010).
 */

#include "identity/applicationidentity.h"

#include <QByteArray>
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QSettings>

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <winver.h>

#include <string>

namespace NetGuard {
namespace {

QString stripLongPathPrefix(QString path)
{
    if (path.startsWith(QStringLiteral("\\\\?\\UNC\\")))
        return QStringLiteral("\\\\") + path.mid(8);
    if (path.startsWith(QStringLiteral("\\\\?\\")))
        return path.mid(4);
    return path;
}

QString normalizedSeparators(const QString &path)
{
    QString result = path;
    result.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return result;
}

QString readVersionString(const QByteArray &block, const QString &subBlock)
{
    LPVOID value = nullptr;
    UINT valueBytes = 0;
    if (!VerQueryValueW(block.constData(),
                        reinterpret_cast<LPCWSTR>(subBlock.utf16()),
                        &value, &valueBytes)
        || !value || valueBytes == 0) {
        return QString();
    }

    // Version strings are NUL-terminated. The reported byte count is not a
    // reliable character count (some resources report it in characters), so it
    // must not be used to size the string: doing so cut every name in half and
    // turned "Google Chrome" into "Google".
    QString text = QString::fromWCharArray(static_cast<const wchar_t *>(value));
    const int terminator = text.indexOf(QChar('\0'));
    if (terminator >= 0) text.truncate(terminator);
    return text.trimmed();
}

} // namespace

QString identityResolutionStatusName(IdentityResolutionStatus status)
{
    switch (status) {
    case IdentityResolutionStatus::Resolved:        return QStringLiteral("resolved");
    case IdentityResolutionStatus::AccessDenied:    return QStringLiteral("access-denied");
    case IdentityResolutionStatus::ProcessNotFound: return QStringLiteral("process-not-found");
    case IdentityResolutionStatus::KernelProcess:   return QStringLiteral("kernel-process");
    case IdentityResolutionStatus::InvalidPath:     return QStringLiteral("invalid-path");
    case IdentityResolutionStatus::FileNotFound:    return QStringLiteral("file-not-found");
    case IdentityResolutionStatus::UnknownError:    return QStringLiteral("unknown-error");
    }
    return QStringLiteral("unknown-error");
}

// ─── IdentityStore ──────────────────────────────────────────────────────────

IdentityStore::IdentityStore() = default;

QString IdentityStore::pathKey(const QString &path)
{
    QString key = normalizedSeparators(QDir::cleanPath(path.trimmed()));
    return key.toLower();
}

void IdentityStore::ensureLoaded() const
{
    if (m_loaded) return;
    m_loaded = true;

    QSettings settings;
    settings.beginGroup(QStringLiteral("IdentityStore"));
    const int version = settings.value(QStringLiteral("schemaVersion"), 0).toInt();
    const QStringList payloads = settings.value(QStringLiteral("identities")).toStringList();
    settings.endGroup();

    // Unknown or missing schema: start empty instead of guessing at old data.
    if (version != 1) return;

    for (const QString &payload : payloads) {
        const ApplicationIdentity identity = fromJsonApplicationIdentity(payload);
        if (identity.id.isEmpty()) continue;
        m_byId.insert(identity.id, identity);
        for (const QString &path : identity.executablePaths) {
            if (!path.isEmpty())
                m_idByPathKey.insert(pathKey(path), identity.id);
        }
    }
}

void IdentityStore::save() const
{
    QStringList payloads;
    payloads.reserve(m_byId.size());
    for (auto it = m_byId.constBegin(); it != m_byId.constEnd(); ++it)
        payloads.append(toJson(it.value()));

    QSettings settings;
    settings.beginGroup(QStringLiteral("IdentityStore"));
    settings.setValue(QStringLiteral("schemaVersion"), 1);
    settings.setValue(QStringLiteral("identities"), payloads);
    settings.endGroup();
}

ApplicationIdentity IdentityStore::findById(const QString &id) const
{
    ensureLoaded();
    return m_byId.value(id);
}

ApplicationIdentity IdentityStore::findByCanonicalPath(const QString &canonicalPath) const
{
    ensureLoaded();
    const QString id = m_idByPathKey.value(pathKey(canonicalPath));
    if (id.isEmpty()) return ApplicationIdentity{};
    return m_byId.value(id);
}

void IdentityStore::upsert(const ApplicationIdentity &identity)
{
    if (identity.id.isEmpty()) return;
    ensureLoaded();

    const auto existing = m_byId.constFind(identity.id);
    if (existing != m_byId.constEnd()) {
        for (const QString &path : existing.value().executablePaths)
            m_idByPathKey.remove(pathKey(path));
    }

    m_byId.insert(identity.id, identity);
    for (const QString &path : identity.executablePaths) {
        if (!path.isEmpty())
            m_idByPathKey.insert(pathKey(path), identity.id);
    }
    save();
}

QList<ApplicationIdentity> IdentityStore::all() const
{
    ensureLoaded();
    return m_byId.values();
}

int IdentityStore::count() const
{
    ensureLoaded();
    return m_byId.size();
}

void IdentityStore::clear()
{
    ensureLoaded();
    m_byId.clear();
    m_idByPathKey.clear();
    save();
}

// ─── ApplicationIdentityResolver ────────────────────────────────────────────

ApplicationIdentityResolver::ApplicationIdentityResolver(IdentityStore *store)
    : m_store(store ? store : &m_ownedStore)
{
}

QString ApplicationIdentityResolver::canonicalPath(const QString &path)
{
    QString cleaned = path.trimmed();
    if (cleaned.isEmpty()) return QString();

    // Service ImagePath values are frequently quoted.
    if (cleaned.size() > 1 && cleaned.startsWith(QLatin1Char('"'))
        && cleaned.endsWith(QLatin1Char('"'))) {
        cleaned = cleaned.mid(1, cleaned.size() - 2);
    }
    cleaned = stripLongPathPrefix(cleaned);
    if (cleaned.isEmpty()) return QString();

    // Reject values that cannot be a filesystem path.
    for (const QChar ch : cleaned) {
        if (ch.unicode() < 0x20 || ch == QLatin1Char('*') || ch == QLatin1Char('?')
            || ch == QLatin1Char('<') || ch == QLatin1Char('>') || ch == QLatin1Char('|')) {
            return QString();
        }
    }

    const std::wstring native = QDir::toNativeSeparators(cleaned).toStdWString();
    wchar_t fullPath[32768] = {};
    const DWORD fullLen = ::GetFullPathNameW(native.c_str(), 32768, fullPath, nullptr);
    QString result = fullLen > 0
        ? QString::fromWCharArray(fullPath, static_cast<int>(fullLen))
        : QDir::toNativeSeparators(cleaned);

    // Opening the final target resolves 8.3 short names, junctions, and
    // symlinks so equivalent spellings collapse to one path.
    HANDLE handle = ::CreateFileW(
        reinterpret_cast<LPCWSTR>(result.utf16()),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
        wchar_t finalPath[32768] = {};
        const DWORD finalLen = ::GetFinalPathNameByHandleW(
            handle, finalPath, 32768, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        ::CloseHandle(handle);
        if (finalLen > 0 && finalLen < 32768) {
            result = stripLongPathPrefix(
                QString::fromWCharArray(finalPath, static_cast<int>(finalLen)));
        }
    }

    result = normalizedSeparators(QDir::cleanPath(normalizedSeparators(result)));
    while (result.size() > 3 && result.endsWith(QLatin1Char('\\')))
        result.chop(1);
    return result;
}

QString ApplicationIdentityResolver::identityIdForCanonicalPath(const QString &canonicalPath)
{
    const QString key = IdentityStore::pathKey(canonicalPath);
    if (key.isEmpty()) return QString();

    const QByteArray digest = QCryptographicHash::hash(
        key.toUtf8(), QCryptographicHash::Sha1).toHex();
    return QStringLiteral("path:") + QString::fromLatin1(digest);
}

FileVersionMetadata ApplicationIdentityResolver::readVersionMetadata(const QString &canonicalPath)
{
    FileVersionMetadata metadata;
    if (canonicalPath.isEmpty()) return metadata;

    const std::wstring native = QDir::toNativeSeparators(canonicalPath).toStdWString();
    DWORD ignored = 0;
    const DWORD size = ::GetFileVersionInfoSizeW(native.c_str(), &ignored);
    if (size == 0) return metadata;

    QByteArray block(static_cast<int>(size), '\0');
    if (!::GetFileVersionInfoW(native.c_str(), 0, size, block.data()))
        return metadata;

    struct Translation { WORD language; WORD codePage; };
    Translation *translations = nullptr;
    UINT translationBytes = 0;
    if (!VerQueryValueW(block.constData(), L"\\VarFileInfo\\Translation",
                        reinterpret_cast<LPVOID *>(&translations), &translationBytes)
        || translationBytes < sizeof(Translation) || !translations) {
        return metadata;
    }

    const QString language = QStringLiteral("%1").arg(
        translations[0].language, 4, 16, QLatin1Char('0'));
    const QString codePage = QStringLiteral("%1").arg(
        translations[0].codePage, 4, 16, QLatin1Char('0'));

    const auto query = [&](const wchar_t *field) -> QString {
        const QString subBlock = QStringLiteral("\\StringFileInfo\\%1%2\\%3")
            .arg(language)
            .arg(codePage)
            .arg(QString::fromWCharArray(field));
        return readVersionString(block, subBlock);
    };

    metadata.companyName      = query(L"CompanyName");
    metadata.productName      = query(L"ProductName");
    metadata.originalFileName = query(L"OriginalFilename");
    metadata.fileDescription  = query(L"FileDescription");
    metadata.fileVersion      = query(L"FileVersion");
    metadata.internalName     = query(L"InternalName");
    return metadata;
}

IdentityResolution ApplicationIdentityResolver::resolveExecutablePath(const QString &path)
{
    IdentityResolution resolution;

    if (path.trimmed().isEmpty()) {
        resolution.status = IdentityResolutionStatus::InvalidPath;
        resolution.message = QStringLiteral("Executable path is empty.");
        return resolution;
    }

    const QString canonical = canonicalPath(path);
    if (canonical.isEmpty()) {
        resolution.status = IdentityResolutionStatus::InvalidPath;
        resolution.message = QStringLiteral("Not a usable filesystem path: %1").arg(path);
        return resolution;
    }

    const QFileInfo info(canonical);
    if (!info.exists() || !info.isFile()) {
        resolution.status = IdentityResolutionStatus::FileNotFound;
        resolution.message = QStringLiteral("Executable no longer exists at %1").arg(canonical);
        resolution.identity.executablePaths = QStringList{canonical};
        return resolution;
    }

    const QString id = identityIdForCanonicalPath(canonical);
    ApplicationIdentity identity = m_store->findById(id); // persisted evidence, may be empty

    const FileVersionMetadata metadata = readVersionMetadata(canonical);
    identity.id = id;
    if (!identity.executablePaths.contains(canonical))
        identity.executablePaths.prepend(canonical);
    identity.processNames = QStringList{info.fileName().toLower()};

    // Fresh metadata wins; persisted values survive when the file's version
    // resource becomes unreadable (for example after an in-place update).
    if (!metadata.companyName.isEmpty())      identity.companyName = metadata.companyName;
    if (!metadata.productName.isEmpty())      identity.productName = metadata.productName;
    if (!metadata.originalFileName.isEmpty()) identity.originalFileName = metadata.originalFileName;
    if (!metadata.fileVersion.isEmpty())      identity.fileVersion = metadata.fileVersion;

    QString display = metadata.productName;
    if (display.isEmpty()) display = metadata.fileDescription;
    if (display.isEmpty()) display = metadata.originalFileName;
    if (display.isEmpty()) display = identity.displayName;
    if (display.isEmpty()) display = info.fileName();
    identity.displayName = display;

    if (!metadata.productName.isEmpty() || !metadata.originalFileName.isEmpty())
        identity.confidence = ApplicationIdentity::Confidence::Confirmed;
    else if (!identity.displayName.isEmpty())
        identity.confidence = ApplicationIdentity::Confidence::StrongInference;
    else
        identity.confidence = ApplicationIdentity::Confidence::WeakInference;

    // NG-011: Authenticode evidence. A failed or unavailable check is recorded
    // as a signer state and never stops the identity from resolving.
    const PublisherEvidence signature = m_publisherResolver.resolve(canonical);
    identity.signerStatus = signature.status;
    if (signature.status == ApplicationIdentity::SignerStatus::Signed) {
        if (!signature.publisher.isEmpty()) identity.publisher = signature.publisher;
    } else {
        // Never attribute a publisher when the signature is absent, invalid, or
        // unverifiable; a persisted publisher would be misleading.
        identity.publisher.clear();
    }
    identity.fingerprints = signature.certificateThumbprint;

    resolution.status = IdentityResolutionStatus::Resolved;
    resolution.identity = identity;
    resolution.message = QStringLiteral("Resolved %1 from canonical path.").arg(display);
    m_store->upsert(identity);
    return resolution;
}

IdentityResolution ApplicationIdentityResolver::resolvePid(quint32 pid)
{
    IdentityResolution resolution;

    if (pid == 0) {
        resolution.status = IdentityResolutionStatus::ProcessNotFound;
        resolution.message = QStringLiteral("PID 0 is the Windows idle process and has no executable.");
        return resolution;
    }
    if (pid == 4) {
        resolution.status = IdentityResolutionStatus::KernelProcess;
        resolution.message = QStringLiteral("PID 4 is the Windows kernel and has no user-mode executable.");
        return resolution;
    }

    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        const DWORD error = ::GetLastError();
        resolution.errorCode = error;
        switch (error) {
        case ERROR_ACCESS_DENIED:
            resolution.status = IdentityResolutionStatus::AccessDenied;
            resolution.message = QStringLiteral("Access denied opening PID %1.").arg(pid);
            break;
        case ERROR_INVALID_PARAMETER:
            resolution.status = IdentityResolutionStatus::ProcessNotFound;
            resolution.message = QStringLiteral("PID %1 is no longer running.").arg(pid);
            break;
        default:
            resolution.status = IdentityResolutionStatus::UnknownError;
            resolution.message = QStringLiteral("OpenProcess(%1) failed with Win32 error %2.")
                                     .arg(pid).arg(error);
            break;
        }
        return resolution;
    }

    wchar_t pathBuffer[32768] = {};
    DWORD pathLength = static_cast<DWORD>(32768);
    const BOOL queried = ::QueryFullProcessImageNameW(process, 0, pathBuffer, &pathLength);
    const DWORD queryError = queried ? ERROR_SUCCESS : ::GetLastError();
    ::CloseHandle(process);

    if (!queried) {
        resolution.status = (queryError == ERROR_ACCESS_DENIED)
            ? IdentityResolutionStatus::AccessDenied
            : IdentityResolutionStatus::UnknownError;
        resolution.errorCode = queryError;
        resolution.message = QStringLiteral("Could not read the executable path for PID %1 "
                                            "(Win32 error %2).")
                                 .arg(pid).arg(queryError);
        return resolution;
    }

    const QString executablePath =
        QString::fromWCharArray(pathBuffer, static_cast<int>(pathLength));
    return resolveExecutablePath(executablePath);
}

} // namespace NetGuard
