/**
 * @file    windivertapi.cpp
 * @author  Oasis
 */
#include "windivertapi.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QStringList>

namespace windivert {
namespace {

QStringList dllCandidates()
{
    const QString appDir = QCoreApplication::applicationDirPath();
    if (appDir.isEmpty())
        return {QStringLiteral("WinDivert.dll")};

    const QStringList relative{
        QStringLiteral("WinDivert.dll"),
        QStringLiteral("windivert/WinDivert.dll"),
        QStringLiteral("windivert/x64/WinDivert.dll"),
        QStringLiteral("x64/WinDivert.dll")
    };

    QStringList candidates;
    for (const QString &entry : relative)
        candidates << QDir::toNativeSeparators(appDir + QLatin1Char('/') + entry);
    return candidates;
}

} // namespace

Api &Api::instance()
{
    static Api api;
    return api;
}

Api::Api()
{
    m_loaded = resolve();
}

Api::~Api()
{
    if (m_module) {
        FreeLibrary(m_module);
        m_module = nullptr;
    }
}

bool Api::resolve()
{
    QString loadError;
    for (const QString &candidate : dllCandidates()) {
        if (!QFileInfo::exists(candidate))
            continue;

        m_module = LoadLibraryW(reinterpret_cast<const wchar_t *>(candidate.utf16()));
        if (m_module) {
            m_modulePath = candidate;
            break;
        }
        loadError = QStringLiteral("WinDivert.dll could not be loaded from %1 (error %2).")
                        .arg(QDir::toNativeSeparators(candidate))
                        .arg(GetLastError());
    }

    if (!m_module) {
        // Last resort: the normal DLL search order (PATH, system directories).
        m_module = LoadLibraryW(L"WinDivert.dll");
        if (m_module)
            m_modulePath = QStringLiteral("WinDivert.dll");
        else if (loadError.isEmpty())
            loadError = QStringLiteral("WinDivert.dll was not found next to the application.");
    }

    if (!m_module) {
        m_reason = loadError;
        return false;
    }

    m_open = reinterpret_cast<OpenFn>(GetProcAddress(m_module, "WinDivertOpen"));
    m_recvEx = reinterpret_cast<RecvExFn>(GetProcAddress(m_module, "WinDivertRecvEx"));
    m_send = reinterpret_cast<SendFn>(GetProcAddress(m_module, "WinDivertSend"));
    m_shutdown = reinterpret_cast<ShutdownFn>(GetProcAddress(m_module, "WinDivertShutdown"));
    m_close = reinterpret_cast<CloseFn>(GetProcAddress(m_module, "WinDivertClose"));
    m_setParam = reinterpret_cast<SetParamFn>(GetProcAddress(m_module, "WinDivertSetParam"));

    if (!m_open || !m_recvEx || !m_send || !m_shutdown || !m_close) {
        m_reason = QStringLiteral("%1 does not export the expected WinDivert 2.x API.")
                       .arg(QDir::toNativeSeparators(m_modulePath));
        FreeLibrary(m_module);
        m_module = nullptr;
        return false;
    }

    m_reason.clear();
    return true;
}

HANDLE Api::open(const char *filter, int layer, short priority, quint64 flags) const
{
    if (!m_open)
        return INVALID_HANDLE_VALUE;
    return m_open(filter, layer, priority, flags);
}

BOOL Api::recvEx(HANDLE handle, void *packet, UINT packetLen, UINT *recvLen, quint64 flags,
                 Address *address, UINT *addressLen, LPOVERLAPPED overlapped) const
{
    if (!m_recvEx) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return m_recvEx(handle, packet, packetLen, recvLen, flags, address, addressLen, overlapped);
}

BOOL Api::send(HANDLE handle, const void *packet, UINT packetLen, UINT *sendLen,
               const Address *address) const
{
    if (!m_send) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return m_send(handle, packet, packetLen, sendLen, address);
}

BOOL Api::shutdown(HANDLE handle, int how) const
{
    if (!m_shutdown)
        return FALSE;
    return m_shutdown(handle, how);
}

BOOL Api::close(HANDLE handle) const
{
    if (!m_close)
        return FALSE;
    return m_close(handle);
}

BOOL Api::setParam(HANDLE handle, int param, quint64 value) const
{
    if (!m_setParam)
        return FALSE;
    return m_setParam(handle, param, value);
}

} // namespace windivert
