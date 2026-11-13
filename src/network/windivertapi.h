/**
 * @file    windivertapi.h
 * @brief   Minimal WinDivert 2.x ABI surface, resolved at runtime.
 * @author  Oasis
 *
 * The declarations below mirror include/windivert.h from WinDivert 2.2. They
 * live here so the project builds without the WinDivert SDK: WinDivert.dll is
 * resolved with LoadLibrary() and the exports through GetProcAddress(), which
 * keeps the download shaper optional at runtime.
 *
 * Deployment: WinDivert.dll and WinDivert64.sys must sit next to the
 * executable (or in a windivert/, windivert/x64/ or x64/ subfolder). Opening a
 * handle also requires the application to run elevated.
 */
#pragma once

#include <QString>
#include <windows.h>

namespace windivert {

enum Layer : int {
    LayerNetwork = 0,
    LayerNetworkForward = 1,
    LayerFlow = 2,
    LayerSocket = 3,
    LayerReflect = 4
};

enum Flag : quint64 {
    FlagSniff = 0x0001,
    FlagDrop = 0x0002,
    FlagRecvOnly = 0x0004,
    FlagSendOnly = 0x0008,
    FlagNoInstall = 0x0010,
    FlagFragments = 0x0020
};

enum Param : int {
    ParamQueueLength = 0,
    ParamQueueTime = 1,
    ParamQueueSize = 2,
    ParamVersionMajor = 3,
    ParamVersionMinor = 4
};

enum ShutdownHow : int {
    ShutdownRecv = 0x1,
    ShutdownSend = 0x2,
    ShutdownBoth = 0x3
};

// Largest packet the driver can deliver (IPv6 header + max IPv6 payload).
constexpr int MtuMax = 40 + 0xFFFF;

struct DataNetwork
{
    UINT32 IfIdx;
    UINT32 SubIfIdx;
};

// WINDIVERT_ADDRESS, 80 bytes. Only Timestamp and Network are ever read here;
// the packet's own address is otherwise handed back to WinDivertSend verbatim.
struct Address
{
    INT64 Timestamp;
    UINT32 Layer:8;
    UINT32 Event:8;
    UINT32 Sniffed:1;
    UINT32 Outbound:1;
    UINT32 Loopback:1;
    UINT32 Impostor:1;
    UINT32 IPv6:1;
    UINT32 IPChecksum:1;
    UINT32 TCPChecksum:1;
    UINT32 UDPChecksum:1;
    UINT32 Reserved1:8;
    UINT32 Reserved2;
    union {
        DataNetwork Network;
        UINT8 Reserved3[64];
    };
};

static_assert(sizeof(Address) == 80, "WinDivert address ABI mismatch");

// Process-wide access to the WinDivert runtime.
class Api
{
public:
    static Api &instance();

    Api(const Api &) = delete;
    Api &operator=(const Api &) = delete;

    bool loaded() const { return m_loaded; }
    // Human readable reason why the runtime cannot be used, empty when loaded.
    QString unavailableReason() const { return m_reason; }
    QString modulePath() const { return m_modulePath; }

    HANDLE open(const char *filter, int layer, short priority, quint64 flags) const;
    BOOL recvEx(HANDLE handle, void *packet, UINT packetLen, UINT *recvLen, quint64 flags,
                Address *address, UINT *addressLen, LPOVERLAPPED overlapped) const;
    BOOL send(HANDLE handle, const void *packet, UINT packetLen, UINT *sendLen,
              const Address *address) const;
    BOOL shutdown(HANDLE handle, int how) const;
    BOOL close(HANDLE handle) const;
    BOOL setParam(HANDLE handle, int param, quint64 value) const;

private:
    Api();
    ~Api();

    bool resolve();

    using OpenFn = HANDLE (*)(const char *, int, short, quint64);
    using RecvExFn = BOOL (*)(HANDLE, void *, UINT, UINT *, quint64, Address *, UINT *, LPOVERLAPPED);
    using SendFn = BOOL (*)(HANDLE, const void *, UINT, UINT *, const Address *);
    using ShutdownFn = BOOL (*)(HANDLE, int);
    using CloseFn = BOOL (*)(HANDLE);
    using SetParamFn = BOOL (*)(HANDLE, int, quint64);

    bool m_loaded = false;
    QString m_reason;
    QString m_modulePath;
    HMODULE m_module = nullptr;

    OpenFn m_open = nullptr;
    RecvExFn m_recvEx = nullptr;
    SendFn m_send = nullptr;
    ShutdownFn m_shutdown = nullptr;
    CloseFn m_close = nullptr;
    SetParamFn m_setParam = nullptr;
};

} // namespace windivert
