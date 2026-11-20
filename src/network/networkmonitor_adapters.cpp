/**
 * @file    networkmonitor_adapters.cpp
 * @brief   Network adapter discovery and local-address refresh, split out of
 *          networkmonitor.cpp. Definitions only; the NetworkMonitor interface
 *          is unchanged.
 * @author  Oasis
 */
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif

#include "networkmonitor.h"

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

QList<AdapterInfo> NetworkMonitor::enumerateAdapters()
{
    QList<AdapterInfo> result;
    ULONG sz = 20000;
    QByteArray buf(static_cast<int>(sz), '\0');
    auto *addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &sz) != NO_ERROR)
        return result;

    for (auto *a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        bool gw = (a->FirstGatewayAddress != nullptr);

        QString ipv4, ipv6;
        for (auto *ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            SOCKADDR *sa = ua->Address.lpSockaddr;
            if (sa->sa_family == AF_INET) {
                char ipBuf[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(sa)->sin_addr, ipBuf, sizeof(ipBuf));
                ipv4 = QString::fromLatin1(ipBuf);
            } else if (sa->sa_family == AF_INET6) {
                char ipBuf[INET6_ADDRSTRLEN] = {};
                inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(sa)->sin6_addr, ipBuf, sizeof(ipBuf));
                ipv6 = QString::fromLatin1(ipBuf);
            }
        }

        if (!ipv4.isEmpty()) {
            AdapterInfo ai;
            ai.ip = ipv4;
            ai.ipv6 = ipv6; // IPv6 address
            ai.hasGateway = gw;
            ai.index = a->IfIndex;
            QString fn = a->FriendlyName ? QString::fromWCharArray(a->FriendlyName) : ai.ip;
            ai.description = fn + "  [" + ai.ip + "]" + (gw ? "  ★" : "");
            result.append(ai);
        }
    }
    return result;
}

// Smart Auto-Detect Adapter Index
int NetworkMonitor::recommendedAdapterIndex(const QList<AdapterInfo> &list)
{
    if (list.isEmpty()) return 0;

    auto isVirtual = [](const QString &description) {
        QString desc = description.toLower();
        return desc.contains("vmware") || desc.contains("virtual") || desc.contains("vbox") ||
               desc.contains("radmin") || desc.contains("pseudo") || desc.contains("zerotier") ||
               desc.contains("hamachi") || desc.contains("tap-") || desc.contains("tun-") ||
               desc.contains("wsl") || desc.contains("vethernet");
    };

    // 1. Check active IPv4 interface
    DWORD bestIfIndex = 0;
    if (GetBestInterface(inet_addr("8.8.8.8"), &bestIfIndex) == NO_ERROR) {
        for (int i = 0; i < list.size(); ++i) {
            if (list[i].index == bestIfIndex && !isVirtual(list[i].description)) {
                return i;
            }
        }
    }

    // 2. Check active IPv6 interface
    SOCKADDR_IN6 sa6 = {};
    sa6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:4860:4860::8888", &sa6.sin6_addr);
    MIB_IPFORWARD_ROW2 routeRow = {};
    SOCKADDR_INET bestDest = {};
    bestDest.Ipv6 = sa6;
    if (GetBestRoute2(nullptr, 0, nullptr, &bestDest, 0, &routeRow, nullptr) == NO_ERROR) {
        for (int i = 0; i < list.size(); ++i) {
            if (list[i].index == routeRow.InterfaceIndex && !isVirtual(list[i].description)) {
                return i;
            }
        }
    }

    // 3. Find physical adapter with highest active traffic (InOctets + OutOctets)
    int bestTrafficIdx = -1;
    quint64 maxBytes = 0;

    for (int i = 0; i < list.size(); ++i) {
        if (!isVirtual(list[i].description) && list[i].hasGateway) {
            MIB_IF_ROW2 row;
            ZeroMemory(&row, sizeof(row));
            row.InterfaceIndex = list[i].index;
            if (GetIfEntry2(&row) == NO_ERROR) {
                quint64 totalBytes = row.InOctets + row.OutOctets;
                if (totalBytes > maxBytes) {
                    maxBytes = totalBytes;
                    bestTrafficIdx = i;
                }
            }
        }
    }

    if (bestTrafficIdx != -1) return bestTrafficIdx;

    // 4. Fallback: First physical adapter with a Gateway
    for (int i = 0; i < list.size(); ++i) {
        if (list[i].hasGateway && !isVirtual(list[i].description)) {
            return i;
        }
    }

    // 5. Ultimate Fallback
    for (int i = 0; i < list.size(); ++i) {
        if (list[i].hasGateway) return i;
    }

    return 0;
}

void NetworkMonitor::refreshLocalIPs()
{
    m_localIPs.clear();
    ULONG sz = 15000;
    QByteArray buf(static_cast<int>(sz), '\0');
    auto *a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST, nullptr, a, &sz) != NO_ERROR) return;
    for (; a; a = a->Next)
        for (auto *ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            SOCKADDR *s = ua->Address.lpSockaddr;
            char ip[INET6_ADDRSTRLEN] = {};
            if      (s->sa_family==AF_INET)  inet_ntop(AF_INET,  &reinterpret_cast<sockaddr_in *>(s)->sin_addr,  ip, sizeof(ip));
            else if (s->sa_family==AF_INET6) inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(s)->sin6_addr, ip, sizeof(ip));
            if (ip[0]) m_localIPs << QString::fromLatin1(ip);
        }
}
