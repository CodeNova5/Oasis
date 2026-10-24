#include "bandwidthguard.h"
#include "networkmonitor.h"

#include <QTimer>

BandwidthGuard::BandwidthGuard(QObject *parent)
    : QObject(parent)
    , m_timer(new QTimer(this))
{
    m_timer->setInterval(1000);
    connect(m_timer, &QTimer::timeout, this, &BandwidthGuard::onTick);
    m_timer->start();
}

void BandwidthGuard::observe(const QList<CapturedPacketInfo> &batch)
{
    for (const CapturedPacketInfo &info : batch) {
        if (info.pid == 0) continue;

        ProcessWindow &window = m_processes[info.pid];
        if (!window.name.isEmpty() && window.name != info.proc)
            window = ProcessWindow{};
        window.name = info.proc.isEmpty() ? QString("PID %1").arg(info.pid) : info.proc;
        window.isService = window.isService || info.isService;

        const ParsedPacket &packet = info.pkt;
        window.currentBytes += packet.wireLen ? packet.wireLen : packet.captureLen;
    }
}

void BandwidthGuard::reset()
{
    m_processes.clear();
}

ProcessCategory BandwidthGuard::classifyProcess(const QString &processName,
                                                bool isService,
                                                quint32 pid)
{
    if (pid == 4 || isService) return ProcessCategory::Protected;

    const QString name = processName.trimmed().toLower();
    if (name == "chrome.exe" || name == "msedge.exe" || name == "firefox.exe" ||
        name == "brave.exe" || name == "steam.exe" || name == "epicgameslauncher.exe" ||
        name == "idman.exe") {
        return ProcessCategory::AskFirst;
    }

    if (name == "chromeupdate.exe" || name == "braveupdater.exe" ||
        name == "microsoftedgeupdate.exe" || name == "onedrive.exe" ||
        name == "deliveryoptimization.exe") {
        return ProcessCategory::AutoCandidate;
    }

    return ProcessCategory::Unknown;
}

void BandwidthGuard::onTick()
{
    for (auto it = m_processes.begin(); it != m_processes.end();) {
        ProcessWindow &window = it.value();
        window.buckets.append(window.currentBytes);
        window.currentBytes = 0;
        if (window.buckets.size() > WindowSeconds)
            window.buckets.remove(0, window.buckets.size() - WindowSeconds);

        quint64 bytesLastMinute = 0;
        for (quint64 bytes : window.buckets) bytesLastMinute += bytes;

        if (bytesLastMinute > DetectionBytesPerMinute) {
            window.lowRateSeconds = 0;
            if (!window.alerted) {
                window.alerted = true;
                BandwidthEvent event;
                event.processName = window.name;
                event.pid = it.key();
                event.bytesLastMinute = bytesLastMinute;
                event.bytesPerSecond = bytesLastMinute / WindowSeconds;
                event.category = classifyProcess(window.name, window.isService, it.key());
                emit sustainedBandwidthExceeded(event);
            }
        } else if (bytesLastMinute < ReleaseBytesPerMinute) {
            ++window.lowRateSeconds;
            if (window.lowRateSeconds >= ReleaseSeconds) {
                it = m_processes.erase(it);
                continue;
            }
        } else {
            window.lowRateSeconds = 0;
        }

        ++it;
    }
}