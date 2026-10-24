#include "bandwidthguard.h"
#include "networkmonitor.h"

#include <QDateTime>
#include <QSettings>
#include <QTimer>

#include <windows.h>

BandwidthGuard::BandwidthGuard(QObject *parent)
    : QObject(parent)
    , m_timer(new QTimer(this))
{
    m_timer->setInterval(1000);
    connect(m_timer, &QTimer::timeout, this, &BandwidthGuard::onTick);
    loadPersistentState();
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
        if (window.executablePath.isEmpty())
            window.executablePath = resolveExecutablePath(info.pid);
        window.isService = window.isService || info.isService;

        const ParsedPacket &packet = info.pkt;
        window.currentBytes += packet.wireLen ? packet.wireLen : packet.captureLen;
    }
}

void BandwidthGuard::reset()
{
    m_processes.clear();
}

void BandwidthGuard::exemptProcess(const QString &processName, int durationSeconds)
{
    const QString key = normalizeProcessName(processName);
    if (key.isEmpty()) return;

    m_exemptions.insert(key, QDateTime::currentSecsSinceEpoch() + durationSeconds);
    savePersistentState();
}

void BandwidthGuard::setCategoryOverride(const QString &processName, ProcessCategory category)
{
    const QString key = normalizeProcessName(processName);
    if (key.isEmpty()) return;

    m_categoryOverrides.insert(key, category);
    savePersistentState();
}

QString BandwidthGuard::normalizeProcessName(const QString &processName)
{
    return processName.trimmed().toLower();
}

QString BandwidthGuard::resolveExecutablePath(quint32 pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return {};

    wchar_t pathBuffer[32768] = {};
    DWORD pathLength = static_cast<DWORD>(std::size(pathBuffer));
    const BOOL resolved = QueryFullProcessImageNameW(process, 0, pathBuffer, &pathLength);
    CloseHandle(process);
    return resolved ? QString::fromWCharArray(pathBuffer, static_cast<int>(pathLength)) : QString();
}

bool BandwidthGuard::isExempt(const QString &processName)
{
    const QString key = normalizeProcessName(processName);
    const auto it = m_exemptions.find(key);
    if (it == m_exemptions.end()) return false;

    if (it.value() > QDateTime::currentSecsSinceEpoch()) return true;
    m_exemptions.erase(it);
    savePersistentState();
    return false;
}

ProcessCategory BandwidthGuard::categoryFor(const ProcessWindow &window, quint32 pid) const
{
    const QString key = normalizeProcessName(window.name);
    const auto overrideIt = m_categoryOverrides.constFind(key);
    if (overrideIt != m_categoryOverrides.constEnd()) return overrideIt.value();
    return classifyProcess(window.name, window.isService, pid);
}

void BandwidthGuard::loadPersistentState()
{
    QSettings settings;
    settings.beginGroup("BandwidthGuard");

    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const QVariantMap exemptions = settings.value("exemptions").toMap();
    for (auto it = exemptions.constBegin(); it != exemptions.constEnd(); ++it) {
        const qint64 expiry = it.value().toLongLong();
        if (expiry > now) m_exemptions.insert(it.key(), expiry);
    }

    const QVariantMap overrides = settings.value("categoryOverrides").toMap();
    for (auto it = overrides.constBegin(); it != overrides.constEnd(); ++it)
        m_categoryOverrides.insert(it.key(), static_cast<ProcessCategory>(it.value().toInt()));

    settings.endGroup();
}

void BandwidthGuard::savePersistentState() const
{
    QSettings settings;
    settings.beginGroup("BandwidthGuard");

    QVariantMap exemptions;
    for (auto it = m_exemptions.constBegin(); it != m_exemptions.constEnd(); ++it)
        exemptions.insert(it.key(), it.value());
    settings.setValue("exemptions", exemptions);

    QVariantMap overrides;
    for (auto it = m_categoryOverrides.constBegin(); it != m_categoryOverrides.constEnd(); ++it)
        overrides.insert(it.key(), static_cast<int>(it.value()));
    settings.setValue("categoryOverrides", overrides);
    settings.endGroup();
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

        if (isExempt(window.name)) {
            window.alerted = false;
            window.lowRateSeconds = 0;
            ++it;
            continue;
        }

        if (bytesLastMinute > DetectionBytesPerMinute) {
            window.lowRateSeconds = 0;
            if (!window.alerted) {
                window.alerted = true;
                BandwidthEvent event;
                event.processName = window.name;
                event.executablePath = window.executablePath;
                event.pid = it.key();
                event.bytesLastMinute = bytesLastMinute;
                event.bytesPerSecond = bytesLastMinute / WindowSeconds;
                event.category = categoryFor(window, it.key());
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