#include "bandwidthguard.h"
#include "networkmonitor.h"

#include <QDateTime>
#include <QSettings>

#include <windows.h>

BandwidthGuard::BandwidthGuard(QObject *parent)
    : QObject(parent)
{
    loadPersistentState();
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

        // NG-015: keep the identity, publisher, and group evidence of this PID,
        // which the capture loop resolves on its own cadence. Only fill what is
        // still missing, so a later refresh can complete an early packet.
        if (window.identityId.isEmpty() && !info.identityId.isEmpty()) {
            window.identityId = info.identityId;
            window.displayName = info.identityName;
            window.publisher = info.identityPublisher;
            window.signerStatus = info.signerStatus;
        }
        if (window.groupId.isEmpty() && !info.groupId.isEmpty()) {
            window.groupId = info.groupId;
            window.groupName = info.groupName;
        }

        const ParsedPacket &packet = info.pkt;
        window.totalBytes += packet.wireLen ? packet.wireLen : packet.captureLen;

        if (!window.alerted && window.totalBytes > DetectionBytes && !isExempt(window.name)) {
            window.alerted = true;
            BandwidthEvent event;
            event.processName = window.name;
            event.executablePath = window.executablePath;
            event.pid = info.pid;
            event.totalBytes = window.totalBytes;
            event.category = resolveCategory(window, info.pid);
            emit sustainedBandwidthExceeded(event);
        }
    }
}

void BandwidthGuard::reset()
{
    m_processes.clear();
    m_groupCategories.clear();
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

ProcessCategory BandwidthGuard::resolveCategory(const ProcessWindow &window, quint32 pid)
{
    const QString key = normalizeProcessName(window.name);
    const auto overrideIt = m_categoryOverrides.constFind(key);
    if (overrideIt != m_categoryOverrides.constEnd()) return overrideIt.value();

    ClassificationEvidence evidence;
    evidence.pid = pid;
    evidence.processName = window.name;
    evidence.executablePath = window.executablePath;
    evidence.identityId = window.identityId;
    evidence.displayName = window.displayName;
    evidence.publisher = window.publisher;
    evidence.signerStatus = window.signerStatus;
    evidence.groupId = window.groupId;
    evidence.groupName = window.groupName;
    evidence.isService = window.isService;

    ProcessCategory category = classifyProcess(evidence);
    if (window.groupId.isEmpty()) return category;

    // NG-015 group evidence: a member with no rule of its own behaves like the
    // group it belongs to, so a helper or a renamed executable is classified
    // without a rule naming it.
    if (category == ProcessCategory::Unknown) {
        const auto groupIt = m_groupCategories.constFind(window.groupId);
        if (groupIt != m_groupCategories.constEnd()) category = groupIt.value();
    }

    // A group is only as actionable as its most cautious member: one member that
    // needs the user's consent keeps every member of the group from being acted
    // on automatically.
    ProcessCategory &groupCategory = m_groupCategories[window.groupId];
    if (categoryRank(category) > categoryRank(groupCategory)) groupCategory = category;
    return category;
}

int BandwidthGuard::categoryRank(ProcessCategory category)
{
    switch (category) {
    case ProcessCategory::AskFirst:      return 2;
    case ProcessCategory::AutoCandidate: return 1;
    case ProcessCategory::Protected:
    case ProcessCategory::Unknown:       break;
    }
    return 0;
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

namespace {

struct NameRule
{
    const char *name;
    ProcessCategory category;
};

// Executable-name rules carried over from the pre-NG-015 classifier. They run
// first and unchanged, so every category the product already assigned is still
// assigned to the same process.
const NameRule kNameRules[] = {
    { "chrome.exe",               ProcessCategory::AskFirst },
    { "msedge.exe",               ProcessCategory::AskFirst },
    { "firefox.exe",              ProcessCategory::AskFirst },
    { "brave.exe",                ProcessCategory::AskFirst },
    { "steam.exe",                ProcessCategory::AskFirst },
    { "epicgameslauncher.exe",    ProcessCategory::AskFirst },
    { "idman.exe",                ProcessCategory::AskFirst },
    { "chromeupdate.exe",         ProcessCategory::AutoCandidate },
    { "braveupdater.exe",         ProcessCategory::AutoCandidate },
    { "microsoftedgeupdate.exe",  ProcessCategory::AutoCandidate },
    { "onedrive.exe",             ProcessCategory::AutoCandidate },
    { "deliveryoptimization.exe", ProcessCategory::AutoCandidate }
};

struct IdentityRule
{
    const char *publisher; // lowercase fragment of the NG-011 publisher
    const char *product;   // lowercase fragment of the NG-010 display name
    ProcessCategory category;
};

// The same vendors the name rules know, matched on the signed publisher and the
// product metadata instead of the file name. Ordered, first match wins, and
// updaters come before the application they update because "Microsoft Edge
// Update" also contains "edge".
const IdentityRule kIdentityRules[] = {
    { "google",    "update",                  ProcessCategory::AutoCandidate },
    { "google",    "chrome",                  ProcessCategory::AskFirst },
    { "microsoft", "onedrive",                ProcessCategory::AutoCandidate },
    { "microsoft", "edge update",             ProcessCategory::AutoCandidate },
    { "microsoft", "edge",                    ProcessCategory::AskFirst },
    { "brave",     "update",                  ProcessCategory::AutoCandidate },
    { "brave",     "brave",                   ProcessCategory::AskFirst },
    { "mozilla",   "firefox",                 ProcessCategory::AskFirst },
    { "valve",     "steam",                   ProcessCategory::AskFirst },
    { "epic games", "epic",                   ProcessCategory::AskFirst },
    { "tonec",     "internet download manager", ProcessCategory::AskFirst }
};

ProcessCategory categoryForName(const QString &processName)
{
    const QString name = processName.trimmed().toLower();
    for (const NameRule &rule : kNameRules) {
        if (name == QLatin1String(rule.name)) return rule.category;
    }
    return ProcessCategory::Unknown;
}

ProcessCategory categoryForIdentity(const ClassificationEvidence &evidence)
{
    // A publisher is only present when NG-011 verified the signature, so an
    // unsigned or tampered executable can never borrow a vendor's rules.
    if (evidence.publisher.isEmpty()) return ProcessCategory::Unknown;

    const QString publisher = evidence.publisher.toLower();
    const QString product = evidence.displayName.toLower();
    if (product.isEmpty()) return ProcessCategory::Unknown;

    for (const IdentityRule &rule : kIdentityRules) {
        if (!publisher.contains(QLatin1String(rule.publisher))) continue;
        if (!product.contains(QLatin1String(rule.product))) continue;
        return rule.category;
    }
    return ProcessCategory::Unknown;
}

} // namespace

ProcessCategory BandwidthGuard::classifyProcess(const QString &processName,
                                               bool isService,
                                               quint32 pid)
{
    ClassificationEvidence evidence;
    evidence.pid = pid;
    evidence.processName = processName;
    evidence.isService = isService;
    return classifyProcess(evidence);
}

ProcessCategory BandwidthGuard::classifyProcess(const ClassificationEvidence &evidence)
{
    if (evidence.pid == 4 || evidence.isService) return ProcessCategory::Protected;

    const ProcessCategory byName = categoryForName(evidence.processName);
    if (byName != ProcessCategory::Unknown) return byName;

    return categoryForIdentity(evidence);
}
