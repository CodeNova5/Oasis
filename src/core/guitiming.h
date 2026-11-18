/**
 * @file    guitiming.h
 * @brief   Opt-in timing probes for GUI-thread work (OASIS_DEBUG_TIMING).
 * @author  Oasis
 */
#pragma once

#include <QDebug>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QString>

namespace Oasis {
namespace GuiTiming {

// One environment variable arms every probe in the build. Off (the default) it
// costs one branch per probe entry and nothing else, so the probes can stay in
// the shipped code.
inline bool enabled()
{
    static const bool on = qEnvironmentVariableIsSet("OASIS_DEBUG_TIMING");
    return on;
}

// Reports are appended here as well as raised through qInfo(): the product runs
// elevated with no console, so a log file is the copy that is always readable.
inline QFile &reportFile()
{
    static QFile file(QDir::temp().filePath(QStringLiteral("oasis-timing.log")));
    static const bool opened =
        file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text);
    Q_UNUSED(opened);
    return file;
}

/**
 * One call site's accumulated durations. Reports every kReportEvery samples,
 * which is about once a minute for a 1 Hz call and every fifteen seconds for a
 * 4 Hz one, so the log stays readable at either rate.
 *
 * GUI thread only: the counters are plain members and are never locked.
 */
class Probe
{
public:
    static constexpr qint64 kReportEvery = 60;

    explicit Probe(const char *name) : m_name(name) {}

    void add(qint64 microseconds)
    {
        ++m_count;
        m_totalUs += microseconds;
        if (microseconds > m_maxUs) m_maxUs = microseconds;
        if (m_count % kReportEvery != 0) return;

        const QString line = QStringLiteral("[timing] %1 n=%2 avg=%3 ms max=%4 ms")
                                 .arg(QLatin1String(m_name))
                                 .arg(m_count)
                                 .arg(m_totalUs / 1000.0 / static_cast<double>(m_count), 0, 'f', 2)
                                 .arg(m_maxUs / 1000.0, 0, 'f', 2);
        qInfo().noquote() << line;
        QFile &file = reportFile();
        if (file.isOpen()) {
            file.write(line.toUtf8());
            file.write("\n");
            file.flush();
        }
    }

private:
    const char *m_name;
    qint64 m_count = 0;
    qint64 m_totalUs = 0;
    qint64 m_maxUs = 0;
};

// RAII: records the enclosing scope's duration into its probe on destruction.
class Scope
{
public:
    explicit Scope(Probe &probe) : m_probe(probe)
    {
        if (enabled()) m_timer.start();
    }
    ~Scope()
    {
        if (m_timer.isValid()) m_probe.add(m_timer.nsecsElapsed() / 1000);
    }
    Scope(const Scope &) = delete;
    Scope &operator=(const Scope &) = delete;

private:
    Probe &m_probe;
    QElapsedTimer m_timer;
};

} // namespace GuiTiming
} // namespace Oasis
