#pragma once

#include <QString>

// Every bandwidth policy the app installs is named from the executable path, so
// the name can be recomputed wherever it is needed — apply, verification, and the
// startup sweep — without a second source of truth. Windows matches policy names
// case-insensitively.
namespace ThrottlePolicyNames {
QString prefix();
QString forPath(const QString &executablePath);
}
