/**
 * @file   rulenames.h
 * @brief  Firewall rule naming (path-unique), independent of COM.
 * @author Codebuff
 */
#pragma once

#include <QString>

// Name of a Oasis firewall rule for one executable and one rule variant
// ("BLOCK_OUT", "BLOCK_IN", "ALLOW_OUT", "ALLOW_IN"). The full executable path
// is hashed into the name, so two files with the same base name in different
// folders never share (or overwrite) each other's rules.
QString firewallRuleName(const QString &appPath, const QString &suffix);

// The name older builds used: keyed by base name only. Still recognised so a
// re-applied or removed rule also cleans up its predecessor; collisions between
// same-named executables cannot be repaired retroactively.
QString legacyFirewallRuleName(const QString &appPath, const QString &suffix);
