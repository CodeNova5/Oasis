/**
 * @file    version.h
 * @brief   Centralized version and publisher metadata for Oasis.
 *          All modules should #include this file to access version constants.
 * @author  Oasis
 */
#pragma once

// ─── Version Numbers ─────────────────────────────────────────────────────────
#define APP_VERSION_MAJOR   1
#define APP_VERSION_MINOR   2
#define APP_VERSION_PATCH   0
#define APP_VERSION_BUILD   0

// Comma-separated for VERSIONINFO resource
#define APP_VERSION_RC      APP_VERSION_MAJOR,APP_VERSION_MINOR,APP_VERSION_PATCH,APP_VERSION_BUILD

// String versions
#define APP_VERSION_STR     "1.2.0"
#define APP_VERSION_RC_STR  "1.2.0.0"

// ─── Application Identity ────────────────────────────────────────────────────
#define APP_NAME            "Oasis"
#define APP_INTERNAL_NAME   "Oasis"
#define APP_DESCRIPTION     "Professional Network & System Monitor"
#define APP_ORIGINAL_NAME   "Oasis.exe"

// ─── Publisher / Author ──────────────────────────────────────────────────────
#define APP_AUTHOR          "Oasis"
#define APP_COMPANY         "Oasis"
#define APP_COPYRIGHT       "Copyright \\xA9 2026 Oasis. All Rights Reserved."

// ─── Online Presence ─────────────────────────────────────────────────────────
#define APP_WEBSITE         "https://github.com/CodeNova5/Oasis"
#define APP_GITHUB          "https://github.com/CodeNova5/Oasis"

// ─── Display String (used in UI header versionLabel) ─────────────────────────
#define APP_VERSION_DISPLAY "V1.2.0"
