/**
 * @file    thememanager.h
 * @brief   Runtime theme owner for the NetGuard UI.
 *
 * Resolves `@token` placeholders in styles.qss against the palette in colors.h
 * plus the spacing/typography tokens, applies the resulting stylesheet, a
 * matching QPalette (so native menus/dialogs stay dark) and the application
 * font. All UI code asks this singleton for the current mode instead of
 * hard-coding colors.
 *
 * @author  Ali Sakkaf
 */
#pragma once
#include <QObject>
#include <QPalette>
#include <QString>

class QApplication;

class ThemeManager : public QObject
{
    Q_OBJECT
public:
    enum Mode { Dark, Light };
    Q_ENUM(Mode)

    static ThemeManager &instance();

    Mode mode() const { return m_mode; }
    bool isDark() const { return m_mode == Dark; }

    /// Resolved stylesheet for a mode (cached).
    QString styleSheetFor(Mode mode) const;

    /// Apply stylesheet, palette and font to the application. Defaults to qApp.
    void apply(QApplication *app = nullptr);

    /// Switch mode, re-apply and emit themeChanged(). No-op if unchanged.
    void setMode(Mode mode);
    void toggleTheme();

    /// QPalette used for native chrome (menus, tooltips, message boxes).
    static QPalette buildPalette(Mode mode);

signals:
    void themeChanged(ThemeManager::Mode mode);

private:
    explicit ThemeManager(QObject *parent = nullptr);

    static QString loadTemplate();
    static QString resolveTokens(const QString &templ, Mode mode);

    Mode    m_mode = Dark;
    QString m_template;
    mutable QString m_cache[2];
};
