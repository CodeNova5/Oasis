# Legacy UI (excluded from the build)

These are the pre-redesign screens, kept for reference only. Nothing here is
compiled by `Oasis.pro`, and no shipping code includes these headers.

| File | Screen | Superseded by |
| --- | --- | --- |
| `firewallwidget.{h,cpp,ui}` | Policies | `OverviewPage` (controls in force) |
| `hardwarewidget.{h,cpp,ui}` | Hardware | `OverviewPage` + status bar |

The *backends* they used are untouched and still built:

- `src/firewall/firewallmanager.*`, `firewallmodel.*`, `rulenames.*`
- `src/hardware/hardwaremonitor.*` (owned by `MainWindow`, feeding the status
  bar and the taskbar overlay)

Data Saver, History and Settings never had separate files: their markup is
part of `src/ui/mainwindow.ui`. Those tab pages are detached and hidden at
startup and are unreachable from the shell. They are moved out of the build
when each screen is redesigned.
