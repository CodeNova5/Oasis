WinDivert runtime for download shaping
=====================================

Oasis shapes inbound (download) traffic with WinDivert. The library
is resolved at runtime, so the project builds and runs without it, but download
limits only take effect once these files are next to Oasis.exe.

Place the files in THIS folder; every build copies them into bin/
automatically.

    WinDivert.dll       (x64)
    WinDivert64.sys     (x64 driver, copied as well)

Steps
-----
1. Download WinDivert 2.2.x (x64) from https://reqrypt.org/windivert.html
2. Copy WinDivert.dll and WinDivert64.sys from the archive's x64 folder here.
3. Rebuild (run.sh or qmake + make). The files land next to the executable.

The loader also searches bin/, bin/windivert/, bin/windivert/x64/ and bin/x64/,
so dropping the two files into any of those works too.

Requirements and notes
----------------------
- Oasis must run elevated. WinDivert installs/opens a kernel driver and
  fails without administrator rights.
- Without these files the app still builds and runs: uploads are throttled by
  Windows QoS and the UI reports that download shaping is unavailable.
- 32-bit builds need WinDivert32.sys instead of WinDivert64.sys.
- WinDivert is (C) Basil Twitter / reqrypt.org, dual licensed LGPLv3 / GPLv2.
  Keep the archive's LICENSE file with the binaries when redistributing them.
- These binaries are not part of the repository; supply them yourself.
