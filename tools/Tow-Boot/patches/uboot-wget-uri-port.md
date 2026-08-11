# U-Boot wget URI/port support (#748)

Tow-Boot base = U-Boot 2022.07. SecuBox netboot serves `boot.fit` on
`http://boot.gk2.secubox.in:8099/<MAC>/boot.fit` (port 8099, never 80 —
HAProxy owns :80). U-Boot's `wget` must therefore parse a non-80 port in
the URL.

Verification at build/bench: at the Tow-Boot prompt run
`wget ${loadaddr} http://192.168.1.200:8099/<MAC>/boot.fit`. If it ignores
the port (connects to :80) or errors on the URL, apply the upstream URI
parsing backport (commit parsing `host:port` in `do_wget`/`wget_start`)
via the `Tow-Boot.patches` list. If 2022.07 already honors the port, no
patch is needed and this file records that result.
