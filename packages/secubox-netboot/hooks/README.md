# Hooks netboot (#737)

Drop-ins exécutables dans `/etc/secubox/netboot/hooks/<event>.d/*`, lancés en
ordre lexical par `secubox-netboot-triggers <event>`. Variables exportées :
`EVENT BOARD MODEL UBOOT_VER IMAGE_VER SLOT NETBOOT_DATA`.

Événements : `on-image-published pre-overlay post-overlay pre-flash post-flash
on-boot-success on-boot-fail on-version-mismatch`.
