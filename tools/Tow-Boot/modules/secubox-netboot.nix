# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: enhanced Tow-Boot netboot config (#748)
# Sets the default boot command to the SecuBox HTTP netboot sequence.
# Only active when the board opts in via `secubox.netboot.enable`.
#
# Boot sequence mirrors packages/secubox-netboot/boot/sbx-boot.cmd:
#   dhcp → wget boot.fit from ${sbx_srv}:${sbx_port} → bootm (FIT sig verify)
#   → fallback tftpboot Image/board.dtb/initrd.img → booti
#
# Provenance note: RSA public key embedding via `-K u-boot.dtb` is deferred to
# the installPhase on the Nix build host (Task 5) where the key is available.
# This module wires the Kconfig side; key injection is handled separately.

{ config, lib, ... }:

let
  inherit (lib) mkIf mkOption types;
  cfg = config.secubox.netboot;
in
{
  options.secubox.netboot = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable SecuBox HTTP netboot boot command + FIT key.";
    };
    server = mkOption {
      type = types.str;
      default = "192.168.1.200";
      description = "Default boot server IP (overridable at runtime via sbx_srv).";
    };
    httpPort = mkOption {
      type = types.int;
      default = 8099;
      description = "Netboot HTTP port (boot-vhost). Never 80.";
    };
  };

  config = mkIf cfg.enable {
    Tow-Boot.config = [
      (helpers: with helpers; {
        # USE_BOOTCOMMAND / BOOTCOMMAND: run the sbx_netboot env var as the
        # default boot command. The env var is defined in EXTRA_ENV_SETTINGS.
        USE_BOOTCOMMAND = yes;
        BOOTCOMMAND = freeform ''"run sbx_netboot"'';

        # EXTRA_ENV_SETTINGS injects the SecuBox netboot sequence into U-Boot's
        # compiled-in environment.  Entries are NUL-separated C string literals.
        #
        # Nix escaping in double-quoted "…" strings:
        #   ${cfg.server}            → Nix interpolation → e.g. 192.168.1.200
        #   ${toString cfg.httpPort} → Nix interpolation → e.g. 8099
        #   \${sbx_srv}              → escaped \${ → literal ${sbx_srv} for U-Boot
        #   \0                       → backslash + 0 (Nix does not interpret \0);
        #                              C compiler turns \0 into NUL in the
        #                              CONFIG_EXTRA_ENV_SETTINGS C string literal.
        EXTRA_ENV_SETTINGS = freeform (
          # Compiled-in default server/port (Nix-interpolated at build time):
          "\"sbx_srv=${cfg.server}\\0"
          + "sbx_port=${toString cfg.httpPort}\\0"
          # sbx_netboot: SecuBox HTTP netboot sequence with TFTP fallback.
          # U-Boot variable references use \${ escape → literal ${…} at runtime.
          + "sbx_netboot="
          + "setenv autoload no; "
          + "if dhcp; then : ; fi; "
          + "if test -z \"\${sbx_srv}\"; then setenv sbx_srv \${serverip}; fi; "
          + "if test -z \"\${sbx_id}\"; then setenv sbx_id \${ethaddr}; fi; "
          + "if wget \${loadaddr} http://\${sbx_srv}:\${sbx_port}/\${sbx_id}/boot.fit; "
          + "then bootm \${loadaddr}; fi; "
          + "if tftpboot \${kernel_addr_r} \${sbx_srv}:\${sbx_id}/Image; then "
          + "tftpboot \${fdt_addr_r} \${sbx_srv}:\${sbx_id}/board.dtb; "
          + "if tftpboot \${ramdisk_addr_r} \${sbx_srv}:\${sbx_id}/initrd.img; then "
          + "booti \${kernel_addr_r} \${ramdisk_addr_r}:\${filesize} \${fdt_addr_r}; "
          + "else booti \${kernel_addr_r} - \${fdt_addr_r}; fi; fi\\0\""
        );
      })
    ];
  };
}
