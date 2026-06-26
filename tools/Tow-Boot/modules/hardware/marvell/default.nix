{ config, lib, pkgs, ... }:

let
  inherit (lib)
    mkIf
    mkMerge
    mkOption
    types
  ;
  inherit (config.hardware) mmcBootIndex;
  cfg = config.hardware.socs;
  cfgMarvell = config.hardware.marvell;
  armada8kSOCs = [
    "armada-7040"
  ];
  armadaSOCs = armada8kSOCs;
  anyArmada8k = lib.any (soc: config.hardware.socs.${soc}.enable) armada8kSOCs;
in
{
  options = {
    hardware.socs = {
      armada-7040.enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable when SoC is Armada 7040";
        internal = true;
      };
    };
    hardware.marvell = {
      arm-trusted-firmware = mkOption {
        type = types.path;
        description = ''
          Path to the arm-trusted-firmware to use for BL2/BL31.
        '';
      };
      scp_bl2 = mkOption {
        type = types.path;
        description = ''
          Path to the scp_bl2 to use for the secure world.
        '';
      };
      ble = mkOption {
        type = types.path;
        description = ''
          Path to the ble.bin (DRAM training, etc.)

          This may vary based on board variant.
        '';
      };
      doimageFlags = mkOption {
        type = types.str;
        default = "-l 0x4100000 -e 0x4100000 -t SLC -n 256";
        description = ''
          Flags to pass to Marvell's doimage tool.
        '';
      };

      globalscale.mochabin.enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable when board is a Mochabin variant";
      };
    };
  };

  config = mkMerge [
    {
      hardware.socList = armadaSOCs;
    }
    (mkIf cfgMarvell.globalscale.mochabin.enable {
      # secubox.netboot.enable deferred: the EXTRA_ENV_SETTINGS string needs
      # Kconfig-safe quote escaping before it can be embedded (#748).
      hardware.SPISize = 4 * 1024 * 1024;  # 4 MiB
      hardware.marvell = {
        arm-trusted-firmware = pkgs.Tow-Boot.armTrustedFirmwareMochabin;
        scp_bl2 = "${pkgs.Tow-Boot.binariesMarvell}/mrvl_scp_bl2.img";
      };
      Tow-Boot = {
        withLogo = false;  # no graphics
        config = [
          (helpers: with helpers; {
            SPI_FLASH_WINBOND = yes;
            SPI_FLASH_GIGADEVICE = yes;
            SPI_FLASH_ISSI = yes;

            ARCH_EARLY_INIT_R = yes;

            DM_MMC = yes;

            # --- SecuBox netboot (#748): HTTP wget + TFTP + signed-FIT verify ---
            # Requires upstream U-Boot >= 2023.07 (the version bump above) for
            # wget. CMD_WGET selects WGET + PROT_TCP. The MV88E6xxx DSA switch
            # driver and the embedded netboot env (EXTRA_ENV_SETTINGS) are
            # DEFERRED — not required for the WAN copper (mvpp2-2) HTTP path.
            NET = yes;
            CMD_NET = yes;
            CMD_DHCP = yes;
            CMD_TFTPBOOT = yes;
            CMD_PING = yes;
            CMD_WGET = yes;
            CMD_BOOTI = yes;

            # signed FIT verification (CSPN)
            FIT = yes;
            FIT_SIGNATURE = yes;
            RSA = yes;
            SHA256 = yes;

            # Marvell PPv2 SoC NIC + 88E1512 copper PHY (the WAN/mvpp2-2 port)
            MVPP2 = yes;
            PHY_MARVELL = yes;

            DEFAULT_DEVICE_TREE = freeform ''"armada-7040-mochabin"'';
          })
        ];
      };
    })
    (mkIf anyArmada8k {
      system.system = "aarch64-linux";

      # SecuBox netboot (#748): bump to upstream U-Boot 2023.07, which is the
      # first release that ships `wget`/PROT_TCP (absent in the 2022.07 Tow-Boot
      # fork). buildUBoot=true uses stock U-Boot (the fork has no 2023.07 tree).
      Tow-Boot.uBootVersion = lib.mkForce "2023.07";
      Tow-Boot.buildUBoot = lib.mkForce true;

      Tow-Boot.defconfig = lib.mkDefault "mvebu_db_armada8k_defconfig";
      # The lukegb armada8k fixup predates 2023.x and does not apply cleanly to
      # newer trees; only apply it on the older U-Boot it was written against.
      Tow-Boot.patches = lib.optionals (lib.versionOlder config.Tow-Boot.uBootVersion "2023.01") [(pkgs.buildPackages.fetchpatch {
        url = "https://github.com/lukegb/u-boot/commit/81954a0bdcec395642f3ca1184e8d5026204a481.patch";
        sha256 = "1487pc26ih06504s5jr8l6dc5gsv2lhg70s2dg5haz08brkr747b";
      })];
      Tow-Boot.builder = {
        additionalArguments = {
          BLE = cfgMarvell.ble;
          BL1 = "${cfgMarvell.arm-trusted-firmware}/bl1.bin";
          BL2 = "${cfgMarvell.arm-trusted-firmware}/bl2.bin";
          SCP_BL2 = cfgMarvell.scp_bl2;
          BL31 = "${cfgMarvell.arm-trusted-firmware}/bl31.bin";
        };
        nativeBuildInputs = [
          pkgs.buildPackages.Tow-Boot.armTrustedFirmwareTools
          pkgs.buildPackages.Tow-Boot.armTrustedFirmwareToolsMarvell

          # for kw-boot
          pkgs.buildPackages.ncurses
        ];
        installPhase = ''
          echo Creating fip from $BL2, $SCP_BL2, $BL31 and u-boot.bin >&2
          fiptool create \
            --tb-fw $BL2 \
            --scp-fw $SCP_BL2 \
            --soc-fw $BL31 \
            --nt-fw u-boot.bin \
            fip.bin
          fiptool info fip.bin

          echo Constructing boot image from BL1 and FIP
          install -m 644 $BL1 boot-image.bin
          truncate -s %128K boot-image.bin
          cat fip.bin >> boot-image.bin
          truncate -s %4 boot-image.bin

          echo Using Marvell doimage to attach $BLE to boot image >&2
          doimage ${cfgMarvell.doimageFlags} -b $BLE boot-image.bin Tow-Boot.$variant.bin

          cp Tow-Boot.$variant.bin $out/binaries/Tow-Boot.$variant.bin
        '';
      };
    })
  ];
}
