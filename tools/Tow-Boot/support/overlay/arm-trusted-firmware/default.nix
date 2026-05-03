# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (c) 2003-2021 Eelco Dolstra and the Nixpkgs/NixOS contributors
# SPDX-FileCopyrightText: Copyright (c) 2021 Samuel Dionne-Riel and respective contributors
#
# This file originates from the Nixpkgs project.
# It does not need to be kept synchronized.
#
# Origin: https://github.com/NixOS/nixpkgs/blob/0cbb80e7f162fac25fdd173d38136068ed6856bb/pkgs/misc/arm-trusted-firmware/default.nix

{ lib, stdenv, fetchFromGitHub, openssl, pkgsCross, buildPackages, git }:

let
  buildArmTrustedFirmware = { filesToInstall
            , installDir ? "$out"
            , platform ? null
            , extraMakeFlags ? []
            , extraMeta ? {}
            , version ? "2.9"
            , ... } @ args:
           stdenv.mkDerivation ({

    name = "arm-trusted-firmware${lib.optionalString (platform != null) "-${platform}"}-${version}";
    inherit version;

    src = fetchFromGitHub {
      owner = "ARM-software";
      repo = "arm-trusted-firmware";
      rev = "v${version}";
      sha256 = "sha256-F7RNYNLh0ORzl5PmzRX9wGK8dZgUQVLKQg1M9oNd0pk=";
    };

    depsBuildBuild = [ buildPackages.stdenv.cc ];

    # For Cortex-M0 firmware in RK3399
    nativeBuildInputs = [ pkgsCross.arm-embedded.stdenv.cc ];

    buildInputs = [ openssl ];

    makeFlags = [
      "CROSS_COMPILE=${stdenv.cc.targetPrefix}"
    ] ++ (lib.optional (platform != null) "PLAT=${platform}")
      ++ extraMakeFlags;

    installPhase = ''
      runHook preInstall

      mkdir -p ${installDir}
      cp ${lib.concatStringsSep " " filesToInstall} ${installDir}

      runHook postInstall
    '';

    hardeningDisable = [ "all" ];
    dontStrip = true;

    # Fatal error: can't create build/sun50iw1p1/release/bl31/sunxi_clocks.o: No such file or directory
    enableParallelBuilding = false;

    meta = with lib; {
      homepage = "https://github.com/ARM-software/arm-trusted-firmware";
      description = "A reference implementation of secure world software for ARMv8-A";
      license = licenses.bsd3;
      maintainers = with maintainers; [ lopsided98 ];
    } // extraMeta;
  } // builtins.removeAttrs args [ "extraMeta" ]);

  buildArmTrustedFirmwareMarvellBLE = let
    mv-ddr = fetchFromGitHub {
      owner = "MarvellEmbeddedProcessors";
      repo = "mv-ddr-marvell";
      # master as of 2024-07-09
      rev = "4a3dc0909b64fac119d4ffa77840267b540b17ba";
      hash = "sha256-atsj0FCEkMLfnABsaJZGHKO0ZKad19jsKAkz39fIcFY=";
    };
  in { platform
  , mvDdrSrc ? mv-ddr
  , extraMeta ? {}
  , ... }@args: buildArmTrustedFirmware ({
    extraMakeFlags = [
      "SCP_BL2=/dev/null"
      "ble"
    ];

    postPatch = ''
      export MV_DDR_PATH=$NIX_BUILD_TOP/mv-ddr
      cp -R ${mv-ddr} $MV_DDR_PATH
      chmod -R +w $MV_DDR_PATH
      git -C $MV_DDR_PATH init
      sed -i 's,-Werror,-Wno-error,g' $MV_DDR_PATH/Makefile
    '';

    nativeBuildInputs = [ pkgsCross.arm-embedded.stdenv.cc git ];

    inherit platform;
    extraMeta = extraMeta // {
      platforms = ["aarch64-linux"];
    };
    filesToInstall = [
      "build/${platform}/release/ble.bin"
    ];
  } // builtins.removeAttrs args [ "mvDdrSrc" "extraMeta" ]);

in {
  inherit buildArmTrustedFirmware;

  armTrustedFirmwareTools = buildArmTrustedFirmware rec {
    extraMakeFlags = [
      "HOSTCC=${stdenv.cc.targetPrefix}gcc"
      "fiptool" "certtool"
    ];
    filesToInstall = [
      "tools/fiptool/fiptool"
      "tools/cert_create/cert_create"
    ];
    postInstall = ''
      mkdir -p "$out/bin"
      find "$out" -type f -executable -exec mv -t "$out/bin" {} +
    '';
  };

  armTrustedFirmwareToolsMarvell = buildArmTrustedFirmware rec {
    extraMakeFlags = [
      "HOSTCC=${stdenv.cc.targetPrefix}gcc"
      "-C" "tools/marvell/doimage"
      "doimage"
    ];
    filesToInstall = [
      "tools/marvell/doimage/doimage"
    ];
    postInstall = ''
      mkdir -p "$out/bin"
      find "$out" -type f -executable -exec mv -t "$out/bin" {} +
    '';
  };

  armTrustedFirmwareAllwinner = buildArmTrustedFirmware rec {
    platform = "sun50i_a64";
    extraMeta.platforms = ["aarch64-linux"];
    filesToInstall = ["build/${platform}/release/bl31.bin"];
  };

  armTrustedFirmwareQemu = buildArmTrustedFirmware rec {
    platform = "qemu";
    extraMeta.platforms = ["aarch64-linux"];
    filesToInstall = [
      "build/${platform}/release/bl1.bin"
      "build/${platform}/release/bl2.bin"
      "build/${platform}/release/bl31.bin"
    ];
  };

  armTrustedFirmwareRK3328 = buildArmTrustedFirmware rec {
    extraMakeFlags = [ "bl31" ];
    platform = "rk3328";
    extraMeta.platforms = ["aarch64-linux"];
    filesToInstall = [ "build/${platform}/release/bl31/bl31.elf"];
  };

  armTrustedFirmwareRK3399 = buildArmTrustedFirmware rec {
    extraMakeFlags = [ "bl31" ];
    platform = "rk3399";
    extraMeta.platforms = ["aarch64-linux"];
    filesToInstall = [ "build/${platform}/release/bl31/bl31.elf"];
  };

  armTrustedFirmwareS905 = buildArmTrustedFirmware rec {
    extraMakeFlags = [ "bl31" ];
    platform = "gxbb";
    extraMeta.platforms = ["aarch64-linux"];
    filesToInstall = [ "build/${platform}/release/bl31.bin"];
  };

  armTrustedFirmwareMochabin = buildArmTrustedFirmware rec {
    extraMakeFlags = [ "SCP_BL2=/dev/null" "bl1" "bl2" "bl31" ];
    platform = "a70x0_mochabin";
    extraMeta.platforms = ["aarch64-linux"];
    filesToInstall = [
      "build/${platform}/release/bl1.bin"
      "build/${platform}/release/bl2.bin"
      "build/${platform}/release/bl31.bin"
    ];
  };

  armTrustedFirmwareMochabin2GBBLE = buildArmTrustedFirmwareMarvellBLE {
    DDR_TOPOLOGY = 0;
    platform = "a70x0_mochabin";
  };
  armTrustedFirmwareMochabin4GBBLE = buildArmTrustedFirmwareMarvellBLE {
    DDR_TOPOLOGY = 1;
    platform = "a70x0_mochabin";
  };
  armTrustedFirmwareMochabin8GBBLE = buildArmTrustedFirmwareMarvellBLE {
    DDR_TOPOLOGY = 2;
    platform = "a70x0_mochabin";
  };
}
