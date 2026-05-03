{ lib, pkgs, ... }:

{
  device = {
    manufacturer = "Globalscale Technologies";
    name = "Mochabin";
    identifier = "globalscale-mochabin-8gb";
    productPageURL = "https://globalscaletechnologies.com/product/mochabin-copy/";
  };

  hardware = {
    soc = "armada-7040";
    mmcBootIndex = "0";  # Enable eMMC boot partition support (mmc partconf)
    marvell.ble = "${pkgs.Tow-Boot.armTrustedFirmwareMochabin8GBBLE}/ble.bin";
    marvell.globalscale.mochabin.enable = true;
  };
}
