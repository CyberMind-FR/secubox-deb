{ stdenv
, lib
, fetchFromGitHub
}:

stdenv.mkDerivation {
  pname = "binaries-marvell";
  version = "armada-SDK10.0.1.0";

  src = fetchFromGitHub {
    owner = "MarvellEmbeddedProcessors";
    repo = "binaries-marvell";
    rev = "b3d449e72196db5d48a2087c3df40b935834d304";
    sha256 = "0xpkzm2w2pifbswhnj8war3hqwndybmijqns7s9rz8wmajy5vhwv";
  };

  installPhase = ''
    install -D mrvl_scp_bl2.img $out/mrvl_scp_bl2.img
  '';

  dontFixup = true;

  meta = with lib; {
    description = "Marvell System Control Processor firmware";
    license = licenses.unfreeRedistributableFirmware;
    maintainers = with maintainers; [ lukegb ];
  };
}
