# nDPId arm64 binaries (CI-populated)

`nDPId` + `nDPIsrvd` are built by `.github/workflows/build-ndpid.yml`
(QEMU arm64 native build, bundled libnDPI via `cmake -DBUILD_NDPI=ON`) and
committed here, then shipped to `/usr/sbin` by `debian/rules`. Do not edit by
hand. Bump the nDPId ref via the workflow's `ndpid_ref` input. (#722)
