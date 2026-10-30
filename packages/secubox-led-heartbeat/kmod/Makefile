# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# Construction hors arbre du pilote leds-is31fl319x (IS31FL3199 du MOCHAbin).
# Appelé par DKMS (dkms.conf : KVER/KDIR fournis) ou à la main sur la cible :
#   make                       # noyau courant
#   make KVER=6.12.107+deb13-arm64
# Construction croisée : make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KDIR=...
# (ARCH/CROSS_COMPILE ne sont plus forcés : DKMS construit nativement sur la box).

obj-m := leds-is31fl319x.o

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
