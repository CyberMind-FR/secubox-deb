-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- MetaNews — index des images (#1835).
--
-- Le relais d'images vérifie, à CHAQUE image servie, que l'URL vient de nos
-- flux (ImageConnue : article.image, puis topic.vignette). Sans index, chaque
-- vérification lisait toute la table — mesuré sur gk2 le 2026-10-01 : 54 653
-- articles, 37 440 sujets, plan « SCAN article », 21 Go relus en 2 h 30.
-- Index COMPLETS, pas partiels : SQLite n'emploie un index partiel
-- (WHERE image<>'') que si la requête porte la même condition, ce qu'un
-- paramètre lié ne lui permet pas de prouver.
CREATE INDEX IF NOT EXISTS idx_article_image  ON article(image);
CREATE INDEX IF NOT EXISTS idx_topic_vignette ON topic(vignette);
