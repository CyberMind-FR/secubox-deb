// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/** Contrat : une action déclarée dans capabilities.d se résout en message sbx (#1613). */
import { describe, expect, it } from 'vitest';
import { resous } from '../hote';

describe('resous', () => {
  it('media.toggle de la radio → {sbx:cmd, action:toggle}', () => {
    expect(resous({ kind: 'sbx-action', service: 'radio', action: 'media.toggle' })).toEqual({ sbx: 'cmd', action: 'toggle' });
  });
  it('valeur typée : media.mute exige un booléen', () => {
    expect(resous({ kind: 'sbx-action', service: 'radio', action: 'media.mute', v: true })).toEqual({ sbx: 'cmd', action: 'muet', v: true });
    expect(resous({ kind: 'sbx-action', service: 'radio', action: 'media.mute', v: 'oui' })).toBeNull();
  });
  it('action ou service non déclarés → rien', () => {
    expect(resous({ kind: 'sbx-action', service: 'radio', action: 'media.next' })).toBeNull();
    expect(resous({ kind: 'sbx-action', service: 'zigbee', action: 'on' })).toBeNull();
  });
});
