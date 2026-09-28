// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import { mount } from 'svelte'
import './app.css'
import MoodMicro from '../MoodMicro.svelte'

mount(MoodMicro, { target: document.getElementById('carte')! })
