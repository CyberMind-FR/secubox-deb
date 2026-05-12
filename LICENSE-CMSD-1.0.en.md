<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# CyberMind Source-Disclosed License v1.0 (CMSD-1.0)

> **⚠ INFORMATIVE TRANSLATION NOTICE**
>
> This English version is provided for **information purposes only**. The French version of this license, distributed as `LICENCE-CMSD-1.0.md`, is the **sole authoritative text**. In the event of any discrepancy, ambiguity, or conflict of interpretation between the two versions, the French text shall prevail in all respects, in accordance with Article 13.5 of the License and the choice-of-law clause set forth in Article 12.

**SPDX Identifier (non-official):** `LicenseRef-CMSD-1.0`
**License author:** CyberMind — Gérald Kerma (sole proprietor, SIREN 409 743 275)
**Effective date:** [TO BE COMPLETED]
**Covered Software version:** [TO BE COMPLETED]

---

## Preamble

This License governs the disclosure of the source code of Software developed by CyberMind for the exclusive purposes of **transparency, auditability, and security research**, without granting any right to productive, commercial, or derivative use.

It is neither a free software license within the meaning of the Free Software Foundation, nor an open source license within the meaning of the Open Source Initiative. It belongs to the *source-available* category: the source code is published, but its use remains subject to the express written authorization of the Licensor.

This License is drafted to support a digital sovereignty strategy compatible with the auditability requirements of the CSPN certification issued by the French National Cybersecurity Agency (ANSSI), while preserving the Licensor's full intellectual property rights over the inventions, algorithms, and architectures composing the Software.

---

## Article 1 — Definitions

**1.1 "Licensor"** means CyberMind, a sole proprietorship operated by Mr. Gérald Kerma, registered with the French Trade and Companies Register under SIREN 409 743 275, with its registered office in Notre-Dame-du-Cruet (Savoie, France).

**1.2 "Software"** means the entirety of the source code, binaries, technical documentation, configuration files, build scripts, and ancillary resources published by the Licensor under this License.

**1.3 "Source Code"** means the preferred form of the Software for making modifications to it, including build scripts, compilation configurations, and the artifacts necessary for its reproduction.

**1.4 "Licensee"** means any natural or legal person accessing the Software or consulting its Source Code.

**1.5 "Audit"** means any inspection operation, static or dynamic analysis, formal verification, or compliance check carried out for the exclusive purposes of evaluating the security, quality, or behavior of the Software, without any production use.

**1.6 "Production"** means any deployment, execution, or use of the Software in an operational context, whether commercial, institutional, non-profit, or regular personal use, beyond the strict scope of evaluation and Audit.

**1.7 "Derivative Work"** means any creation based upon the Software or upon substantial extracts thereof, within the meaning of Articles L. 112-1 et seq. of the French Intellectual Property Code.

---

## Article 2 — Purpose and philosophy of the License

This License pursues three cumulative objectives:

a) To **guarantee transparency** of the Software through full and permanent publication of its Source Code;

b) To **enable independent audit** of the Software by any interested party, particularly within the framework of security certification processes (CSPN, Common Criteria, ANSSI qualifications);

c) To **fully preserve the patrimonial and moral rights** of the Licensor over the Software, including the monopoly on commercial exploitation, the right of distribution, and the right to create derivative works.

---

## Article 3 — Rights granted to the Licensee

Subject to strict compliance with this License, the Licensor grants the Licensee, on a **non-exclusive, non-transferable, non-sublicensable, and revocable** basis, the following rights:

**3.1** The right to **consult, download, and keep a local copy** of the Source Code for personal study purposes.

**3.2** The right to **compile the Software** in an isolated environment (virtual machine, container, physical test bench not connected to a production network) for the exclusive purposes of Audit, evaluation, or security research.

**3.3** The right to **publish the results** of an Audit or research conducted on the Software, subject to compliance with Article 8 (responsible disclosure).

**3.4** The right to **quote** extracts of the Source Code in an academic, journalistic, or pedagogical context, within the limits of the right of short citation provided for by Article L. 122-5 of the French Intellectual Property Code.

No other rights are granted. In particular, **no right to use in Production, to permanently modify, to redistribute, or to create a Derivative Work** is granted by this License.

---

## Article 4 — Prohibitions

The following are expressly prohibited to the Licensee, save with the prior written authorization of the Licensor:

**4.1** Use of the Software in Production, in any form whatsoever, free of charge or for consideration, as a primary or ancillary use.

**4.2** Redistribution of the Software or its binaries, in whole or in part, on any medium whatsoever.

**4.3** Creation, distribution, or exploitation of Derivative Works.

**4.4** Integration of the Software or substantial fragments of its Source Code into another piece of software, product, or service.

**4.5** Removal, modification, or concealment of authorship notices, license warnings, copyright notices, or cryptographic signatures affixed by the Licensor.

**4.6** Provision of the Software as a hosted service (SaaS, PaaS, IaaS, MSP) to third parties.

**4.7** Circumvention, deactivation, or neutralization of any technical protection mechanism that may be present in the Software.

Any breach of the foregoing prohibitions constitutes an act of infringement (*contrefaçon*) within the meaning of Article L. 335-2 of the French Intellectual Property Code, without prejudice to any other civil and criminal remedies available to the Licensor.

---

## Article 5 — Source Code disclosure obligation

The Licensor undertakes, in consideration of the use restrictions imposed by this License, to:

**5.1** Publish the full Source Code of the Software in a public and durable repository, accessible without authentication or technical restriction.

**5.2** Publish any security update of the Software under the same License and in the same repository, within a reasonable period following its internal integration.

**5.3** Publicly document the changes made to the Software through a timestamped and signed changelog.

**5.4** Maintain the availability of the Source Code for a minimum period of **ten (10) years** from the effective date of this License, including in the event of cessation of active development of the Software.

This disclosure obligation constitutes a unilateral undertaking of the Licensor and an essential element of the contractual balance of this License.

---

## Article 6 — Express reservations

**6.1 Patents.** This License grants no patent license, express or implied, over patents owned or controlled by the Licensor, in particular those covering the cryptographic inventions of the GK·HAM-HASH family or any other algorithm integrated into the Software. Any industrial exploitation requires a separate patent license.

**6.2 Trademarks.** The names "CyberMind", "SecuBox", "Gondwana", "GK·HAM-HASH", as well as the associated logos, monograms, and visual identities, remain the exclusive property of the Licensor. No right to use these trademarks is granted by this License, except for the strict identification of the original Software in the context of activities permitted under Article 3.

**6.3 Moral rights.** In accordance with Article L. 121-1 of the French Intellectual Property Code, the Licensor's moral rights over the Software are inalienable. Any public mention of the Software must attribute authorship to CyberMind / Gérald Kerma.

---

## Article 7 — Audit, certification, and interoperability

**7.1** The Licensor expressly authorizes the conduct of Audits by accredited laboratories (CESTI, Common Criteria equivalents, university security research bodies) without prior formality, within the framework of certification processes or independent evaluation.

**7.2** In accordance with Article L. 122-6-1 of the French Intellectual Property Code, the Licensee retains the mandatory rights provided for by French law, in particular:

- observation, study, and testing of the operation of the Software;
- decompilation for the sole purpose of interoperability with other independently created software.

No provision of this License may restrict these mandatory rights.

---

## Article 8 — Security research and responsible disclosure

**8.1** The Licensor encourages independent security research on the Software and undertakes not to bring proceedings against any researcher acting in good faith within the framework of a coordinated disclosure approach.

**8.2** Any vulnerability identified must be reported to the Licensor at the contact address shown in the Software repository, with a reasonable remediation period **prior to any publication**:

- 90 days for vulnerabilities of medium severity or below;
- 30 days for critical vulnerabilities exploitable remotely, subject to negotiated extension if full remediation requires it.

**8.3** The Licensor undertakes to publicly credit researchers having complied with the coordinated disclosure procedure, unless otherwise requested by them.

---

## Article 9 — Disclaimer of warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, FREEDOM FROM HIDDEN DEFECTS, OR NON-INFRINGEMENT.

The Licensee assumes full responsibility for the evaluation of the Software and for the appropriateness of any action taken on the basis thereof.

---

## Article 10 — Limitation of liability

To the fullest extent permitted by applicable law, the Licensor shall in no event be liable for any direct, indirect, incidental, special, or consequential damages, including loss of data, loss of profits, business interruption, or any other harm resulting from access to the Software or from the exercise of the rights granted by this License.

This limitation applies notwithstanding the failure of the essential purpose of any limited remedy, but without prejudice to mandatory provisions of French law concerning intentional misconduct (*dol*) or gross negligence (*faute lourde*).

---

## Article 11 — Termination

**11.1** Any breach by the Licensee of any of the provisions of Articles 3, 4, or 6 shall result in **automatic termination as of right** of the granted rights, without prior notice.

**11.2** In the event of termination, the Licensee shall immediately cease any use of the Software and destroy any copy in its possession, with the exception of one archival copy kept for evidentiary purposes.

**11.3** The obligations under Article 5 (disclosure) shall survive any individual termination, insofar as they constitute a unilateral undertaking of the Licensor towards the community.

---

## Article 12 — Governing law and jurisdiction

**12.1** This License is governed by French law, to the exclusion of its conflict-of-laws rules.

**12.2** Any dispute relating to the interpretation, performance, or validity of this License shall be brought before the competent courts within the jurisdiction of the Court of Appeal of Chambéry, notwithstanding multiple defendants or third-party indemnity claims.

**12.3** The parties agree to attempt, prior to any contentious action, an amicable resolution of the dispute within a period of sixty (60) days from the written notification of the dispute.

---

## Article 13 — Miscellaneous provisions

**13.1 Entire agreement.** This License constitutes the entire agreement between the parties in relation to its subject matter and supersedes any prior agreement or communication.

**13.2 Severability.** If any provision of this License is held to be void or unenforceable by a competent court, the remaining provisions shall remain in full force and effect.

**13.3 No waiver.** The fact that the Licensor does not avail itself of any provision of this License shall not be construed as a waiver of the right to do so subsequently.

**13.4 License versioning.** The Licensor reserves the right to publish later versions of this License. Versions of the Software released under version 1.0 shall remain governed by it.

**13.5 Language.** The French version of this License is the authoritative text. Any translation, including this English version, is provided for information purposes only.

---

## Annex A — How to apply this License

To place a project under the CMSD-1.0 License, attach the License file at the root of your repository under the name `LICENCE-CMSD-1.0.md` (authoritative French version), optionally accompanied by `LICENSE-CMSD-1.0.en.md` (informative English version), and affix the following header at the top of each significant source file:

```
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) [YEAR] CyberMind — Gérald Kerma
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms (French text authoritative).
```

For components subject to a different licensing regime (AGPLv3, BUSL, Apache 2.0, etc.), place them in separate subdirectories with their own `LICENSE` file and document the license tree in a `LICENSING.md` file at the root of the repository.

---

## Final note on authority

This English version is offered as a courtesy to facilitate international understanding of the License. It does not create any contractual rights or obligations. The French version, and the French version alone, governs the relationship between the Licensor and the Licensee. By accessing the Software, the Licensee acknowledges having had the opportunity to consult the authoritative French text and accepts that any interpretive question be resolved by reference to it.

---

*End of the CyberMind Source-Disclosed License v1.0 — Informative English Version*
