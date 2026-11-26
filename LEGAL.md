# Legal Risk and Acceptable Use

**This document is part of CatchClaw. Using, copying, building, or distributing the Software constitutes acceptance of [LICENSE](LICENSE) and of this notice.**

The copyright holder is **Coff0xc**.

This notice is a **worldwide** risk disclosure. It is not legal advice. It does not grant extra rights. It does not make any use lawful in any country. If LICENSE and this notice conflict on copyright, LICENSE controls. **No choice-of-law clause limits which criminal, regulatory, or tort law applies to your conduct.**

---

## 1. Nature of the Software

CatchClaw is **dual-use**. It can fingerprint services, send exploit payloads, guess credentials, chain multi-stage attacks, query cyberspace search engines, and expose those functions to an AI assistant via MCP.

Possession, compilation, distribution, or use may be regulated **anywhere**. You must determine legality **before** you download or run it. This repository being public does not make the Software legal to use against any system.

## 2. Authorized use only

You may run CatchClaw only if **all** of the following are true:

1. You own the system, **or** you hold **prior, explicit, written** authorization from a person with legal authority to grant it.
2. The writing names the targets (hosts, networks, applications), the time window, and the permitted techniques.
3. You stay inside that scope.

These are **not** authorization: robots.txt, an open port, a default password, a public IP, a bug-bounty program you did not enroll in, an employer’s implied duty, or a third party’s request without the owner’s writing.

Port scans, fingerprinting, `--dry-run`, Nuclei templates, OSINT queries, and MCP tool calls are testing techniques. They still require authorization when aimed at systems you do not own.

## 3. Worldwide criminal, civil, and regulatory exposure

Unauthorized scanning, access, interception, credential use, data acquisition, or interference with a computer system can be a **crime, a tort, and an administrative offence**.

**Every applicable legal system may apply at the same time**, including the law of:

- the place you act from (keyboard, VPN exit, cloud runner, CI);
- the place the target, its operator, or its data is located;
- your nationality, residence, or incorporation;
- any country of transit, hosting, DNS, or telecommunications;
- any country whose export-control, sanctions, or dual-use rules reach you.

No statute list is complete or safe to rely on. The same pattern exists under many names worldwide (unauthorized access, computer misuse, illegal interception, data interference, fraud, trade-secret theft, privacy and data-protection offences, export control, sanctions). **Absence of a country from any example list is not permission.**

Penalties can include imprisonment, fines, confiscation, injunctions, and damages in more than one country at once. **The copyright holder will not defend, indemnify, or reimburse you.**

LICENSE §10 governs **disputes about the copyright license as a contract**. It does **not** choose, waive, or cap the criminal, regulatory, or tort law of any state that applies to your conduct.

## 4. Assumption of risk; not legal advice

You assume all risk arising from download, build, configuration, target selection (including CIDR, target files, OSINT hosts, MCP `--allow`), false positives and negatives, disruption of the target, leakage of evidence, and third-party API terms.

Findings are unverified technical signals. They are not a vulnerability confirmation, not a CVSS you may republish as fact, and not legal, compliance, or professional advice.

**This file is not a legal opinion.** Laws change. You must obtain advice from counsel admitted in **each** jurisdiction that may apply to you and to the target.

## 5. Operator handling

- Some modules are intrusive. Do not run them on production without a defined window and rollback.
- Treat reports, tokens, and evidence as sensitive. The current HTTP client skips TLS verify and does not follow redirects.
- Keep secrets in the environment, not on the command line.
- MCP defaults to private address space. Widening `--allow` is a legal decision you own; every resolved IP must remain in scope.
- Do not send engagement data to third-party models unless every applicable data-protection law and contract allows it.

## 6. Commercial use and derivatives

The Software is licensed under the **MIT License**. You may use, copy, modify, merge, publish, distribute, sublicense, and sell it, including commercial products, paid services, and proprietary forks, provided you keep the copyright notice and permission notice in copies or substantial portions. See [LICENSE](LICENSE).

MIT is a copyright license. **It does not authorize unauthorized access to computer systems.** A commercial pentest, SaaS scanner, or internal security program still needs the target owner’s written authorization wherever computer-misuse law applies.

## 7. Distribution and forks

Keep the MIT copyright notice and permission notice in every copy or substantial portion. If you publish a fork with LEGAL.md warnings removed, you are responsible for how others use that copy.

## 8. Export, sanctions, dual-use

You must not export, re-export, or furnish the Software or its output in violation of **any** export-control, sanctions, or dual-use regime that applies to you — including those of your country, the destination, and any other competent authority. You must not use the Software for or on behalf of a sanctioned party.

## 9. No warranty; limitation of liability

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND. TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE AUTHORS AND COPYRIGHT HOLDERS ARE NOT LIABLE FOR ANY CLAIM, DAMAGE, FINE, CRIMINAL PROCESS, OR OTHER LIABILITY ARISING FROM THE SOFTWARE OR ITS USE, IN ANY JURISDICTION.

Nothing here excludes liability that a mandatory rule of a competent forum does not allow to be excluded.

## 10. Indemnity

To the maximum extent permitted by applicable law, you will indemnify and hold harmless the authors and copyright holders against claims, losses, fines, and costs (including reasonable legal fees) arising from your use or distribution of the Software in any country, including unauthorized testing.

## 11. Product defects vs target defects

Report vulnerabilities **in CatchClaw** per [SECURITY.md](SECURITY.md). Do not file public issues with exploit details.

Report vulnerabilities in **third-party platforms** to those vendors. Do not use this repository as a 0-day drop.

## 12. Acknowledgement

BY USING THE SOFTWARE YOU CONFIRM THAT:

- you have read LICENSE, this notice, and SECURITY.md;
- you have lawful authorization for every target under **all** laws that apply;
- you understand unauthorized use can be a crime **anywhere it is prohibited**, which is most of the world;
- you accept full legal responsibility for your conduct in every applicable jurisdiction.

If you cannot accept these terms, do not download, build, or run CatchClaw.
