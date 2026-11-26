# Legal Risk and Acceptable Use

**This document is part of CatchClaw. Using, copying, building, or distributing the Software constitutes acceptance of [LICENSE](LICENSE) and of this notice.**

The copyright holder is **Coff0xc**.

This notice is a **worldwide** risk disclosure. It is not legal advice. It does not grant extra rights. It does not make any use lawful in any country. If LICENSE and this notice conflict on copyright, LICENSE controls. **No choice-of-law clause limits which criminal, regulatory, or tort law applies to your conduct.**

---

## 中文摘要（全球适用，具有约束力）

1. **CatchClaw 是双用途（民用/可能被滥用于入侵）安全评估工具。** 下载、持有、编译、分发或运行，在任何国家或地区都可能受管制。
2. **仅允许对你拥有的系统，或已事先取得权利人明确书面授权的系统使用。** 授权必须写明目标、时间窗口与方法。口头许可、默示许可、端口开放、默认口令、未报名的漏洞赏金、第三方口头请托，均不构成授权。
3. **未经授权的扫描、探测、侵入、拦截、凭据使用、数据获取或系统干扰，在全球范围内均可构成刑事犯罪、民事侵权和/或行政违法。** 可能同时适用的法律包括但不限于：你实施行为所在地、目标及其数据所在地、你的国籍/居所地、通信或数据过境地、出口与制裁相关国家的全部法律。任何国家的计算机滥用、非法访问、非法拦截、数据干扰、诈骗、商业秘密、隐私与数据保护、出口管制与制裁规则均可能适用。本工具不因在某一国家开发或许可而在其他国家获得豁免。
4. **你对在任何司法辖区产生的全部法律后果独立承担责任**（刑事侦查与刑罚、罚款、没收、禁令、民事赔偿、行政处罚、雇主或客户索赔）。作者与版权人不辩护、不补偿、不承担。
5. **未经 Coff0xc 事先书面授权，禁止任何商业使用**（付费渗透、咨询交付、SaaS、二次销售、用产出作为商业交付物、用本软件训练商业模型等）。详见 LICENSE。
6. **结果可能误报或漏报，不构成漏洞鉴定、合规结论或法律意见。** 对外披露须独立复核，并遵守各适用地的披露与保密规则。
7. **OSINT 与 MCP 会扩大目标范围。** 你须自行保证不违反搜索引擎条款、数据保护法，且每一个被扫到的地址仍在书面授权内。
8. **软件按“现状”提供，不作任何担保。** 你须在使用前自行就每一个相关国家咨询有资格的律师。

英文正文与 [LICENSE](LICENSE) 为完整条款。中文摘要与英文不一致时，以更能保护版权人、且不缩小你在各国法下义务的解读为准。

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

LICENSE §10 (choice of law and Beijing courts) governs **disputes about the copyright license**. It does **not** choose, waive, or cap the criminal, regulatory, or tort law of any other state that applies to your conduct.

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

## 6. Commercial use

Commercial use is **prohibited** without prior written authorization from Coff0xc, including paid testing, consulting, SaaS, internal revenue-supporting use, resale, white-labeling, and using outputs as a commercial deliverable. See LICENSE.

Copyright remedies are in addition to, not instead of, computer-crime liability.

Commercial license requests: https://github.com/Coff0xc

## 7. Distribution and forks

Keep LICENSE and attribution in every copy. Do not strip origin or train commercial models on the Software. If you publish a fork with warnings removed, you are responsible for how others use that copy.

## 8. Export, sanctions, dual-use

You must not export, re-export, or furnish the Software or its output in violation of **any** export-control, sanctions, or dual-use regime that applies to you (including, without limitation, those of your country, the destination, the United States, the European Union, the United Kingdom, the People’s Republic of China, and any other competent authority). You must not use the Software for or on behalf of a sanctioned party.

## 9. No warranty; limitation of liability

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND. TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE AUTHORS AND COPYRIGHT HOLDERS ARE NOT LIABLE FOR ANY CLAIM, DAMAGE, FINE, CRIMINAL PROCESS, OR OTHER LIABILITY ARISING FROM THE SOFTWARE OR ITS USE, IN ANY JURISDICTION.

Nothing here excludes liability that a mandatory rule of a competent forum does not allow to be excluded.

## 10. Indemnity

To the maximum extent permitted by applicable law, you will indemnify and hold harmless the authors and copyright holders against claims, losses, fines, and costs (including reasonable legal fees) arising from your use or distribution of the Software in any country, including unauthorized testing and unauthorized commercial use.

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
