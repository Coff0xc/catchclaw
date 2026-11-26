# Legal Risk and Acceptable Use

**This document is part of CatchClaw. Using, copying, building, or distributing the Software constitutes acceptance of [LICENSE](LICENSE) and of this notice.**

The copyright holder is **Coff0xc**. Governing law: laws of the People’s Republic of China; exclusive jurisdiction: courts in Beijing, China. See LICENSE §10.

This notice is a risk disclosure. It does not grant extra rights. It does not legalize any use. If LICENSE and this notice conflict, LICENSE controls.

---

## 中文摘要（具有约束力）

1. **CatchClaw 是双用途安全评估工具**，含漏洞探测、利用链编排、凭据提取与攻击面扫描能力。下载、持有、编译或使用本身即可能受所在司法辖区管制。
2. **仅允许在已取得权利人明确书面授权的系统上使用。** 授权范围必须覆盖目标、时间窗口与测试方法。口头许可、推测许可、公开互联网上的“默认开放”均不构成授权。
3. **未经授权对计算机信息系统实施扫描、入侵、控制、数据窃取或破坏，可能构成违法犯罪。** 在中华人民共和国境内，可能触犯《刑法》第 285 条、第 286 条及相关司法解释（非法侵入计算机信息系统、非法获取计算机信息系统数据、非法控制计算机信息系统、破坏计算机信息系统等）；同时可能承担民事责任与行政处罚。在其他国家或地区，可能触犯当地计算机犯罪、未授权访问、数据保护与出口管制法律。
4. **使用者对一切使用行为独立承担全部法律责任、监管责任与损害赔偿。** 作者与版权人不对误用、违法使用、误报、漏报、业务中断、数据丢失、第三方索赔或刑事追究承担任何责任。
5. **禁止任何商业使用**（含付费渗透测试、咨询交付、SaaS、二次销售、用本软件产出作为商业交付物、用本软件训练商业模型等），除非事先取得版权人书面授权。详见 LICENSE。
6. **扫描结果可能误报或漏报，不构成漏洞鉴定、法律意见或安全保证。** 对外披露前必须独立复核，并遵守漏洞披露与保密义务。
7. **OSINT（Shodan / FOFA / Hunter）与 MCP 扩展目标范围，由使用者自行保证不违反引擎服务条款、数据保护法和授权范围。**
8. **软件按“现状”提供，不作任何明示或默示担保。**

完整条款以以下英文正文与 [LICENSE](LICENSE) 为准。

---

## 1. Nature of the Software

CatchClaw is a **dual-use** security assessment toolkit. It can:

- probe and fingerprint AI/LLM and adjacent infrastructure;
- send exploit payloads, including credential-guessing and injection attempts;
- chain multi-stage attacks and record evidence;
- query third-party cyberspace search engines;
- expose those capabilities to an AI assistant via MCP.

Possession, compilation, distribution, or use may be regulated where you live or where the target is located. You are solely responsible for determining legality **before** any use.

## 2. Authorized use only

You may run CatchClaw **only** against systems that satisfy **all** of the following:

1. You own the system, **or** you hold **prior, explicit, written** authorization from the owner or a person with legal authority to grant it.
2. The authorization names the targets (hosts, networks, applications), the time window, and the permitted techniques.
3. You stay inside that scope.

The following are **not** authorization: robots.txt, an open port, a default password, a public IP, a bug bounty program you did not enroll in, an employer’s implied duty, or a third party’s request without the owner’s writing.

**Dry-run, fingerprinting, port scans, OSINT queries, and Nuclei templates are in-scope testing techniques.** They still require authorization when directed at systems you do not own.

## 3. Criminal, civil, and administrative exposure

Unauthorized scanning, access, interception, credential use, data acquisition, or system interference can be a crime and a tort.

Illustrative (non-exhaustive) references:

- **People’s Republic of China:** Criminal Law Articles 285 and 286 and related judicial interpretations (unlawful intrusion into a computer information system; unlawful acquisition of data; unlawful control; damaging a computer information system). Administrative and civil liability may apply in parallel.
- **Other jurisdictions:** computer-misuse / unauthorized-access statutes (for example the U.S. Computer Fraud and Abuse Act and state equivalents, the UK Computer Misuse Act, EU member-state implementations of illegal access and data interference offences), as well as privacy, trade-secret, and export-control rules.

Penalties can include imprisonment, fines, confiscation, injunctions, and damages. **The copyright holder will not defend, indemnify, or reimburse you for unlawful use.**

## 4. Assumption of risk; no reliance

You assume all risk arising from:

- your decision to download, build, configure, or run the Software;
- target selection, including CIDR expansion, `--targets-file`, OSINT-derived hosts, and MCP `--allow` / `--allow-file`;
- false positives, false negatives, incomplete evidence, and severity scoring;
- disruption of the target (including denial of service from probes, brute force, or race modules);
- leakage of tokens, API keys, or findings in reports, logs, or LLM context;
- third-party API use (Shodan, FOFA, Hunter) and their terms, quotas, and data-handling rules.

Findings are **unverified technical signals**. They are not a confirmation of a vulnerability, not a CVSS assignment you may republish as fact, and not legal, compliance, or professional advice.

## 5. Operator security and data handling

- Do not point CatchClaw at production systems without a change window and a rollback plan. Some modules are intrusive.
- The HTTP client is built for assessment traffic (including disabled redirects and, in the current Go client, TLS certificate verification skipped). Treat captured traffic, reports, and evidence as **sensitive**. Encrypt at rest; restrict access; retain only as long as the engagement requires.
- Do not embed secrets in command lines that are logged. Prefer environment variables (`CATCHCLAW_TOKEN`, `SHODAN_API_KEY`, `FOFA_EMAIL` / `FOFA_KEY`, `HUNTER_API_KEY`).
- MCP default allowlist is private address space only. Expanding it to public ranges is a legal and operational decision you own. Hostnames are resolved and every address must stay in the allowlist; you must still ensure the name and all records remain in scope for the whole scan.
- Do not feed engagement data into third-party models unless the contract and data-protection law allow it.

## 6. Commercial use

Commercial use is **prohibited** without prior written authorization from the copyright holder. That includes paid pentest or consulting, SaaS, internal use that supports revenue, resale, white-labeling, and using outputs as a commercial deliverable. See LICENSE §§1–4.

Unauthorized commercial use is copyright infringement. LICENSE reserves retroactive enforcement, disgorgement, and costs to the extent permitted by applicable law. **“No statute of limitations” language in LICENSE does not override mandatory limitation rules of the governing law; where a mandatory rule applies, that rule applies.**

For a commercial license, contact the copyright holder via GitHub: https://github.com/Coff0xc

## 7. Distribution, forks, and models

- Keep LICENSE and attribution unmodified in every copy and substantial portion (LICENSE §§5–6).
- Do not strip origin, rebrand, or use the Software to train commercial AI/ML models or datasets.
- Public forks remain bound by LICENSE. You are liable for how others use a copy you publish if you remove or obscure these warnings.

## 8. Export, sanctions, and local controls

You must not export, re-export, or provide the Software or its output in violation of export-control, sanctions, or dual-use rules that apply to you (including PRC, U.S., EU, and destination-country rules). You must not use the Software on behalf of a sanctioned party.

## 9. No warranty; limitation of liability

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND. TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE AUTHORS AND COPYRIGHT HOLDERS ARE NOT LIABLE FOR ANY CLAIM, DAMAGE, OR OTHER LIABILITY ARISING FROM THE SOFTWARE OR ITS USE, INCLUDING CRIMINAL INVESTIGATION, FINES, LOST PROFITS, DATA LOSS, AND THIRD-PARTY CLAIMS.

Nothing in this notice excludes liability that applicable law does not allow to be excluded (for example liability for harm caused by intent or gross negligence where such exclusion is void).

## 10. Indemnity

To the maximum extent permitted by applicable law, you will indemnify and hold harmless the authors and copyright holders against claims, losses, fines, and costs (including reasonable legal fees) arising from your use, distribution, or misrepresentation of the Software, including unauthorized testing and unauthorized commercial use.

## 11. Responsible disclosure of product defects

Vulnerabilities **in CatchClaw itself** must be reported per [SECURITY.md](SECURITY.md). Do not file public issues with exploit details.

Vulnerabilities in **third-party platforms** that CatchClaw probes must be reported to those vendors under their policies. Do not use this repository as a 0-day drop.

## 12. Acknowledgement

BY USING THE SOFTWARE YOU CONFIRM THAT:

- you have read LICENSE, this notice, and SECURITY.md;
- you have lawful authorization for every target;
- you accept that unauthorized use can be a crime;
- you accept full legal responsibility for your conduct.

If you cannot accept these terms, do not download, build, or run CatchClaw.
