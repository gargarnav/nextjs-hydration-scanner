# Response to Reviewers — Paper ID 10 (CAIS 2026)

**Title:** Hydration Leakage and Over-fetching in Next.js: The Security Implications of Server-to-Client Data Serialization
**Track:** Cybersecurity

We thank all five reviewers for their careful and constructive feedback. The
paper was accepted conditionally on addressing the raised points, and we have
revised it accordingly. Below we respond to every comment, grouped by theme
(since several reviewers raised overlapping points), and note where each change
appears. All new experimental numbers are drawn from the actual scanner
artifacts and are reproducible from the released repository.

A one-line summary of the substantive additions:

- **Quantitative metrics** — new §4.3 with a full confusion matrix (precision,
  recall, F1) — Table 6.
- **Cross-framework evaluation** — new §4.4 with experiments on Nuxt, Remix, and
  SvelteKit — Table 7.
- **Performance/scalability** — new §4.5 with a measured runtime benchmark —
  Table 8.
- **Comparison with existing tools** — new §2.5 and Table 1.
- **Two figures** — the hydration pipeline (Fig. 1) and the scanner workflow
  (Fig. 2).
- **Related work** — replaced weak/web citations with five peer-reviewed
  references; **removed one citation that we found to be non-existent.**
- **Abbreviations** — every abbreviation is now expanded on first use.
- **Novelty positioning** — new §2.4 relating and contrasting the work with
  CWE-200 and OWASP API3:2023.

---

## Theme A — False-positive rate not quantified; precision/recall/F1 requested
*(Reviewer #1, comment 3; Reviewer #3; Reviewer #11, comment 3)*

We added **§4.3 "Detection Effectiveness"** with a formal confusion matrix over
the full four-route corpus (**Table 6**), reporting precision, recall, and F1
under three configurations:

| Configuration | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Raw (all findings) | 24 | 93 | 0 | 0.205 | 1.000 | 0.340 |
| CRITICAL tier only | 24 | 9 | 0 | 0.727 | 1.000 | 0.842 |
| + internal-field allowlist | 24 | 0 | 0 | **1.000** | **1.000** | **1.000** |

Recall is 100% (no planted credential is ever missed). The raw precision of
20.5% is fully explained by two structural false-positive classes; a short
allowlist of framework-internal field names removes all 93 false positives
without discarding any true positive, giving 100% precision at unchanged recall.
The false-positive analysis is expanded and made quantitative in **§6.1**.

**Note on data reconciliation.** In the course of this quantification we found
that the originally submitted results tables reported only the *true-positive*
CRITICAL counts and omitted the `className`→`/ssn/` false positives that the raw
scanner also emits. The revised **Tables 4 and 5** now report the raw numbers
split into true and false positives, and the headline claim is stated precisely
as "100% of **true-positive** critical exposures eliminated (24 → 0)." This makes
the results internally consistent and, we believe, stronger.

---

## Theme B — No evaluation against real-world / larger / other-framework applications
*(Reviewer #1, comment 4; Reviewer #3; Reviewer #9, comment 1; Reviewer #11, comments 2 and 6)*

We addressed this along two axes:

1. **Cross-framework evaluation (new §4.4, Table 7).** We extended the scanner
   with channel extractors for SvelteKit (`__sveltekit_data`), Remix
   (`__remixContext`), and Nuxt (`__NUXT_DATA__`), and evaluated on a controlled
   fixture corpus carrying the same schema. The scanner detected **32 of 32**
   planted credentials across all four frameworks with zero false negatives and
   zero false positives. This converts the previously unsupported claim that "the
   vulnerability is not Next.js-specific" into a reproducible experimental
   result, directly answering Reviewer #9 and Reviewer #11, comment 6.

2. **Scale and external validity.** §4.5 benchmarks the analysis to payloads of
   10,000 records; §6.2 discusses ORM-backed production schemas. We deliberately
   evaluate on controlled corpora with exact ground truth and have added a
   **"Threats to Validity"** subsection (§6.4) that states this explicitly and
   scopes an authorized, at-scale study of deployed applications as future work.
   We note there that scanning third-party production sites without permission
   raises legal/ethical concerns, which is why controlled corpora are used for
   the measured claims.

---

## Theme C — Comparison with existing tools / static-analysis approaches
*(Reviewer #1, comment 2; Reviewer #3; Reviewer #9, comment 2; Reviewer #11, comment 4)*

New **§2.5 "Comparison with Existing Tools"** and **Table 1** compare the scanner
against React's `experimental_taintObjectReference`, commercial secret scanners
(`@snyk/nextjs`), general-purpose SAST/taint analysers, and architectural
excessive-exposure metrics, across the dimensions of target, Pages Router
coverage, multi-framework coverage, and analysis stage. The key distinction: no
existing tool targets hydration-payload field leakage across routing paradigms
at runtime. We also describe (§6.3) a prototype static, type-aware ESLint rule as
a write-time complement to the runtime scanner.

---

## Theme D — Related work is short / references are not peer-reviewed
*(Reviewer #1, comment 2; Reviewer #3; Reviewer #9; Reviewer #10, "big mistake"; Reviewer #11, comment 5)*

Reviewer #10 correctly noted that several references were web pages rather than
authenticated sources. We have substantially strengthened the bibliography:

- **Added five peer-reviewed references**, each verified against dblp/ACM
  DL/NDSS/Springer:
  - Genfer & Zdun, *Avoiding Excessive Data Exposure Through Microservice APIs*,
    ECSA 2022 (Springer) — the closest architectural analog to our work.
  - Meli, McNiece & Reaves, *How Bad Can It Git?*, NDSS 2019 — validates
    regex-based credential detection at scale.
  - Lekies, Stock & Johns, *25 Million Flows Later*, ACM CCS 2013 — large-scale
    taint-based web-flow detection.
  - Steffens, Rossow, Johns & Stock, *Don't Trust the Locals*, NDSS 2019 —
    client-side web-security measurement.
  - Katz et al., *SIExVulTS*, 2025 — CWE-200 detection via static analysis.
- **Removed a non-existent citation.** The originally submitted bibliography
  contained an entry ("State Leakage in Single-Page Applications via Developer
  Tools," attributed to Luo et al., CCS 2023) that we were unable to verify in
  any index (ACM DL, dblp, Google Scholar); we have removed it and an
  unverifiable blog reference, and now anchor the discussion on the five
  peer-reviewed works above. We are grateful this was surfaced before
  publication.
- Remaining web references are limited to appropriate primary sources
  (framework documentation, OWASP, MITRE CWE, MDN), each with an access date.

The prior-work discussion (§2.2) and a new **§2.4 "Novelty and Positioning"**
were rewritten around these sources.

---

## Theme E — Diagrams / flowchart requested
*(Reviewer #3; Reviewer #9, comment 3; Reviewer #10; Reviewer #11)*

We added two figures:

- **Figure 1** — the SSR hydration serialization pipeline, showing where the leak
  occurs and where the DTO mitigation intervenes.
- **Figure 2** — the scanner workflow (fetch → five-channel extraction →
  recursive walk → field-name/value-pattern decision → severity-tagged report),
  i.e., the flowchart Reviewer #10 requested.

---

## Theme F — Scanner performance / runtime / scalability
*(Reviewer #3)*

New **§4.5 "Performance and Scalability"** and **Table 8** report a measured
benchmark of the recursive walk on payloads from 10 to 10,000 records. The walk
is linear in payload size (~2.1 µs per node, O(n) time, O(1) additional space); a
2.5 MB, 10,000-record payload is analysed in ~200 ms. End-to-end scan time is
dominated by the single network round-trip.

---

## Theme G — Novelty vs. Excessive Data Exposure / CWE-200
*(Reviewer #11, comment 1)*

New **§2.4 "Novelty and Positioning"** states three claims specific to SSR
hydration that distinguish the work from generic Excessive Data Exposure
(OWASP API3:2023) and CWE-200: (i) the leaking "API" is the initial HTML served
to every unauthenticated visitor, with no explicit endpoint to audit;
(ii) a single framework has two structurally distinct serialization channels,
each requiring a different parser, both of which we detect; and (iii) the
vulnerability and detection generalize across four independent frameworks. §2.1
also frames the issue explicitly as a CWE-200 instance while contrasting it with
the usual CWE-200 examples.

---

## Theme H — Research-methodology framing
*(Reviewer #10, comments 1 and 2)*

We added an explicit **threat model** (§1), an **experimental corpus and
ground-truth protocol** (§3, defining how TP/FP/FN are assigned and verified),
and a **Threats to Validity** subsection (§6.4). Together with the confusion
matrix and the flowchart (Fig. 2), these frame the contribution as a controlled,
reproducible study rather than a documentation report.

---

## Theme I — Predefine all abbreviations
*(Reviewer #1, comment 1)*

Every abbreviation is now expanded on first use, including SSR, HTML, API, SSN,
RSC, PoC, DTO, JSON, HTTP, HTTPS, CSP, SQL, TOTP, JWT, PAT, AWS, ORM, and CWE.

---

## Theme J — Applicability to other SSR frameworks (Nuxt, Remix, SvelteKit)
*(Reviewer #9, comment 4; Reviewer #11, comment 6)*

Addressed by the cross-framework experiment (Theme B / §4.4 / Table 7): rather
than only claiming applicability, we demonstrate it with detection results on all
three frameworks and confirm the DTO mitigation is framework-agnostic (§6.2).

---

## Editorial format corrections

- **Citation order.** The editorial note that in-text sources were not in the
  correct order has been addressed: references are now numbered in **order of
  first citation** in the text (reference [1] is the first source cited, [2] the
  second, and so on), so the in-text citation numbers ascend sequentially. The
  Springer reference formatting is unchanged.

---

We believe these revisions address all reviewer comments and the editorial
format note, and we appreciate the feedback, which materially strengthened the
paper.
