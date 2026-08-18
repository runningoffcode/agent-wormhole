# Mind-virus corpus

Verbatim payload excerpts from **Papadopoulos, Shah, Zimmerman & Lindsey,
"Mind Viruses: Self-Propagating Ideas in Multi-Agent LLM Systems"**
(arXiv 2608.10218, 10 August 2026), Transcripts 15–16 and §3.3.1.

These are not our constructions. They are payloads an evolutionary algorithm
selected for spreading ability, which makes them a fairer test than anything we
would write ourselves: we cannot accidentally tune a rule to text we invented.

## Why some of these are expected to MISS

`WORM-001` requires self-reference plus a propagation verb plus a destination.
Two payloads here carry no self-reference at all — they instruct the creation of
a *new* file whose content is dictated inline. That is propagation by dictation
rather than by copying, and it is a different shape.

The honest position is that these are recorded as misses rather than quietly
excluded, and the detection rate below is reported against the full set. A
corpus that only contains what we already catch measures nothing.

## Provenance

Payload text is quoted from the paper for detection testing under fair use. The
authors released their own transcripts at https://www.mindvirusdata.live and
reproduction code at https://github.com/frotaur/mindvirus-viruschain.
