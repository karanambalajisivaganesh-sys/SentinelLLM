# SentinelLLM v4.2.0 — media-generation false-positive fix

- Dataset: 54,000 unique prompt rows, 27,000 benign and 27,000 attack labels.
- Added 2,000 media-specific prompts: 1,000 benign image/video generation/editing requests and 1,000 unsafe media-abuse requests.
- Added a narrow contextual policy safeguard for ordinary media-generation requests. Explicit harmful-intent and prompt-injection rules run first; obfuscation and elevated behavioral signals prevent the exemption.
- Added regression tests for ordinary image/video prompts and harmful media misuse.
- Dataset is synthetic; reported metrics should not be treated as real-world performance.
