# SentinelLLM v4.2.0 — Image/Video Generation False-Positive Fix

## Changes
- Refined the 52,000-prompt corpus to **54,000 unique prompts**, balanced at **27,000 benign** and **27,000 attack-labelled**.
- Added 2,000 media-focused prompts: 1,000 benign image/video creation, illustration, animation, editing and infographic requests; 1,000 unsafe media-abuse requests covering non-consensual deepfakes, impersonation, fraudulent media, blackmail, fake documents and harassment.
- Added a contextual policy safeguard for ordinary media-production requests. It runs only after explicit harmful-intent and prompt-injection rules, and only when obfuscation and elevated session-behavior indicators are absent. It does not exempt explicit abuse terms such as non-consensual deepfake, blackmail, fraud, impersonation or doxxing.
- Added regression tests for safe and unsafe media generation.
- Retrained the active TF-IDF word+character n-gram Logistic Regression classifier.

## Dataset audit
- Rows: 54000
- Unique prompt texts: 54000
- Class counts: {0: 27000, 1: 27000}
- Media-specific rows: 2000
- Media topic counts: {'image_video_generation_safe': 1000, 'image_video_generation_unsafe': 1000}

## Grouped test metrics
- Split: grouped by prompt-template family; threshold selected using validation only; test families held out.
- Training rows: 34387
- Validation rows: 9210
- Test rows: 10403
- Selected threshold: 0.35
- Accuracy: 98.4620%
- Attack precision: 96.8064%
- Attack recall: 100.0000%
- Benign false-positive rate: 2.9668%
- False-negative rate: 0.0000%

## Regression tests
`python -m unittest discover -s tests -v` — **54 tests passed** (including the newly added media-generation tests).

## Limitations
- Data are synthetic/template-generated. Grouped splitting reduces exact template leakage but cannot establish real-world performance.
- A separate, independent external benchmark has not been run in this build.
- Image/video safeguards address the specific false-positive category described; they are not a complete image/video safety policy. Context and labels should be reviewed against your product policy.
- Optional legacy Random Forest and XGBoost artifacts emit scikit-learn/XGBoost version warnings. The active Logistic Regression model was retrained and is the default.
