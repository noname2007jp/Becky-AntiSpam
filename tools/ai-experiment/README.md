# AntiSpamAI experimental model

This directory prepares an **isolated, manual-only experiment** for the x64
`AntiSpamAI.exe` worker. It does not enable AI inference in the Becky! plugin,
does not change the production classifier, and does not write to the Bayes DB
or evaluation database.

## Candidate model

- Repository: `onnx-community/tanaos-spam-detection-v1-ONNX`
- Revision: `dac7281d03723c7024de552ddec6eac0b4d6fabf` (pinned)
- License declared by the model repository: MIT
- Architecture: multilingual DistilBERT sequence classifier
- Labels: `not_spam` (0), `spam` (1)
- Selected ONNX: `onnx/model_quantized.onnx` (about 136 MB)
- Tokenizer: WordPiece vocabulary from the same pinned revision

The model card describes training on synthetic multilingual messages. It is a
candidate for a technical trial, **not a validated Japanese business-email
classifier**. It may flag legitimate business notifications or newsletters.
The experiment must display probabilities and must never move, delete, train
on, or relabel a message.

## Download assets

Run from the repository root in PowerShell:

```powershell
.\tools\ai-experiment\download-model.ps1
```

The script downloads only the pinned model and tokenizer assets into
`models\tanaos-spam-detection-v1\`. The model is not committed to Git.

## Isolation and privacy

- Manual invocation only; no automatic receive hook.
- Subject and body text are sent only to the local x64 worker over the local
  named pipe once inference integration is complete.
- No sender address, transport headers, attachments, or raw RFC822 message.
- No external inference API.
- No Bayes training, evaluation-label registration, or production verdict
  changes.
- Keep this experiment in shadow/manual mode until a Japanese business-mail
  evaluation shows acceptable false-positive behavior.

## Current status

This first step only pins and retrieves model assets. ONNX Runtime inference,
WordPiece tokenization in the native worker, a manual test entry point, and
result display are still to be implemented and tested. Do not treat a
successful model download as a working AI classifier.
