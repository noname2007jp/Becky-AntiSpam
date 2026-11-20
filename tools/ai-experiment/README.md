# AntiSpamAI experimental model

This is an isolated, manual-only experiment for the x64 AntiSpamAI.exe worker. It does not enable inference in the Becky! plugin, change the production classifier, or write to Bayes/evaluation databases.

## Candidate model
- Repository: onnx-community/tanaos-spam-detection-v1-ONNX
- Pinned revision: dac7281d03723c7024de552ddec6eac0b4d6fabf
- Model: multilingual DistilBERT, labels not_spam (0) and spam (1)
- ONNX: onnx/model_quantized.onnx (about 136 MB)
- License declared by the model repository: MIT

The model was trained on synthetic multilingual messages and is not validated for Japanese business email. Treat its probability as experimental, not as an operational verdict.

## Build and prepare
The x64 CMake configuration downloads the pinned CPU ONNX Runtime NuGet package (1.20.1).

```powershell
cmake -S . -B build-x64 -A x64
cmake --build build-x64 --config Release
.	oolsai-experimentdownload-model.ps1
```

The release output requires **both** `AntiSpamAI.exe` and the matching `onnxruntime.dll` from the same build. Keep these two files in the same directory when running the executable. The GitHub Actions artifact `BeckyAntiSpam-AI-x64` packages both files. Do not substitute an older ONNX Runtime DLL from another application or from the Becky! plugin directory.

## Manual test
Create a UTF-8 text file containing the subject and body, then run from the release output directory:

```powershell
.AntiSpamAI.exe --classify-file .\sample-mail.txt
```

Optional model path:
```powershell
.AntiSpamAI.exe --classify-file .\sample-mail.txt --model-dir D:\models\tanaos-spam-detection-v1
```

The command prints SPAM/NOT_SPAM, both probabilities, and inference time. Input is limited to 1 MiB and 512 tokens.

## Safety boundaries
- Manual CLI only; no automatic receive hook and no Becky! UI integration yet.
- No message is moved/deleted; no Bayes training or evaluation-label writes.
- No sender address, transport headers, attachments, or raw RFC822 data are required.
- No external inference API; inference runs locally on CPU.
- Native WordPiece tokenization is a minimal implementation and must be checked against the reference tokenizer before production use.
