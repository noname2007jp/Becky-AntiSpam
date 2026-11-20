[CmdletBinding()]
param(
    [string]$Destination = (Join-Path (Get-Location) "models\tanaos-spam-detection-v1")
)

$ErrorActionPreference = "Stop"
$revision = "dac7281d03723c7024de552ddec6eac0b4d6fabf"
$base = "https://huggingface.co/onnx-community/tanaos-spam-detection-v1-ONNX/resolve/$revision"
$files = @(
    "config.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "vocab.txt",
    "onnx/model_quantized.onnx"
)

$root = [System.IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Force -Path $root | Out-Null

foreach ($relative in $files) {
    $target = Join-Path $root ($relative -replace "/", "\")
    $parent = Split-Path -Parent $target
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $url = "$base/$relative"
    Write-Host "Downloading $relative ..."
    Invoke-WebRequest -Uri $url -OutFile $target
    if (!(Test-Path -LiteralPath $target) -or (Get-Item -LiteralPath $target).Length -eq 0) {
        throw "Download failed or returned an empty file: $relative"
    }
}

$modelPath = Join-Path $root "onnx\model_quantized.onnx"
$modelBytes = (Get-Item -LiteralPath $modelPath).Length
if ($modelBytes -lt 100MB) {
    throw "ONNX model is unexpectedly small ($modelBytes bytes); refusing to continue."
}

$hashes = foreach ($relative in $files) {
    $target = Join-Path $root ($relative -replace "/", "\")
    $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    [PSCustomObject]@{
        file = $relative
        sha256 = $hash
        bytes = (Get-Item -LiteralPath $target).Length
    }
}
$manifest = [PSCustomObject]@{
    model = "onnx-community/tanaos-spam-detection-v1-ONNX"
    revision = $revision
    downloaded_utc = [DateTime]::UtcNow.ToString("o")
    license = "MIT (as declared by model repository)"
    files = @($hashes)
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root "download-manifest.json") -Encoding UTF8
Write-Host ""
Write-Host "Model assets downloaded to: $root"
Write-Host "Model size: $([math]::Round($modelBytes / 1MB, 1)) MiB"
Write-Host "SHA-256 values recorded in download-manifest.json"
Write-Host "Model assets are ready for AntiSpamAI.exe."
