$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    throw "csc.exe not found at $csc. .NET Framework 4.x is required."
}
$outDir = Join-Path $root "release"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$out = Join-Path $outDir "IGTAP-PowerTrainer.exe"
& $csc /nologo /target:winexe /optimize+ /r:System.Windows.Forms.dll /r:System.Drawing.dll "/out:$out" (Join-Path $root "Trainer.cs")
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
Write-Output "Built $out"
