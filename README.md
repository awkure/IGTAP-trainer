# IGTAP Power Trainer

Memory trainer for the single-player game **IGTAP: an Incremental Game That's Also a Platformer** (`IGTAPfullGame.exe`). It attaches to the running process. The game binary is not modified on disk.

## Run

The executable is not in this repository. Build it first (see below), then:

1. Start the game and load a save. The POWER panel can be closed; values still update.
2. Run `release\IGTAP-PowerTrainer.exe`.
3. Wait for the first scan (about 20 seconds). The status line shows the process id when attach finishes.

Re-find after a reload. Currency and player addresses move when the game creates new objects.

Run the trainer as the same user as the game. If the game is elevated, run the trainer elevated too. `OpenProcess` error 5 means the integrity levels do not match.

## What it edits

- Watts, green power, nuclear power, clone dust, red power, blue power
- Nuclear cap, red cap, and NP boost when those fields are found
- God mode: `Movement.onDeath` returns immediately
- Infinite jumps and infinite dashes, as separate toggles
- Moss as metal: moss ground and walls refill jumps, dashes, and wall jumps
- Tick speed: `globalStats.baseGameSpeed`, copied by the game into Unity `Time.timeScale`. Range is 0.1 to 50. `1` is normal. Freeze keeps writing the box value. Pause still sets time scale to 0 until unpause.

Boxes accept raw numbers or `K` `M` `G` `T` `P` suffixes (`200T` = 200 trillion). Freeze rewrites that row every tick.

## Compile

Windows with .NET Framework 4.x. The compiler ships with Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

Output: `release\IGTAP-PowerTrainer.exe`.

Equivalent `csc` command:

```text
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:winexe /optimize+ /r:System.Windows.Forms.dll /r:System.Drawing.dll /out:release\IGTAP-PowerTrainer.exe Trainer.cs
```

## Diagnostic dump

With the game running:

```text
release\IGTAP-PowerTrainer.exe --dump
```

Writes `%TEMP%\igtap-trainer-dump.txt`. Read-only aside from the short Mono calls used to resolve field offsets. Close the windowed trainer first if you only want the dump.
