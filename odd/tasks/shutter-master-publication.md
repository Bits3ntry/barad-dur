# Shutter master publication

Publish SBOMs for the Shutter repositories to Dependency-Track under the SHUTTER parent.
Scans run locally without modifying the source checkouts.

## Specs

S1. "ejecuta el SOBM /Volumes/980PRO/Workspace/Councilbox/shutter @HEAD*                                                                                        10:13:06
❯ ls                                 
rivulet        rivulet-client shutter-api    shutter-soup   shutter-turn de estooo tienes que meterlo en dependencytracker bajo la carpeta de shutter"

S2. "apuntando a arma master  o main en todos"

S3. "Origin/master actual"

## Tasks

- T1 [S1-S3] inline — Add a local SHUTTER Dependency-Track profile and tests for parent resolution — commit: pending (profile and health verified)
- T2 [S1-S3] inline — Build isolated master scan inputs and publish the five SBOMs under SHUTTER — commit: pending (in progress)
- T3 [S1-S3] inline — Verify remote hierarchy, BOM imports, and target immutability — commit: pending

## Log

- L1: User request: "ejecuta el SOBM /Volumes/980PRO/Workspace/Councilbox/shutter @HEAD*                                                                                        10:13:06
❯ ls                                 
rivulet        rivulet-client shutter-api    shutter-soup   shutter-turn de estooo tienes que meterlo en dependencytracker bajo la carpeta de shutter"
- L2: User requirement: "apuntando a arma master  o main en todos"
- L3: Read-only mapping: all five source checkouts are clean and on `master`; `shutter-api` local master is 91 commits behind `origin/master`; SHUTTER is a unique root Dependency-Track project.
- L4: User selected "Origin/master actual" for shutter-api. Use an isolated copy rather than modifying its checkout.
