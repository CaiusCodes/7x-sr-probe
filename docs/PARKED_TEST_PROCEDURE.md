# First test — vehicle PARKED the whole time

Allow about 15 minutes. Do every step with the car in **P**, parking brake on, somewhere you can safely sit with the screen on. Do not drive with the app capturing until we have reviewed this first report.

## 0. Before you start (no settings changed)

Open the car's About / System Information page and write down (or photograph) whatever is shown:

```
Zeekr OS version:
Software version:
Build number:
MCU version:
App Lab version:
Android/platform version:
Model variant:
```

Do not change any setting while doing this.

## 1. Install and launch

1. Install `7x-sr-probe-v0.1-debug.apk` with your usual App Lab method. Confirm the only permission listed is "query all packages" (or none).
2. Launch **7X SR Probe**.
3. Confirm the green **SAFETY MODE  READ ONLY ✓** banner is visible. If not, stop.

## 2. Safe discovery (the main step)

4. Press **Run Safe Discovery**. The "Working:" line shows each step. Expect 1–3 minutes; the last step scans system APK files for names and is the slowest.
5. While it runs, leave the car alone. The app is reading only.
6. When the log says "Safe discovery finished", look at the left panel:
   - **Platform APIs › ECARX** should say CONNECTED if the adapt API exists on your firmware.
   - **Known signals** shows live values. Check a few against reality:
     - Gear reads **P**.
     - Speed reads **0.0 km/h**.
     - Press **Refresh Known Signals** after each of these, one at a time:
       - turn the steering wheel a little left (angle should become positive / "left");
       - press the brake pedal (Brake pedal ON, brake depth rises);
       - switch the left indicator on, then off; then the right;
       - open and close the driver's door.
   - Note any value that does not match what you did. That mismatch matters more than a match.

## 3. Optional steps (each is your choice; see READ_ONLY_AUDIT.md first)

7. **Binder interface names** (toggle, default OFF). Turning it ON and pressing Run Safe Discovery again also records the AIDL interface name of each relevant system service. It sends one standard "what interface are you?" query per service. Skip it if you prefer; the service names are already in the report.
8. **Read SDK-named ADAS ids once (parked)**. Reads, once, each ADAS/lane/target-related id that the ECARX SDK itself names, using the same getters as the known signals. A confirmation dialog explains it. Skip it if you would rather review the catalogue in the report first.

## 4. Short parked capture

9. Press **Start Read-Only Capture (parked)**. It refuses to start unless gear reads P (or asks you to confirm Park if gear is unreadable).
10. Over about two minutes, slowly: indicate left, indicate right, turn the wheel, press and release the brake, switch headlights on and off, open and close the driver's door. Optionally open the factory 360° camera view and close it again.
11. Press **Stop Capture**.

## 5. Export and stop

12. Press **Export Report**. It writes to the app's storage and copies to `Download/SRProbe/` if the system allows.
13. If you cannot reach Downloads from the car, use **Save Report To Folder / USB…** (pick a USB drive in the system picker) or **Share Report…**.
14. You should have three files: `srprobe-report.md`, `srprobe-discovery.json`, `srprobe-events.jsonl` (plus a zip with all three).
15. Close the app. You are done.

Send me the three files (or the zip) plus your notes from step 0 and any mismatches from step 6. If nothing can be exported, photograph the left panel and the log.

## If something looks wrong

- The factory 360° view, warnings or cluster behave differently while the app is open: close the app, note what happened, and tell me. (Not expected; the app only reads.)
- The app crashes: relaunch it and press Export Report straight away; the log usually shows the step that failed.
- ECARX shows NOT FOUND or ERROR: that is a valid result. Export anyway; the package and service inventory is still useful.
