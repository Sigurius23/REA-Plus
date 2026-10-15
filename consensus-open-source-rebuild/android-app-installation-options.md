# Android app installation options by computer and device access

**Research checked:** 9 October 2026  
**Scope:** Install Android apps from Google Play on macOS, Windows, or Linux, then—where useful—retrieve installed APK files for analysis. The primary example in this project is Consensus (`app.consensus.android`). This is a practical shortlist, not a catalogue of every gaming emulator.

## Quick recommendation

- **If you have an Android phone:** install the app from Google Play on the phone. This is usually the most representative environment. Use Android Debug Bridge (ADB) from any of the three desktop operating systems to inspect the installed package and copy its APK file(s).
- **If you do not have a phone:** use **Android Studio's Android Emulator (AVD)** and create a virtual phone with a system image explicitly labelled **Google Play**. It is the strongest general-purpose option across macOS, Windows, and Linux.
- **Secondary options:** Genymotion Desktop can add Google Play using its built-in Google Apps installer. BlueStacks is more consumer/game-oriented and is not my first choice for a repeatable APK-analysis workflow.

## Choose by computer and whether you have a phone

| Computer | If you have an Android phone | If you do not have an Android phone |
|---|---|---|
| **macOS** | Install from Play on the phone, connect by USB, and use ADB from macOS. | Use Android Studio + an AVD with a Google Play image. On Apple Silicon, select an available `arm64-v8a` image; on Intel, choose an image supported by the host. Genymotion Desktop is another option. BlueStacks Air is an Apple-Silicon, game-focused alternative. |
| **Windows** | Install from Play on the phone, connect by USB, and use ADB from Windows. | Use Android Studio + an AVD with a Google Play image. Enable hardware virtualization; Android recommends Windows Hypervisor Platform (WHPX). Genymotion Desktop and BlueStacks 5 are alternatives. |
| **Linux** | Install from Play on the phone, connect by USB, and use ADB from Linux. | Use Android Studio + an AVD with a Google Play image and KVM acceleration. Genymotion Desktop is another option on its supported Linux distributions. |

ADB is included with Android SDK Platform-Tools and is available on all three desktop platforms. For a phone, enable USB debugging and authorize the computer on the device when prompted.

## Emulator comparison

| Option | Host OS | Install from Google Play? | Best fit here | Practical limitations |
|---|---|---|---|---|
| **Android Studio Emulator / AVD** | macOS, Windows, Linux | **Yes.** Choose a phone profile marked with the **Play Store** badge and a system image that includes Google Play. | **Recommended when no phone is available.** Official Android tooling, Play Store support, and straightforward ADB access. | More setup and resource use than a consumer app player. Google currently lists 16 GB RAM and 16 GB disk as emulator system requirements; higher API levels or larger virtual devices may need more. Physical-device-dependent app features may behave differently. |
| **Genymotion Desktop** | Windows, macOS, Linux; check current host and distribution requirements | **Yes, after setup.** Google Apps are not preinstalled; Genymotion provides a built-in installer that adds Google Play and Google services. | Cross-platform secondary emulator for device-profile and sensor testing. Genymotion advertises native ARM64 images on Apple Silicon Macs. | Some apps may be unavailable or show as incompatible with the virtual device. Play compatibility is not universal. |
| **BlueStacks 5** | Windows | **Yes.** Its documented install flow uses the Play Store. | Convenient consumer/game-oriented app player on Windows. | Less suited than Android Studio for controlled device profiles and repeatable package-analysis work. |
| **BlueStacks Air** | Apple-Silicon Macs | Google Play is used for supported games/titles; the product documentation is game-focused. | Gaming on an Apple-Silicon Mac. | Not my recommendation for general app acquisition or REA/JADX work. Confirm current chip and app support before relying on it. |
| **Google Play Games on PC** | Windows | It provides Google Play **games**, not a general Play Store for arbitrary Android apps. | Playing games in Google's supported PC catalog. | **Not suitable for downloading a general Android app** such as a research/productivity app. |

## Android Studio: the recommended no-phone route

1. Install Android Studio and its Android Emulator/SDK components.
2. Open **Device Manager → Create Device** and select a phone profile showing the **Play Store** badge.
3. On the system-image screen, choose an image that explicitly says **Google Play**. A **Google APIs** image provides Google APIs/services but is not, by itself, the same selection as a Play Store image.
4. Start the virtual phone, sign in to Google Play, and install the app as you would on a phone.
5. Use ADB to inspect the installed package or retrieve its APK file(s).

Google's AVD documentation says Play Store-marked phone profiles are CTS-compliant and may use system images with the Play Store app. The images offered depend on Android version and host CPU architecture. Android's current emulator page lists 64-bit Windows 10+, macOS 12+, or Linux, and 16 GB RAM/16 GB disk as system requirements. Hardware acceleration uses WHPX on Windows, Hypervisor.framework on macOS, and KVM on Linux.

## Genymotion: useful alternative, with a compatibility caveat

Genymotion Desktop supports Windows, macOS, and Linux, with native ARM64 images available on Apple Silicon Macs. Its Google Play instructions say Google Apps are not included by default; use the built-in **Install GApps** feature and restart the virtual device. Genymotion notes that some apps may be unavailable or report that the virtual device is incompatible. For an app that must be installed from Play, try Android Studio's Play-enabled AVD first.

## BlueStacks and Google Play Games

BlueStacks 5 documents installing apps from its Play Store on Windows. BlueStacks Air is the Mac/Apple-Silicon product, but its support materials are primarily about gaming; Android Studio or a real phone is a better starting point for general app analysis. Google Play Games on PC is Windows-only and presents a supported game catalog, not a general Android app environment.

## Retrieving an installed package for REA

With a phone or AVD running and visible in ADB:

```sh
adb devices
adb shell pm path app.consensus.android
```

The package manager prints one or more device-side paths. Pull **every** path it returns, for example:

```sh
mkdir consensus-apks
adb pull <returned-device-path> ./consensus-apks/
```

Repeat `adb pull` for each returned path, preserving the filenames. A Play install can consist of a base APK plus split APKs; `pm path` shows what that particular installation has. The same ADB workflow works from macOS, Linux, and Windows (PowerShell or Command Prompt).

REA can statically inspect a supplied Android APK using headless JADX. Its Android guide explicitly says its Android provider does **not** implement split-APK/AAB handling. If `pm path` returns multiple files, keep all of them and do not assume that analyzing only `base.apk` represents the full installed app. REA is the analysis stage, not the Play Store downloader or split-package manager.

## Which route I would use

1. **Phone available:** use the real phone for installation and first-pass behavior observation; run ADB from whichever computer is convenient.
2. **No phone:** start with Android Studio's Play-enabled AVD on macOS, Windows, or Linux.
3. **App missing or marked incompatible in the AVD:** try a physical phone before spending time on a different emulator. Genymotion is a secondary option, but its Play compatibility is not universal.
4. **App depends on a camera, Bluetooth accessory, cellular feature, device-integrity behavior, or other physical-device capability:** an emulator may install it but not reproduce the full experience. A phone is more representative; this may matter for camera companion apps.

**Status:** no emulator has been installed or tested against Consensus or the Osmo 360 app as part of this compilation. The Consensus package ID above comes from its Google Play listing; installation success on a particular emulator remains to be checked.

## Sources

- [Android Emulator: run apps on the Android Emulator](https://developer.android.com/studio/run/emulator)
- [Android Studio: create and manage AVDs](https://developer.android.com/studio/run/managing-avds)
- [Android Emulator: hardware acceleration](https://developer.android.com/studio/run/emulator-acceleration)
- [Android Debug Bridge (ADB)](https://developer.android.com/studio/command-line/adb)
- [Genymotion Desktop](https://www.genymotion.com/product-desktop/)
- [Genymotion Desktop downloads and host requirements](https://www.genymotion.com/product-desktop/download/)
- [Genymotion: install Google Play and Google Apps](https://docs.genymotion.com/features/opengapps/)
- [BlueStacks 5: install an app from the Play Store](https://support.bluestacks.com/hc/en-us/articles/360057712191-How-to-install-an-app-from-the-BlueStacks-Store-Play-Store-or-using-an-APK-on-BlueStacks-5)
- [BlueStacks Air: requirements for Mac](https://support.bluestacks.com/hc/en-us/articles/32272913555597-System-specifications-for-installing-BlueStacks-Air)
- [Google Play Games on PC: requirements and availability](https://support.google.com/googleplaygamesonpc/answer/11358071?hl=en)
- [Consensus for Android on Google Play](https://play.google.com/store/apps/details?id=app.consensus.android)
