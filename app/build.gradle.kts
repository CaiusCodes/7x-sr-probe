plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "au.local.zeekr.srprobe"
    compileSdk = 34

    defaultConfig {
        applicationId = "au.local.zeekr.srprobe"
        // The 7X head unit reports Android 12 (API 31). 26 keeps the APK installable on older test devices.
        minSdk = 26
        targetSdk = 34
        versionCode = 2
        versionName = "0.1.1"
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            // v0.1 is a diagnostic build; keep reflection-heavy code unobfuscated so the audit matches the binary.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

// Deliberately no dependencies beyond the Kotlin standard library: no AndroidX, no networking,
// no camera, no analytics. Everything the probe does is visible in this module's sources.
