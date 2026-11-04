// Standalone build of the Kotlin side (run from this folder: `gradle :kotlin:test`, Gradle 9). Inside the
// PingBot app the same module is built as :cl1 by android/settings.gradle.kts; this file is not used there.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "pingbot-crypto"
include(":kotlin")
