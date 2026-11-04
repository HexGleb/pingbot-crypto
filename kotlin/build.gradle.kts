// :cl1: the CL1 envelope crypto, alone in its own module so the published code is exactly what the app builds.
// Built two ways: as :cl1 inside the app's Gradle build (android/settings.gradle.kts points here), and on its
// own from the crypto/ folder (crypto/settings.gradle.kts). Pure Kotlin on the JVM, no dependencies.
plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

dependencies {
    testImplementation(libs.junit)
}

// The shared test vectors (crypto/vectors/cl1.txt), read by the tests on every side.
tasks.test {
    val vectors = projectDir.resolve("../vectors/cl1.txt")
    inputs.file(vectors).withPropertyName("cl1Vectors")
    systemProperty("cl1.vectors", vectors.canonicalPath)
}
