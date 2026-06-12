// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox-Deb :: Android ToolBox client (#531)
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "SecuBoxToolBox"
include(":app")
