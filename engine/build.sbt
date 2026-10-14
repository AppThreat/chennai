name                     := "chennai-engine"
ThisBuild / organization := "io.appthreat"
ThisBuild / version      := "1.0.3"
ThisBuild / scalaVersion := "3.10.0"

val chenVersion   = "3.0.1"
val circeVersion  = "0.14.16"

ThisBuild / resolvers ++= Seq(
  Resolver.defaultLocal,
  Resolver.mavenLocal,
  "Sonatype OSS" at "https://oss.sonatype.org/content/repositories/public"
)

githubOwner                      := "appthreat"
githubRepository                 := "atom"
credentials +=
  Credentials(
    "GitHub Package Registry",
    "maven.pkg.github.com",
    "appthreat",
    sys.env.getOrElse("GITHUB_TOKEN", "N/A")
  )

lazy val engine = (project in file("."))
  .enablePlugins(JavaAppPackaging, GraalVMNativeImagePlugin)
  .settings(
    libraryDependencies ++= Seq(
      "io.appthreat" %% "dataflowengineoss" % chenVersion,
      "io.appthreat" %% "semanticcpg"       % chenVersion,
      "io.appthreat" %% "x2cpg"             % chenVersion,
      "org.scala-lang" %% "scala3-compiler" % scalaVersion.value,
      "org.scala-lang" %% "scala3-repl"     % scalaVersion.value,
      "io.circe"     %% "circe-core"        % circeVersion,
      "io.circe"     %% "circe-parser"      % circeVersion,
      "com.github.scopt" %% "scopt"         % "4.1.0",
      "org.slf4j"     % "slf4j-nop"         % "2.0.18",
      "org.scalatest" %% "scalatest"        % "3.2.20" % Test
    ),
    Compile / mainClass := Some("io.appthreat.chennai.engine.Main"),
    executableScriptName := "chennai-engine",
    scalacOptions ++= Seq("-deprecation", "-feature", "--release", "23"),
    Test / fork := true,
    // sbt 2 runs the suites of a forked test JVM in parallel by default; keep sbt 1's one-at-a-time
    // runs, since the engine's REPL context and result sinks are process-wide singletons
    Test / testForkedParallel := false,
    // sbt 2 packs test classes+resources into jars (exportJars := true); keep exploded dirs so
    // tests can read their fixtures as plain files
    Test / exportJars := false,
    // sbt 2 moves `target` to target/out/jvm/scala-<version>/chennai-engine; the TUI, CI and the
    // release scripts expect the staged engine and the native image where sbt 1 put them
    Universal / UniversalPlugin.autoImport.stagingDirectory := baseDirectory.value / "target" / "universal" / "stage",
    GraalVMNativeImage / target := baseDirectory.value / "target" / "graalvm-native-image",
    // sbt 1's clean removed all of target; sbt 2's only removes target/out, so clean these too, or
    // a stage keeps the jars of earlier builds (and the npm jar fallback packages them)
    cleanFiles ++= Seq(
      (Universal / UniversalPlugin.autoImport.stagingDirectory).value,
      (GraalVMNativeImage / target).value
    )
  )

// executeTests reads it through a dynamic task, which lintUnused cannot see
Global / excludeLintKeys += testForkedParallel

val libcOptions = if (sys.env.getOrElse("CHENNAI_GRAALVM_LIBC", "glibc") == "musl") Seq("--libc=musl") else Seq.empty
val niOpt = sys.env.getOrElse("CHENNAI_NI_OPT", "-O2")
val niMarch = sys.env.getOrElse("CHENNAI_NI_MARCH", "compatibility")
val niGc = sys.env.getOrElse("CHENNAI_NI_GC", "serial")
graalVMNativeImageOptions := Seq(
  "-H:+UnlockExperimentalVMOptions",
  "-R:MaximumHeapSizePercent=90",
  s"--gc=$niGc",
  "-H:+CompactingOldGen",
  niOpt,
  s"-march=$niMarch",
  "--initialize-at-build-time=io.appthreat.*",
  "--no-fallback"
) ++ libcOptions
