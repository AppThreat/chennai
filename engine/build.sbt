name                     := "chennai-engine"
ThisBuild / organization := "io.appthreat"
ThisBuild / version      := "1.0.1"
ThisBuild / scalaVersion := "3.8.4"

val chenVersion   = "3.0.0"
val circeVersion  = "0.14.16"

ThisBuild / resolvers ++= Seq(
  Resolver.defaultLocal,
  Resolver.mavenLocal,
  "Sonatype OSS" at "https://oss.sonatype.org/content/repositories/public"
)

githubOwner                      := "appthreat"
githubRepository                 := "atom"
githubSuppressPublicationWarning := true
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
    Test / fork := true
  )

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
