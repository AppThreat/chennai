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
    ),
    jvmEngineJars := Def.uncached {
      val conv = fileConverter.value
      val jars = scriptClasspathOrdering.value.map { case (ref, mapped) =>
        conv.toPath(ref).toFile -> mapped.stripPrefix("lib/")
      }
      // Named by their content, so an engine unpacks a new copy only for a different build
      val digest = java.security.MessageDigest.getInstance("SHA-256")
      jars.foreach { case (jar, name) =>
        digest.update(name.getBytes("UTF-8"))
        digest.update(IO.readBytes(jar))
      }
      val id  = digest.digest().take(8).map(b => f"$b%02x").mkString
      val out = target.value / "jvm-engine" / "chennai-jvm-engine.jar"
      IO.createDirectory(out.getParentFile)
      val zip = new java.util.zip.ZipOutputStream(new java.io.FileOutputStream(out))
      try {
        def add(path: String, bytes: Array[Byte]): Unit = {
          zip.putNextEntry(new java.util.zip.ZipEntry(path))
          zip.write(bytes)
          zip.closeEntry()
        }
        jars.foreach { case (jar, name) => add(s"chennai/jvm-engine/lib/$name", IO.readBytes(jar)) }
        add("chennai/jvm-engine/index.txt", (id +: jars.map(_._2)).mkString("", "\n", "\n").getBytes("UTF-8"))
        add(
          "META-INF/native-image/io.appthreat/chennai-jvm-engine/reachability-metadata.json",
          """{"resources":[{"glob":"chennai/jvm-engine/**"}]}""".getBytes("UTF-8")
        )
      } finally zip.close()
      out
    },
    GraalVMNativeImage / scriptClasspathOrdering := Def.uncached {
      scriptClasspathOrdering.value :+
        (fileConverter.value.toVirtualFile(jvmEngineJars.value.toPath) -> "lib/chennai-jvm-engine.jar")
    }
  )

// A native image cannot run the Scala REPL (it has no class files and cannot define classes at run
// time), so it carries the engine's jars and runs eval, complete and expression flows on a JVM
// (JvmEngine.scala). They are resources of one extra jar on the image's class path, not in the stage.
lazy val jvmEngineJars = taskKey[File]("Packs the engine's jars as resources for the native image")

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
  // Every charset, not only the standard six, as atom does: a JVM engine has them all, and the
  // encoding of a source or BOM is known only at run time
  "-H:+AddAllCharsets",
  "--no-fallback"
) ++ libcOptions
