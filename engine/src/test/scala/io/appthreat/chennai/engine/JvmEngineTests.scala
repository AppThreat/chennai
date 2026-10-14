package io.appthreat.chennai.engine

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.nio.file.attribute.PosixFilePermissions
import scala.util.Try

class JvmEngineTests extends AnyWordSpec with Matchers:

  private def tempDir(): Path = Files.createTempDirectory("chennai-jvm-engine-")

  /** A fake Java home: an executable `bin/java` and a `release` file naming `version`. */
  private def javaHome(root: Path, name: String, version: String): Path =
    val home = Files.createDirectories(root.resolve(name))
    val java = Files.createDirectories(home.resolve("bin")).resolve(
      if sys.props("os.name").toLowerCase.contains("win") then "java.exe" else "java"
    )
    Files.writeString(java, "")
    Try(Files.setPosixFilePermissions(java, PosixFilePermissions.fromString("rwxr-xr-x")))
    Files.writeString(home.resolve("release"), s"JAVA_VERSION=\"$version\"\n")
    home

  "Guarded" should:
    "turn exceptions, linkage errors and stack overflows into messages" in:
      Guarded(throw new IllegalStateException("no scala")) shouldBe Left("no scala")
      Guarded(throw new NoClassDefFoundError("dotty/tools/repl/Rendering")) shouldBe
          Left("dotty/tools/repl/Rendering")
      Guarded(throw new StackOverflowError()) shouldBe Left("java.lang.StackOverflowError")
      Guarded(42) shouldBe Right(42)

    "let running out of memory end the engine" in:
      an[OutOfMemoryError] should be thrownBy Guarded(throw new OutOfMemoryError("heap"))

  "JavaRuntimes" should:
    "read feature versions" in:
      JavaRuntimes.featureVersion("1.8.0_412") shouldBe 8
      JavaRuntimes.featureVersion("23.0.2") shouldBe 23
      JavaRuntimes.featureVersion("26-ea") shouldBe 26
      JavaRuntimes.featureVersion("") shouldBe 0

    "pick the newest installed runtime that is new enough" in:
      val root = tempDir()
      javaHome(root, "jdk-21", "21.0.7")
      javaHome(root, "jdk-23", "23.0.2")
      val jdk25 = javaHome(root, "jdk-25", "25.0.2")
      JavaRuntimes.find(Map.empty, List(root)).map(_.home) shouldBe Right(jdk25)

    "prefer a configured home over the installed ones, but not an old one" in:
      val root = tempDir()
      javaHome(root, "jdk-25", "25.0.2")
      val configured = javaHome(tempDir(), "jdk-23", "23.0.1")
      val old        = javaHome(tempDir(), "jdk-17", "17.0.15")
      JavaRuntimes.find(Map("JAVA_HOME" -> configured.toString), List(root)).map(_.home) shouldBe
          Right(configured)
      JavaRuntimes.find(Map("CHENNAI_JAVA_HOME" -> old.toString), List(root)).map(
        _.version
      ) shouldBe
          Right(25)

    "say what it found when nothing is new enough" in:
      val root = tempDir()
      javaHome(root, "jdk-21", "21.0.7")
      val err = JavaRuntimes.find(Map.empty, List(root)).swap.getOrElse("")
      err should include("no Java 23 or later found")
      err should include("found only Java 21")
      err should include("CHENNAI_JAVA_HOME")

  "EngineJars" should:
    "use the folder CHENNAI_ENGINE_LIB names" in:
      val lib = tempDir()
      EngineJars.directory(Map("CHENNAI_ENGINE_LIB" -> lib.toString)) shouldBe Right(lib)
      EngineJars.directory(Map("CHENNAI_ENGINE_LIB" -> lib.resolve("nope").toString)).isLeft shouldBe
          true

    "unpack the jars it carries once, into a folder named by the bundle" in:
      // src/test/resources/chennai/jvm-engine stands in for the jars build.sbt packs for the image
      val cache = tempDir()
      val lib   = EngineJars.unpacked(cache).fold(err => fail(err), identity)
      lib shouldBe cache.resolve("jvm-engine").resolve("test-bundle").resolve("lib")
      Files.readString(lib.resolve("fake.jar"), UTF_8).trim shouldBe "not really a jar"
      Files.writeString(lib.resolve("fake.jar"), "kept")
      EngineJars.unpacked(cache) shouldBe Right(lib)
      Files.readString(lib.resolve("fake.jar"), UTF_8) shouldBe "kept"

    "remove the copies of earlier builds, but not a copy being unpacked" in:
      val cache   = tempDir()
      val earlier = Files.createDirectories(cache.resolve("jvm-engine/0123456789abcdef/lib"))
      Files.writeString(earlier.resolve("old.jar"), "old")
      Files.writeString(earlier.getParent.resolve(".complete"), "")
      val staging = Files.createDirectories(cache.resolve("jvm-engine/0123456789abcdef-42"))
      EngineJars.unpacked(cache).isRight shouldBe true
      Files.exists(earlier.getParent) shouldBe false
      Files.isDirectory(staging) shouldBe true

    "replace a copy left without its marker" in:
      val cache = tempDir()
      val left  = Files.createDirectories(cache.resolve("jvm-engine/test-bundle/lib"))
      Files.writeString(left.resolve("fake.jar"), "partial")
      val lib = EngineJars.unpacked(cache).fold(err => fail(err), identity)
      Files.readString(lib.resolve("fake.jar"), UTF_8).trim shouldBe "not really a jar"

    "keep its cache where the platform keeps caches" in:
      EngineJars.cacheRoot(Map("CHENNAI_CACHE_DIR" -> "/tmp/c")) shouldBe Path.of("/tmp/c")
      val os = sys.props("os.name").toLowerCase
      if !os.contains("win") && !os.contains("mac") then
        EngineJars.cacheRoot(Map("XDG_CACHE_HOME" -> "/tmp/x")) shouldBe Path.of("/tmp/x/chennai")
end JvmEngineTests
