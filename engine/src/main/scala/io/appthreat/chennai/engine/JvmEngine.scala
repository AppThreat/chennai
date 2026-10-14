package io.appthreat.chennai.engine

import io.circe.Json
import io.circe.parser.parse

import java.io.{
    BufferedReader,
    BufferedWriter,
    File as JFile,
    InputStreamReader,
    OutputStreamWriter
}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{
    DirectoryNotEmptyException,
    FileAlreadyExistsException,
    Files,
    Path,
    Paths,
    StandardCopyOption
}
import java.util.Comparator
import java.util.concurrent.TimeUnit
import scala.jdk.CollectionConverters.*
import scala.util.{Try, Using}

/** A JVM engine that runs the REPL-backed commands for a native-image engine.
  *
  * A GraalVM native image carries no class files and cannot define classes at run time, so the
  * Scala REPL behind `eval`, `complete` and expression `flows` cannot run inside it. The native
  * image carries the engine's jars instead (`jvmEngineJars` in build.sbt). On the first such
  * command, [[JvmEngine.Launcher]] unpacks them into the cache, finds a Java runtime the way chen
  * finds a JDK, and starts the engine on it with `--serve`. [[Server]] then hands the open atom
  * over, since an atom can be open in one process only, and forwards every request to it.
  */
final class JvmEngine private[engine] (process: Process):
  private val toEngine =
      new BufferedWriter(new OutputStreamWriter(process.getOutputStream, UTF_8))
  private val fromEngine =
      new BufferedReader(new InputStreamReader(process.getInputStream, UTF_8))

  /** Send one request line and read the engine's reply to it. */
  def send(line: String): Either[String, Json] =
      Guarded {
          toEngine.write(line)
          toEngine.newLine()
          toEngine.flush()
          fromEngine.readLine()
      }.flatMap {
          case null  => Left(exitStatus)
          case reply => parse(reply).left.map(err => s"unreadable reply: ${err.getMessage}")
      }

  /** Open the atom at `path` in the engine. */
  def open(path: String, sourceRoot: Option[String]): Either[String, Unit] =
    val args = Json.fromFields(
      ("path" -> Json.fromString(path)) +: sourceRoot.map("sourceRoot" -> Json.fromString(_)).toList
    )
    val request =
        Json.obj("id" -> Json.fromLong(-1), "cmd" -> Json.fromString("open"), "args" -> args)
    send(request.noSpaces).flatMap { reply =>
        if JvmEngine.succeeded(reply) then Right(())
        else Left(reply.hcursor.get[String]("error").getOrElse("open failed"))
    }

  private def exitStatus: String =
      if process.waitFor(5, TimeUnit.SECONDS) then s"it exited with code ${process.exitValue}"
      else "it stopped answering"

  /** Stop the engine. Closing its input ends its request loop, which closes its atom; that can take
    * a while for a large one, so it gets a minute before it is ended.
    */
  def stop(): Unit =
    Try(toEngine.close())
    if !process.waitFor(60, TimeUnit.SECONDS) then process.destroy()
end JvmEngine

object JvmEngine:
  private val MainClass = "io.appthreat.chennai.engine.Main"

  /** Whether this engine runs as a GraalVM native image. */
  def inNativeImage: Boolean =
      sys.props.get("org.graalvm.nativeimage.imagecode").contains("runtime")

  def succeeded(reply: Json): Boolean = reply.hcursor.get[Boolean]("ok").contains(true)

  /** Starts JVM engines, remembering when there is no Java runtime or no jars to start one with, so
    * that commands such as `complete` do not search again on every key press.
    */
  final class Launcher(env: Map[String, String] = sys.env):
    private var unavailable: Option[String] = None

    def start(): Either[String, JvmEngine] =
        unavailable.toLeft(()).flatMap { _ =>
          val located =
              for
                java <- JavaRuntimes.find(env)
                lib  <- EngineJars.directory(env)
              yield (java, lib)
          located.left.foreach(err => unavailable = Some(err))
          located.flatMap((java, lib) => spawn(java, lib))
        }

    private def spawn(java: JavaRuntimes.Runtime, lib: Path): Either[String, JvmEngine] =
      val options =
          env.get("CHENNAI_JAVA_OPTS").toList.flatMap(_.trim.split("\\s+")).filter(_.nonEmpty)
      // Both options exist from Java 23 on; they keep the JDK's warnings about Scala's lazy vals
      // and jline's native library off the TUI's stderr.
      val command =
          List(
            java.executable.toString,
            "--sun-misc-unsafe-memory-access=allow",
            "--enable-native-access=ALL-UNNAMED"
          ) ++ options ++ List("-cp", s"$lib${JFile.separator}*", MainClass, "--serve")
      Guarded {
          new JvmEngine(
            new ProcessBuilder(command*).redirectError(ProcessBuilder.Redirect.INHERIT).start()
          )
      }.left.map(err => s"could not start ${java.executable}: $err")
  end Launcher
end JvmEngine

/** Finds a Java runtime for the JVM engine where chen looks for a JDK: the configured homes, the
  * `java` on PATH, then the usual install folders, newest first.
  */
object JavaRuntimes:
  /** The engine is compiled with `--release 23`. */
  val MinimumVersion = 23

  val HomeEnvVars: List[String] = List("CHENNAI_JAVA_HOME", "JAVA_HOME", "JDK_HOME")

  final case class Runtime(home: Path, executable: Path, version: Int)

  private def isWindows = sys.props.get("os.name").exists(_.toLowerCase.contains("win"))

  def find(
    env: Map[String, String] = sys.env,
    roots: List[Path] = defaultRoots
  ): Either[String, Runtime] =
    val found = candidateHomes(env, roots).flatMap(runtimeAt)
    found.find(_.version >= MinimumVersion).toRight {
        val older = found.map(r => s"Java ${r.version} at ${r.home}").distinct
        val seen  = if older.isEmpty then "" else s"; found only ${older.mkString(", ")}"
        s"no Java $MinimumVersion or later found (looked at ${HomeEnvVars.mkString(", ")}, " +
            s"java on PATH and the usual install folders$seen); install one or set CHENNAI_JAVA_HOME"
    }

  private[engine] def candidateHomes(env: Map[String, String], roots: List[Path]): List[Path] =
    val configured = HomeEnvVars.flatMap(env.get).flatMap(toPath)
    // Windows names it Path, and a Scala Map does not look keys up case-insensitively.
    val onPath    = env.get("PATH").orElse(env.get("Path")).toList.flatMap(javaHomesOnPath)
    val installed = roots.flatMap(installedHomes)
    (configured ++ onPath ++ installed).distinct

  private def toPath(s: String): Option[Path] =
      Option(s).map(_.trim).filter(_.nonEmpty).flatMap(p => Try(Paths.get(p)).toOption)

  private def executableIn(home: Path): Path =
      home.resolve("bin").resolve(if isWindows then "java.exe" else "java")

  private def runtimeAt(home: Path): Option[Runtime] =
    val java = executableIn(home)
    Option.when(Files.isRegularFile(java) && Files.isExecutable(java))(
      Runtime(home, java, javaVersion(home))
    )

  /** The homes of the `java` executables on PATH, following symlinks (`/usr/bin/java` ->
    * `/usr/lib/jvm/x/bin/java`).
    */
  private def javaHomesOnPath(pathEnv: String): List[Path] =
      pathEnv.split(JFile.pathSeparator).toList.flatMap(toPath).flatMap { dir =>
        val java = dir.resolve(if isWindows then "java.exe" else "java")
        Option.when(Files.isExecutable(java))(java).toList
            .flatMap(j => Try(j.toRealPath()).toOption)
            .flatMap(real => Option(real.getParent).flatMap(bin => Option(bin.getParent)))
      }

  /** The Java homes directly under an install folder, newest first. */
  private def installedHomes(root: Path): List[Path] =
      if !Files.isDirectory(root) then Nil
      else
        Try(Using.resource(Files.list(root))(_.iterator().asScala.toList)).getOrElse(Nil)
            .flatMap { dir =>
              // macOS bundles keep the home in Contents/Home.
              val macHome = dir.resolve("Contents").resolve("Home")
              if Files.isDirectory(macHome) then Some(macHome)
              else Option.when(Files.isDirectory(dir))(dir)
            }
            .sortBy(javaVersion)(using Ordering[Int].reverse)

  /** The feature version of a Java home from its `release` file, or 0 when unknown. */
  private[engine] def javaVersion(home: Path): Int =
      Try {
          Using.resource(scala.io.Source.fromFile(home.resolve("release").toFile)) { src =>
              src.getLines()
                  .collectFirst {
                      case line if line.startsWith("JAVA_VERSION=") =>
                          line.stripPrefix("JAVA_VERSION=").replace("\"", "")
                  }
                  .map(featureVersion)
                  .getOrElse(0)
          }
      }.getOrElse(0)

  /** `1.8.0_412` -> 8, `21.0.7` -> 21, `26-ea` -> 26. */
  private[engine] def featureVersion(version: String): Int =
    val parts = version.takeWhile(c => c.isDigit || c == '.').split('.').filter(_.nonEmpty)
    parts.headOption.flatMap(_.toIntOption) match
      case Some(1) => parts.lift(1).flatMap(_.toIntOption).getOrElse(0)
      case Some(v) => v
      case None    => 0

  private def defaultRoots: List[Path] =
    val home = sys.props.get("user.home").toList
    val roots =
        if isWindows then
          List("Java", "Eclipse Adoptium", "Microsoft", "Zulu", "Amazon Corretto", "BellSoft")
              .flatMap(vendor =>
                  sys.env.get("ProgramFiles").toList.map(pf => s"$pf${JFile.separator}$vendor")
              )
        else
          List("/Library/Java/JavaVirtualMachines", "/usr/lib/jvm", "/usr/java", "/opt/java") ++
              home.flatMap(h =>
                  List(
                    s"$h/Library/Java/JavaVirtualMachines",
                    s"$h/.sdkman/candidates/java",
                    s"$h/.jdks"
                  )
              )
    roots.flatMap(toPath)
end JavaRuntimes

/** The jars the JVM engine runs on: the folder named by `CHENNAI_ENGINE_LIB`, or the copy this
  * native image carries, unpacked once per build into the cache.
  */
object EngineJars:
  val LibEnv   = "CHENNAI_ENGINE_LIB"
  val CacheEnv = "CHENNAI_CACHE_DIR"

  /** Where build.sbt puts the jars in the image, with an index: the bundle's id on the first line,
    * then one jar name per line.
    */
  private val ResourceDir = "chennai/jvm-engine"
  private val Complete    = ".complete"

  def directory(env: Map[String, String] = sys.env): Either[String, Path] =
      env.get(LibEnv).map(_.trim).filter(_.nonEmpty) match
        case Some(dir) =>
            val lib = Paths.get(dir)
            if Files.isDirectory(lib) then Right(lib) else Left(s"$LibEnv=$dir is not a folder")
        case None => unpacked(cacheRoot(env))

  private def index: Option[List[String]] =
      Option(getClass.getResourceAsStream(s"/$ResourceDir/index.txt")).map { in =>
          Using.resource(scala.io.Source.fromInputStream(in, "UTF-8"))(
            _.getLines().map(_.trim).filter(_.nonEmpty).toList
          )
      }

  private[engine] def unpacked(cache: Path): Either[String, Path] =
      index match
        case Some(id :: jars) if jars.nonEmpty =>
            val dir = cache.resolve("jvm-engine").resolve(id)
            Guarded {
                if !Files.isRegularFile(dir.resolve(Complete)) then unpack(dir, jars)
                dir.resolve("lib")
            }.left.map(err => s"could not unpack the engine's jars into $dir: $err")
        case _ =>
            Left(
              s"this engine was built without its jars; set $LibEnv to the lib folder of a " +
                  "chennai-engine stage"
            )

  /** Unpack into a staging folder and move it into place, so that an engine never sees a partial
    * copy and two engines starting together do not trip over each other.
    */
  private def unpack(dir: Path, jars: List[String]): Unit =
    val staging = Files.createTempDirectory(
      Files.createDirectories(dir.getParent),
      s"${dir.getFileName}-"
    )
    try
      val lib = Files.createDirectories(staging.resolve("lib"))
      jars.foreach { jar =>
        require(!jar.contains('/') && !jar.contains('\\') && !jar.startsWith("."), jar)
        val in = getClass.getResourceAsStream(s"/$ResourceDir/lib/$jar")
        require(in != null, s"$jar is missing from the engine")
        Using.resource(in)(Files.copy(_, lib.resolve(jar)))
      }
      Files.createFile(staging.resolve(Complete))
      if !Files.isRegularFile(dir.resolve(Complete)) then
        // Left without its marker by an engine that stopped while moving it into place.
        if Files.exists(dir) then deleteTree(dir)
        try Files.move(staging, dir, StandardCopyOption.ATOMIC_MOVE)
        catch
          case _: FileAlreadyExistsException | _: DirectoryNotEmptyException =>
              () // another engine moved its copy in first
      pruneOthers(dir)
    finally if Files.exists(staging) then deleteTree(staging)
  end unpack

  /** Remove the copies of earlier builds, about 80 MB each, best effort: Windows does not let go of
    * the jars of a JVM engine still running on them. The marker goes first, so a copy left half
    * removed is unpacked again rather than used. Staging folders (`<id>-<suffix>`) of engines
    * unpacking right now are left alone.
    */
  private def pruneOthers(dir: Path): Unit =
      Try(Using.resource(Files.list(dir.getParent))(_.iterator().asScala.toList)).getOrElse(Nil)
          .filter(p => p != dir && Files.isDirectory(p) && !p.getFileName.toString.contains('-'))
          .foreach(p => Try { Files.deleteIfExists(p.resolve(Complete)); deleteTree(p) })

  private def deleteTree(root: Path): Unit =
      Using.resource(Files.walk(root))(
        _.sorted(Comparator.reverseOrder[Path]()).forEach(p => Files.deleteIfExists(p))
      )

  private[engine] def cacheRoot(env: Map[String, String]): Path =
    def dir(key: String) = env.get(key).map(_.trim).filter(_.nonEmpty).map(Paths.get(_))
    val home             = Paths.get(sys.props.getOrElse("user.home", "."))
    val os               = sys.props.getOrElse("os.name", "").toLowerCase
    dir(CacheEnv).getOrElse {
        if os.contains("win") then
          dir("LOCALAPPDATA").getOrElse(home.resolve("AppData").resolve("Local"))
              .resolve("chennai").resolve("cache")
        else if os.contains("mac") then home.resolve("Library").resolve("Caches").resolve("chennai")
        else dir("XDG_CACHE_HOME").getOrElse(home.resolve(".cache")).resolve("chennai")
    }
end EngineJars
