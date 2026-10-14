package io.appthreat.chennai.engine

import dotty.tools.dotc.interactive.Completion
import dotty.tools.repl.{ReplDriver, State}
import io.appthreat.dataflowengineoss.language.Path
import io.shiftleft.codepropertygraph.Cpg

import java.io.{ByteArrayOutputStream, PrintStream}
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicReference

/** Captures the JSON result of a REPL expression out-of-band, so the engine need not parse the
  * REPL's pretty-printed `val resN = ...` echo. The wrapped expression calls [[set]].
  */
object ReplSink:
  private val ref             = new AtomicReference[String](null)
  def set(json: String): Unit = ref.set(json)
  def take(): Option[String]  = Option(ref.getAndSet(null))

/** Captures the `List[Path]` produced by a data-flow expression, evaluated out-of-band so the
  * engine can format the paths in Scala instead of round-tripping through `.toJson`.
  */
object FlowSink:
  private val ref                  = new AtomicReference[List[Path]](null)
  def set(paths: List[Path]): Unit = ref.set(paths)
  def take(): Option[List[Path]]   = Option(ref.getAndSet(null))

/** Holds the open atom for the REPL to pick up via the predef, since `ReplDriver.bind` is a no-op
  * in Scala 3.8.4. The engine is single-session, so a single global binding is sufficient.
  */
object ReplContext:
  @volatile private var cpgRef: Cpg = null
  def install(cpg: Cpg): Unit       = cpgRef = cpg
  def atom: Cpg                     = cpgRef

/** Embeds the official Scala 3 REPL ([[dotty.tools.repl.ReplDriver]]) with the chennai DSL imported
  * and the open atom bound as `atom`, evaluating arbitrary chen queries.
  *
  * Unrecognised TUI commands are normalised to end in `.toJson` and evaluated here, so the result
  * is always a JSON string the TUI can render as a table.
  *
  * `ReplDriver` is an internal Scala API; all coupling to it is isolated in this one file (see the
  * implementation plan's risk note).
  */
final class ReplBridge(cpg: Cpg):

  private val outBuf = new ByteArrayOutputStream()
  private val out    = new PrintStream(outBuf, true, StandardCharsets.UTF_8)

  // Imports baked into the REPL's init script (the `extraPredef` constructor argument), so the
  // chennai DSL is in scope for every evaluation.
  ReplContext.install(cpg)

  private val predef = Seq(
    "import _root_.io.shiftleft.codepropertygraph.Cpg",
    "import _root_.io.shiftleft.codepropertygraph.generated.*",
    "import _root_.io.shiftleft.codepropertygraph.generated.nodes.*",
    "import _root_.io.shiftleft.semanticcpg.language.*",
    "import _root_.io.appthreat.dataflowengineoss.language.*",
    "import _root_.io.appthreat.dataflowengineoss.queryengine.EngineContext",
    "import _root_.scala.jdk.CollectionConverters.*",
    "given EngineContext = EngineContext()",
    "val atom: _root_.io.shiftleft.codepropertygraph.Cpg = _root_.io.appthreat.chennai.engine.ReplContext.atom"
  ).mkString("\n")

  private var state: State = scala.compiletime.uninitialized

  // Booted on first use: booting the compiler is expensive and must not delay engine startup or
  // non-REPL commands. A failed boot (no compiler classpath, as in a native image) is kept and
  // reported by every REPL command instead of being retried.
  private lazy val driver: Either[String, ChennaiReplDriver] =
      Guarded {
          // `-Xrepl-interrupt-instrumentation:false` makes the REPL classloader delegate to our
          // parent classloader instead of re-defining (instrumenting) app classes locally. Without
          // it, chen's `Cpg` and our `ReplContext` would be duplicated in a separate classloader
          // and the open atom would be invisible to evaluated code.
          val settings =
              Array("-usejavacp", "-color:never", "-Xrepl-interrupt-instrumentation:false")
          val d = new ChennaiReplDriver(settings, out, Some(getClass.getClassLoader), predef)
          state = d.initialState
          d
      }.left.map(err => s"the Scala REPL could not start: $err")

  /** Run `code` in the REPL, keeping the state it leaves for the next evaluation. */
  private def run(code: String): Either[String, Unit] =
      driver.flatMap { d =>
        outBuf.reset()
        Guarded { state = d.run(code)(using state) }.left.map(err => s"repl error: $err")
      }

  /** What the REPL printed for the last evaluation (its compile errors), or `fallback`. */
  private def printed(fallback: String): String =
    val msg = outBuf.toString(StandardCharsets.UTF_8).trim
    if msg.nonEmpty then msg else fallback

  private val terminals = List(".toJsonPretty", ".toJson", ".toList", ".p", ".l")

  /** Strip any trailing collection/render terminal and append `.toJson` so the expression yields a
    * JSON string.
    */
  private[engine] def normalise(expr: String): String =
    var e       = expr.trim
    var changed = true
    while changed do
      changed = false
      terminals.find(t => e.endsWith(t)).foreach { t =>
        e = e.dropRight(t.length).trim
        changed = true
      }
    s"$e.toJson"

  /** Evaluate `expr`, returning the JSON produced by `.toJson` on success or the REPL error text on
    * failure.
    */
  def eval(expr: String): Either[String, String] =
      synchronized {
          ReplSink.take() // clear any stale value
          run(s"_root_.io.appthreat.chennai.engine.ReplSink.set({ ${normalise(expr)} })")
              .flatMap(_ => ReplSink.take().toRight(printed("expression did not produce a result")))
      }

  /** Semantic completions for `line` at character offset `cursor`, using the compiler's completion
    * engine (the same source chen 2.x's Tab completion used). Returns distinct member labels, or
    * the reason the REPL could not start.
    */
  def complete(line: String, cursor: Int): Either[String, List[String]] =
      synchronized {
          driver.map { d =>
            val at = cursor.max(0).min(line.length)
            Guarded(d.completionsAt(at, line, state)).getOrElse(Nil)
                .map(_.label)
                // Keep public identifier members; drop operators (`!=`, `##`) and internal/
                // synthetic names beginning with `_` (`_argumentIn`, …).
                .filter(l => l.nonEmpty && l.head.isLetter)
                .distinct
                .sorted
          }
      }

  /** Strip any trailing render/collection terminal so the remaining expression yields an
    * `Iterator[Path]`/`Traversal[Path]`, then materialise it as a `List[Path]`.
    */
  private[engine] def normaliseFlows(expr: String): String =
    var e       = expr.trim
    var changed = true
    while changed do
      changed = false
      (terminals :+ ".t").find(t => e.endsWith(t)).foreach { t =>
        e = e.dropRight(t.length).trim
        changed = true
      }
    s"($e).toList"

  /** Evaluate a data-flow expression and capture the resulting paths out-of-band. */
  def evalFlows(expr: String): Either[String, List[Path]] =
      synchronized {
          FlowSink.take() // clear any stale value
          run(s"_root_.io.appthreat.chennai.engine.FlowSink.set({ ${normaliseFlows(expr)} })")
              .flatMap(_ =>
                  FlowSink.take().toRight(printed("expression did not produce any flows"))
              )
      }
end ReplBridge

/** Subclass that exposes `ReplDriver.completions` (protected upstream) so the engine can offer
  * compiler-driven autocomplete to the TUI.
  */
final class ChennaiReplDriver(
  settings: Array[String],
  out: PrintStream,
  classLoader: Option[ClassLoader],
  extraPredef: String
) extends ReplDriver(settings, out, classLoader, extraPredef):
  def completionsAt(cursor: Int, line: String, state: State): List[Completion] =
      completions(cursor, line, state)
