package io.appthreat.chennai.engine.handlers

import io.appthreat.chennai.engine.ReplBridge
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.dataflowengineoss.language.Path
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.circe.Json
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.util.Try

/** Computes data-flows (`.reachableByFlows` / `.df` / the `reachables` preset) and shapes each
  * `Path` into a structured `FlowSet` the TUI renders as a master/detail flow view.
  *
  * Unlike [[QueryHandler]] (flat tables), flows are inherently hierarchical: a list of flows, each
  * an ordered list of steps. Steps are classified (source / propagation / sanitizer / external /
  * sink) and tainted symbols / tags surfaced so the TUI can highlight without re-deriving anything.
  *
  * The actual reachability is evaluated through the REPL bridge (so arbitrary chen DSL works), but
  * the resulting `List[Path]` is captured out-of-band and formatted here in plain Scala — no
  * `EngineContext` is needed once the paths exist.
  */
object FlowHandler:

  /** Method/tag substrings that mark a step as a validation/sanitisation mitigation. Ported from
    * chen 2.x `Path.isCheckLike` + the chenpy check-label list.
    */
  private val checkLabels = List(
    "valid",
    "check",
    "sanit",
    "escape",
    "clean",
    "safe",
    "serialize",
    "convert",
    "authenti",
    "authori",
    "encode",
    "encrypt",
    "decrypt",
    "transform"
  )

  private def isCheckLike(s: String): Boolean =
    val l = s.toLowerCase
    checkLabels.exists(l.contains)

  private def tagsOf(node: AstNode): List[String] =
      Try(node.tag.name.l).getOrElse(Nil).distinct

  private def fileOf(node: AstNode): String =
      Try(node.file.name.headOption.getOrElse("")).getOrElse("").replace("<unknown>", "")

  private def methodOf(node: AstNode): String = node match
    case m: Method            => m.name
    case m: MethodParameterIn => Try(m.method.name).getOrElse("")
    case m: Return            => Try(m.method.name).getOrElse("")
    case m: CfgNode           => Try(m.method.name).getOrElse("")
    case _ => Try(node.inAst.isMethod.name.headOption.getOrElse("")).getOrElse("")

  /** Best-effort "the symbol being tracked" for a node, used for highlighting + fingerprints. */
  private def symbolOf(node: AstNode): String = node match
    case m: MethodParameterIn => m.name
    case i: Identifier        => i.name
    case c: Call              => c.name
    case r: Return            => r.argumentName.getOrElse(r.code)
    case _                    => node.code

  /** A short, human label for the node kind (its generated class simple name). */
  private def labelOf(node: AstNode): String = node.getClass.getSimpleName

  private def isExternalCall(node: AstNode): Boolean = node match
    case c: Call =>
        !c.name.startsWith("<operator") && !c.methodFullName.startsWith("<operator") &&
        Try(c.callee(using NoResolve).headOption.exists(_.isExternal)).getOrElse(false)
    case m: MethodParameterIn => Try(m.method.isExternal).getOrElse(false)
    case _                    => false

  /** The code shown for a step. Method parameters render as `name(params)`. */
  private def codeOf(node: AstNode): String = node match
    case m: MethodParameterIn =>
        val params = Try(m.method.parameter.l.sortBy(_.index).map(_.code).mkString(", "))
            .getOrElse("")
        s"${Try(m.method.name).getOrElse("")}($params)"
    case _ => node.code

  private final case class Step(
    kind: String,
    label: String,
    code: String,
    method: String,
    file: String,
    line: Int,
    symbol: String,
    tags: List[String]
  ):
    def stepJson: Json = Json.obj(
      "kind"   -> Json.fromString(kind),
      "label"  -> Json.fromString(label),
      "code"   -> Json.fromString(code),
      "method" -> Json.fromString(method),
      "file"   -> Json.fromString(file),
      "line"   -> Json.fromInt(line),
      "symbol" -> Json.fromString(symbol),
      "tags"   -> Json.arr(tags.map(Json.fromString)*)
    )

    /** Per-step identity used for whole-flow dedup + sub-flow detection. */
    def fingerprint: String = s"$method|$symbol|$line"
  end Step

  private def buildSteps(path: Path): List[Step] =
    val elems = path.elements
    val n     = elems.size
    elems.zipWithIndex.flatMap { case (node, idx) =>
        node match
          case _: MethodReturn => None // mirrors chen 2.x: method returns are noise in flows
          case _ =>
              val tags    = tagsOf(node)
              val method  = methodOf(node)
              val checkly = isCheckLike(method) || tags.exists(isCheckLike)
              val kind =
                  if idx == 0 then "source"
                  else if idx == n - 1 then "sink"
                  else if checkly then "sanitizer"
                  else if isExternalCall(node) then "external"
                  else "propagation"
              Some(Step(
                kind = kind,
                label = labelOf(node),
                code = codeOf(node),
                method = method,
                file = fileOf(node),
                line = node.lineNumber.map(_.toInt).getOrElse(0),
                symbol = symbolOf(node),
                tags = tags
              ))
    }
  end buildSteps

  private final case class Flow(steps: List[Step], srcTags: List[String], sinkTags: List[String]):
    val sourceLabel: String = steps.headOption.map(_.code).getOrElse("")
    val sinkLabel: String   = steps.lastOption.map(_.code).getOrElse("")
    val mitigated: Boolean  = steps.exists(_.kind == "sanitizer")
    // A flow is "reachable" (library-attributable) when any step carries a package-url tag.
    val hasPurl: Boolean    = steps.exists(_.tags.exists(_.startsWith("pkg:")))
    val fingerprint: String = steps.map(_.fingerprint).mkString(">")
    def flowJson(id: Int, subFlowOf: Option[Int]): Json = Json.obj(
      "id"         -> Json.fromInt(id),
      "source"     -> Json.fromString(sourceLabel),
      "sink"       -> Json.fromString(sinkLabel),
      "sourceTags" -> Json.arr(srcTags.map(Json.fromString)*),
      "sinkTags"   -> Json.arr(sinkTags.map(Json.fromString)*),
      "mitigated"  -> Json.fromBoolean(mitigated),
      "hasPurl"    -> Json.fromBoolean(hasPurl),
      "length"     -> Json.fromInt(steps.size),
      "subFlowOf"  -> subFlowOf.map(Json.fromInt).getOrElse(Json.Null),
      "steps"      -> Json.arr(steps.map(_.stepJson)*)
    )

  /** Shape raw paths into a deduped, sub-flow-annotated `FlowSet` JSON object.
    *
    * When `purlOnly` is set (the `reachables` view), only flows with a package-url-tagged step are
    * kept — i.e. flows attributable to a known library/dependency.
    *
    * @param passesThrough
    *   optional substring — only keep flows whose steps include a matching method name, code
    *   snippet or file path (case-insensitive).
    * @param doesNotPassThrough
    *   optional substring — exclude flows whose steps include a match.
    */
  private def toFlowSet(
    title: String,
    paths: List[Path],
    offset: Int,
    limit: Int,
    purlOnly: Boolean,
    capped: Boolean = false,
    passesThrough: Option[String] = None,
    doesNotPassThrough: Option[String] = None
  ): Json =
    // Build flows, dropping ones with too few visible steps to be interesting.
    val built = paths.map { p =>
      val steps = buildSteps(p)
      Flow(
        steps,
        steps.headOption.map(_.tags).getOrElse(Nil),
        steps.lastOption.map(_.tags).getOrElse(Nil)
      )
    }.filter(f => f.steps.sizeIs >= 2 && (!purlOnly || f.hasPurl))

    // Exact-duplicate dedup by fingerprint.
    val deduped =
        built.foldLeft((Vector.empty[Flow], Set.empty[String])) { case ((acc, seen), f) =>
            if seen.contains(f.fingerprint) then (acc, seen)
            else (acc :+ f, seen + f.fingerprint)
        }._1

    // Apply passesThrough / doesNotPassThrough filters.
    val stepMatches = (s: Step, pattern: String) =>
        s.method.toLowerCase.contains(pattern.toLowerCase) ||
            s.code.toLowerCase.contains(pattern.toLowerCase) ||
            s.file.toLowerCase.contains(pattern.toLowerCase)
    val filtered = deduped.filter { f =>
        passesThrough.forall(pt => f.steps.exists(stepMatches(_, pt)))
    }.filter { f =>
        doesNotPassThrough.forall(dnpt => !f.steps.exists(stepMatches(_, dnpt)))
    }

    // Sub-flow detection: a flow whose fingerprint is contained within a strictly longer flow's
    // fingerprint is a sub-path of it. Point it at the longest such super-flow.
    val withIds = filtered.zipWithIndex
    val subOf: Map[Int, Int] = withIds.flatMap { case (f, i) =>
        val supers = withIds.filter { case (g, j) =>
            j != i && g.steps.size > f.steps.size && g.fingerprint.contains(f.fingerprint)
        }
        supers.sortBy(-_._1.steps.size).headOption.map { case (_, j) => i -> j }
    }.toMap

    val total = filtered.size
    val off   = offset.max(0)
    val lim   = limit.max(0)
    val window =
        withIds.slice(off, off + lim).map { case (f, i) =>
            f.flowJson(i, subOf.get(i))
        }
    // A further page exists when the window stops short of the (post-filter) total.
    val nextOffset = if off + window.size < total then Some(off + window.size) else None

    Json.obj(
      "title"  -> Json.fromString(title),
      "total"  -> Json.fromInt(total),
      "shown"  -> Json.fromInt(window.size),
      "offset" -> Json.fromInt(off),
      "limit"  -> Json.fromInt(lim),
      // `capped` => path enumeration stopped at the `take` budget, so `total` is a lower bound
      // and there are likely more flows than reported. Re-run with a larger `take` to widen.
      "capped" -> Json.fromBoolean(capped),
      // Convenience pointer for paginating: pass this as `offset` to fetch the next page.
      "nextOffset" -> nextOffset.map(Json.fromInt).getOrElse(Json.Null),
      "flows"      -> Json.arr(window*)
    )
  end toFlowSet

  // Default source/sink tag sets, mirrored from io.appthreat.atom Atom.DEFAULT_SOURCE_TAGS /
  // DEFAULT_SINK_TAGS so the `reachables` preset reproduces atom's reachable-slice queries.
  private val DefaultSourceTags = Seq(
    "framework-input",
    "framework-route",
    "cli-source",
    "driver-source",
    "framework",
    "event",
    "sensitive-data",
    "pii",
    "service-ingress"
  )

  private val DefaultSinkTags = Seq(
    "framework-output",
    "library-call",
    "cloud",
    "rpc",
    "http",
    "http-client",
    "network",
    "file-io",
    "sql",
    "code-execution",
    "reflection",
    "concurrent",
    "serialization",
    "unsafe-deserialization",
    "regex",
    "cron",
    "mail",
    "framework",
    "api",
    "pkg.*",
    "service-egress",
    "on-device-ai",
    "tracker",
    "adware"
  )

  // High-value source/sink tags surfaced FIRST, so an agent paging through a bounded result sees
  // the flows most likely to be exploitable (untrusted framework input reaching an injection,
  // command-execution, file-io, or deserialization sink) before the long tail of library flows.
  private val PrioritySourceTags = Seq("framework-input", "framework-route", "cli-source")
  private val PrioritySinkTags = Seq(
    "sql",
    "code-execution",
    "unsafe-deserialization",
    "serialization",
    "file-io",
    "reflection"
  )

  private def tagRegex(tags: Seq[String]): String = tags.mkString("(", "|", ")")

  private val DynamicLangs = Set("PYTHON", "PYTHONSRC", "JAVASCRIPT", "JSSRC", "RUBYSRC")

  /** Default upper bound on the number of source-to-sink paths enumerated for a preset, before any
    * windowing. This is the lever that keeps `dataflows`/`reachables` responsive on large
    * codebases: path enumeration short-circuits once this many paths have been produced, rather
    * than walking the entire (potentially unbounded) flow space. Callers override via `take`.
    */
  val DefaultTake = 100

  /** Compute the `reachables` flows directly (type-checked Scala), mirroring the basic +
    * dynamic-language + default-tag flow collectors in io.appthreat.atom `ReachableSlicing`.
    *
    * Flows are emitted as a lazy iterator and capped at `take` paths by the caller, so enumeration
    * stops early on large atoms. Higher-value flows (priority source → priority sink) are produced
    * first so they survive both the `take` cap and the later fingerprint dedup.
    *
    * @param srcTags
    *   source tag names to scope flow origins to (defaults to [[DefaultSourceTags]]).
    * @param sinkTags
    *   sink tag names to scope flow destinations to (defaults to [[DefaultSinkTags]]).
    */
  private def reachableIterator(
    cpg: Cpg,
    srcTags: Seq[String],
    sinkTags: Seq[String]
  ): Iterator[Path] =
    given EngineContext = EngineContext()
    val lang   = Try(cpg.metaData.language.headOption.getOrElse("")).getOrElse("").toUpperCase
    val srcRe  = tagRegex(srcTags)
    val sinkRe = tagRegex(sinkTags)

    // `def` (not `val`): each traversal is re-evaluated per use so the iterators are not exhausted.
    def sP                                                  = cpg.tag.name(srcRe).parameter
    def sI                                                  = cpg.tag.name(srcRe).identifier
    def sC                                                  = cpg.tag.name(srcRe).call
    def basicFrom(sinks: Iterator[CfgNode]): Iterator[Path] = sinks.reachableByFlows(sP, sI, sC)

    // Priority flows: untrusted framework/CLI input reaching a high-value sink. Restricted to the
    // intersection of the requested tags and the priority sets so a scoped query stays scoped.
    val prioSrc = tagRegex(srcTags.filter(PrioritySourceTags.contains))
    val priority =
        if srcTags.exists(PrioritySourceTags.contains) &&
          sinkTags.exists(PrioritySinkTags.contains)
        then
          val prioSinkRe = tagRegex(sinkTags.filter(PrioritySinkTags.contains))
          def pSrcP      = cpg.tag.name(prioSrc).parameter
          def pSrcI      = cpg.tag.name(prioSrc).identifier
          def pSrcC      = cpg.tag.name(prioSrc).call
          Iterator(
            cpg.tag.name(prioSinkRe).call.reachableByFlows(pSrcP, pSrcI, pSrcC),
            cpg.tag.name(prioSinkRe).call.argument.isIdentifier.reachableByFlows(
              pSrcP,
              pSrcI,
              pSrcC
            )
          ).flatten
        else Iterator.empty[Path]

    val basic = Iterator(
      basicFrom(cpg.tag.name(sinkRe).call),
      basicFrom(cpg.tag.name(sinkRe).identifier),
      basicFrom(cpg.tag.name(sinkRe).call.argument.isIdentifier),
      basicFrom(cpg.tag.name(sinkRe).parameter),
      basicFrom(cpg.ret.where(_.tag.name(sinkRe)))
    ).flatten

    // Default-tag flows: returns of tagged methods, and API parameter→identifier flows.
    val defaultTag = Iterator(
      cpg.ret.where(_.method.tag.name(srcRe)).reachableByFlows(sP, sI, sC),
      cpg.tag.name("api").parameter
          .reachableByFlows(cpg.tag.name("api").parameter, cpg.tag.name("api").identifier)
    ).flatten

    // Dynamic-language (Python/JS/Ruby) flows over call arguments + method call-ins.
    val dynamic =
        if DynamicLangs.contains(lang) then
          def dynCallSource     = cpg.tag.name(srcRe).call.argument.isIdentifier
          def dynCallAllArg     = cpg.tag.name(srcRe).call.argument
          def dynFrameworkParam = cpg.tag.name("(framework|framework-input)").parameter
          Iterator(
            cpg.tag.name(sinkRe).call.argument.isIdentifier
                .reachableByFlows(dynCallSource, dynFrameworkParam),
            cpg.tag.name(sinkRe).method.callIn(using NoResolve).reachableByFlows(dynCallAllArg)
          ).flatten
        else Iterator.empty[Path]

    priority ++ basic ++ defaultTag ++ dynamic
  end reachableIterator

  /** Materialise up to `take` reachable paths (priority flows first). */
  private def computeReachables(
    cpg: Cpg,
    take: Int,
    srcTags: Seq[String] = DefaultSourceTags,
    sinkTags: Seq[String] = DefaultSinkTags
  ): List[Path] =
      reachableIterator(cpg, srcTags, sinkTags).take(take.max(0)).toList

  /** Compute the `cryptos` flows (crypto-algorithm → crypto-generate), language-aware. */
  private def computeCryptos(cpg: Cpg, take: Int): List[Path] =
    given EngineContext = EngineContext()
    val lang = Try(cpg.metaData.language.headOption.getOrElse("")).getOrElse("").toUpperCase
    val it =
        if DynamicLangs.contains(lang) then
          cpg.tag.name("crypto-generate").call
              .reachableByFlows(cpg.tag.name("crypto-algorithm").call)
        else
          cpg.tag.name("crypto-generate").call
              .reachableByFlows(cpg.tag.name("crypto-algorithm").literal)
    it.take(take.max(0)).toList

  /** Entry point: compute and shape flows for the open atom.
    *
    *   - `preset: dataflows` (default) → all computed flows, titled "Data flows".
    *   - `preset: reachables` → only flows attributable to a package (purl-tagged step), titled
    *     "Reachable flows".
    *   - `preset: cryptos` → crypto flows.
    *   - `expr` → arbitrary chen dataflow DSL, evaluated via the REPL bridge.
    *   - `source` + `sink` → `(sink).reachableByFlows(source)`, via the REPL bridge.
    *   - `passesThrough` / `doesNotPassThrough` → filter result by step method/code/file substring
    *     matching (case-insensitive). These are applied to every output path.
    *
    * Slicing / pagination args (all optional):
    *   - `take` → cap on the number of paths enumerated for a preset (default [[DefaultTake]]); the
    *     responsiveness lever on large atoms. The result is flagged `capped` when this is hit.
    *   - `offset` / `limit` → window into the computed flows (default offset 0, limit 50). Use
    *     `nextOffset` from the response to page forward without recomputing.
    *   - `sourceTags` / `sinkTags` → override the default source/sink tag sets for the `dataflows`
    *     and `reachables` presets. Accept a JSON array or a `|`/`,`-delimited string.
    */
  /** Parse a tag list argument, accepting either a JSON array of strings (`["sql","exec"]`) or a
    * single pipe/comma-delimited string (`"sql|exec"`). Returns `None` when absent or empty so the
    * caller falls back to its default tag set.
    */
  private def tagListArg(args: io.circe.HCursor, key: String): Option[Seq[String]] =
      args.get[List[String]](key).toOption
          .orElse(
            args.get[String](key).toOption
                .map(_.split("[|,]").iterator.map(_.trim).filter(_.nonEmpty).toList)
          )
          .map(_.filter(_.nonEmpty))
          .filter(_.nonEmpty)

  def flows(cpg: Cpg, bridge: ReplBridge, args: io.circe.HCursor): Either[String, Json] =
    val offset = args.get[Int]("offset").getOrElse(0)
    val limit  = args.get[Int]("limit").getOrElse(50)
    // `take` caps how many paths are *enumerated* (the cost lever on large atoms); `limit`/`offset`
    // window the already-computed result for pagination. They are independent: page through a large
    // `take` budget with successive `offset`s without recomputing.
    val take          = args.get[Int]("take").getOrElse(DefaultTake)
    val srcTags       = tagListArg(args, "sourceTags").getOrElse(DefaultSourceTags)
    val sinkTags      = tagListArg(args, "sinkTags").getOrElse(DefaultSinkTags)
    val expr          = args.get[String]("expr").toOption.map(_.trim).filter(_.nonEmpty)
    val preset        = args.get[String]("preset").toOption.map(_.trim).filter(_.nonEmpty)
    val source        = args.get[String]("source").toOption.map(_.trim).filter(_.nonEmpty)
    val sink          = args.get[String]("sink").toOption.map(_.trim).filter(_.nonEmpty)
    val passesThrough = args.get[String]("passesThrough").toOption.map(_.trim).filter(_.nonEmpty)
    val doesNotPassThrough =
        args.get[String]("doesNotPassThrough").toOption.map(_.trim).filter(_.nonEmpty)

    // A preset enumeration is "capped" when it produced exactly `take` paths — there may be more.
    def shaped(title: String, paths: List[Path], purlOnly: Boolean, fromPreset: Boolean) =
        toFlowSet(
          title,
          paths,
          offset,
          limit,
          purlOnly,
          capped = fromPreset && take > 0 && paths.sizeIs >= take,
          passesThrough,
          doesNotPassThrough
        )

    (expr, preset, source, sink) match
      case (Some(e), _, _, _) =>
          bridge.evalFlows(e).map(p =>
              shaped("Data flows", p, purlOnly = false, fromPreset = false)
          )
      case (_, Some("cryptos"), _, _) =>
          Try(computeCryptos(cpg, take)).toEither.left.map(_.getMessage)
              .map(p => shaped("Crypto flows", p, purlOnly = false, fromPreset = true))
      case (_, Some("reachables"), _, _) =>
          Try(computeReachables(cpg, take, srcTags, sinkTags)).toEither.left.map(_.getMessage)
              .map(p => shaped("Reachable flows", p, purlOnly = true, fromPreset = true))
      case (_, Some("dataflows"), _, _) | (_, None, None, None) =>
          Try(computeReachables(cpg, take, srcTags, sinkTags)).toEither.left.map(_.getMessage)
              .map(p => shaped("Data flows", p, purlOnly = false, fromPreset = true))
      case (_, _, Some(s), Some(k)) =>
          bridge.evalFlows(s"($k).reachableByFlows($s)")
              .map(p => shaped("Data flows", p, purlOnly = false, fromPreset = false))
      case _ =>
          Left("flows requires 'expr', 'preset', or both 'source' and 'sink'")
  end flows
end FlowHandler
