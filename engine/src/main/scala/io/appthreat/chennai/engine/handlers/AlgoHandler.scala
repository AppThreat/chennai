package io.appthreat.chennai.engine.handlers

import io.appthreat.dataflowengineoss.language.*
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.circe.{HCursor, Json}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.{ICallResolver, NoResolve, *}

import overflowdb.Node
import overflowdb.algorithm.{
    DominatorTree,
    PageRank,
    PathFinder,
    StronglyConnectedComponents,
    TopologicalSort
}

import scala.util.Try
import scala.jdk.CollectionConverters.*
import scala.collection.immutable.Map as ImmutableMap

/** Exposes overflowdb2 graph algorithms as engine commands so the agent can do structural reasoning
  * over the call graph — ranking hot methods, finding cyclic dependencies, ordering topologically,
  * checking dominator relationships, and finding shortest paths.
  *
  * Each algorithm returns a compact JSON table (same shape as [[QueryHandler]]) so the TUI and the
  * agent loop can consume it uniformly.
  */
object AlgoHandler:

  private val DefaultLimit = 50

  // ---------------------------------------------------------------------------
  // Public entry point
  // ---------------------------------------------------------------------------

  def algo(cpg: Cpg, args: HCursor): Either[String, Json] =
    val name = args.get[String]("name").toOption.map(_.trim).filter(_.nonEmpty)
    name match
      case Some("pagerank")      => computePageRank(cpg, args)
      case Some("scc")           => computeScc(cpg, args)
      case Some("toposort")      => computeTopoSort(cpg, args)
      case Some("dominators")    => computeDominators(cpg, args)
      case Some("shortest-path") => computeShortestPath(cpg, args)
      case Some("reachable-by")  => computeReachableBy(cpg, args)
      case Some(other)           => Left(s"unknown algorithm: $other")
      case None                  => Left("algo requires a 'name' argument")

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /** The set of methods in the atom, optionally filtered by `scope` ("external" / "internal"). */
  private def methodNodes(cpg: Cpg, scope: Option[String]): Iterator[Method] =
      scope match
        case Some("external") => cpg.method.external
        case Some("internal") => cpg.method.internal
        case _                => cpg.method

  given ICallResolver = NoResolve

  /** Successor function: for a Method node, return its callee Method nodes (the methods it calls).
    */
  private val calleeSuccessor: java.util.function.Function[Node, java.util.Iterator[Node]] =
      (m: Node) =>
          m match
            case method: Method =>
                method.call.callee.map(_.asInstanceOf[Node]).iterator.asJava
            case _ => java.util.Collections.emptyIterator()

  /** Build a JSON column/rows table from algorithm output. */
  private def algoTable(title: String, columns: Seq[String], rows: Seq[Seq[Json]]): Json =
      Json.obj(
        "title"   -> Json.fromString(title),
        "columns" -> Json.arr(columns.map(Json.fromString)*),
        "rows"    -> Json.arr(rows.map(row => Json.arr(row*))*),
        "total"   -> Json.fromInt(rows.size),
        "offset"  -> Json.fromInt(0)
      )

  private def cell(v: String, kind: String = "text"): Json =
      Json.obj("v" -> Json.fromString(v), "k" -> Json.fromString(kind))

  private def cellNum(n: Long): Json =
      Json.obj("v" -> Json.fromString(n.toString), "k" -> Json.fromString("num"))

  private def cellNumD(d: Double): Json =
      Json.obj("v" -> Json.fromString(f"$d%.4f"), "k" -> Json.fromString("num"))

  // ---------------------------------------------------------------------------
  // PageRank — "what are the central / hottest methods?"
  // ---------------------------------------------------------------------------

  private def computePageRank(cpg: Cpg, args: HCursor): Either[String, Json] =
    val scope = args.get[String]("scope").toOption
    val limit = args.get[Int]("limit").getOrElse(DefaultLimit)
    val nodes = methodNodes(cpg, scope).toList
    if nodes.isEmpty then return Left("no methods found in the specified scope")

    val rawRanks: java.util.Map[java.lang.Long, java.lang.Double] =
        PageRank.compute(nodes.asJava, calleeSuccessor)
    val ranks: Iterable[(Long, Double)] =
        rawRanks.asScala.map { case (k, v) => (k.toLong, v.toDouble) }

    val sorted = ranks.toSeq.sortBy(-_._2).take(limit)
    val rows = sorted.map { case (id, score) =>
        val m = nodes.find(_.id() == id)
        Seq(
          cell(m.map(_.name).getOrElse(s"node#$id"), "name"),
          cell(m.map(_.fullName).getOrElse(""), "code"),
          cell(m.flatMap(n => Try(n.file.name.headOption).toOption.flatten).getOrElse(""), "path"),
          cellNumD(score)
        )
    }

    Right(algoTable(
      s"PageRank (top $limit)",
      Seq("Method", "Full Name", "File", "Score"),
      rows
    ))
  end computePageRank

  // ---------------------------------------------------------------------------
  // Strongly Connected Components — "recursive / cyclic call clusters"
  // ---------------------------------------------------------------------------

  private def computeScc(cpg: Cpg, args: HCursor): Either[String, Json] =
    val scope = args.get[String]("scope").toOption
    val nodes = methodNodes(cpg, scope).toList
    if nodes.isEmpty then return Left("no methods found in the specified scope")

    val components: List[java.util.Set[Node]] =
        StronglyConnectedComponents.compute(nodes.asJava, calleeSuccessor).asScala.toList

    val nonTrivial = components.filter(_.size >= 2).sortBy(-_.size)
    val rows = nonTrivial.flatMap { comp =>
      val members = comp.asScala.toSeq.sortBy {
          case m: Method => m.name
          case n         => n.id().toString
      }
      // First row: size header.
      val sizeRow = Seq(
        cell(s"--- SCC (${comp.size} methods) ---", "name"),
        cell("", "text"),
        cell("", "text"),
        cellNum(comp.size)
      )
      val memberRows = members.map {
          case m: Method =>
              Seq(
                cell(m.name, "name"),
                cell(m.fullName, "code"),
                cell(Try(m.file.name.headOption.getOrElse("")).getOrElse(""), "path"),
                cell("", "text")
              )
          case n =>
              Seq(
                cell(n.id().toString, "num"),
                cell("", "text"),
                cell("", "text"),
                cell("", "text")
              )
      }
      sizeRow +: memberRows
    }

    val total = components.count(_.size >= 2)
    Right(algoTable(
      s"Strongly Connected Components ($total cycles)",
      Seq("Method", "Full Name", "File", "Size"),
      rows
    ))
  end computeScc

  // ---------------------------------------------------------------------------
  // Topological Sort — "build ordering"
  // ---------------------------------------------------------------------------

  private def computeTopoSort(cpg: Cpg, args: HCursor): Either[String, Json] =
    val scope = args.get[String]("scope").toOption
    val limit = args.get[Int]("limit").getOrElse(DefaultLimit)
    val nodes = methodNodes(cpg, scope).toList
    if nodes.isEmpty then return Left("no methods found in the specified scope")

    Try {
        val sorted: java.util.List[Node] = TopologicalSort.sort(nodes.asJava, calleeSuccessor)
        val rows = sorted.asScala.take(limit).zipWithIndex.toSeq.map { case (m, idx) =>
            m match
              case method: Method =>
                  Seq(
                    cellNum((idx + 1).toLong),
                    cell(method.name, "name"),
                    cell(method.fullName, "code"),
                    cell(Try(method.file.name.headOption.getOrElse("")).getOrElse(""), "path")
                  )
              case n =>
                  Seq(
                    cellNum((idx + 1).toLong),
                    cell(n.id().toString, "num"),
                    cell("", "text"),
                    cell("", "text")
                  )
        }
        Right(algoTable(
          s"Topological Sort (showing ${rows.size} of ${sorted.size})",
          Seq("#", "Method", "Full Name", "File"),
          rows
        ))
    }.toEither.left.map { ex =>
        if ex.getMessage != null && ex.getMessage.contains("cycle") then
          "call graph contains a cycle; topological sort is not possible. Use the 'scc' algorithm to find cycles."
        else
          s"topological sort failed: ${ex.getMessage}"
    }.flatten
  end computeTopoSort

  // ---------------------------------------------------------------------------
  // Dominators — "must-pass-through gates"
  // ---------------------------------------------------------------------------

  private def computeDominators(cpg: Cpg, args: HCursor): Either[String, Json] =
    val scope = args.get[String]("scope").toOption
    val limit = args.get[Int]("limit").getOrElse(DefaultLimit)
    val nodes = methodNodes(cpg, scope).toList

    nodes.maxByOption(m => Try(m.callIn.size).getOrElse(0))
        .toRight("no methods found in the specified scope")
        .flatMap { root =>
          val rawDoms: java.util.Map[java.lang.Long, java.lang.Long] =
              DominatorTree.computeDominators(root, calleeSuccessor)
          val doms: Iterable[(Long, Long)] =
              rawDoms.asScala.map { case (k, v) => (k.toLong, v.toLong) }

          // Build a nice table of method → immediate dominator.
          val domList = doms.toSeq.filter((id, _) => nodes.exists(_.id() == id) || id == root.id())
              .sortBy { case (id, _) =>
                  nodes.find(_.id() == id).map(_.name).getOrElse("")
              }.take(limit)

          val rows = domList.map { case (id, domId) =>
              val method = nodes.find(_.id() == id)
              val dom    = nodes.find(_.id() == domId)
              Seq(
                cell(method.map(_.name).getOrElse(s"node#$id"), "name"),
                cell(dom.map(_.name).getOrElse("(root)"), "code"),
                cell(
                  if method.exists(_.id() == root.id()) then "(root — no dominator)" else "",
                  "text"
                )
              )
          }

          Right(algoTable(
            s"Dominator Tree (root: ${root.name})",
            Seq("Method", "Immediate Dominator", "Notes"),
            rows
          ))
        }
  end computeDominators

  // ---------------------------------------------------------------------------
  // Shortest Path — "is X reachable from Y, and how?"
  // ---------------------------------------------------------------------------

  private def computeShortestPath(cpg: Cpg, args: HCursor): Either[String, Json] =
    val from     = args.get[String]("from").toOption.map(_.trim).filter(_.nonEmpty)
    val to       = args.get[String]("to").toOption.map(_.trim).filter(_.nonEmpty)
    val maxDepth = args.get[Int]("maxDepth").getOrElse(20)

    (from, to) match
      case (Some(srcName), Some(snkName)) =>
          val srcNodes = cpg.method.fullName(srcName).l
          val snkNodes = cpg.method.fullName(snkName).l

          if srcNodes.isEmpty then return Left(s"source method not found: $srcName")
          if snkNodes.isEmpty then return Left(s"sink method not found: $snkName")

          val paths = PathFinder(srcNodes.head, snkNodes.head, maxDepth)
          if paths.isEmpty then
            Right(algoTable(
              s"Shortest Path: $srcName → $snkName",
              Seq("#", "Method"),
              Seq(Seq(cell("no path found within max depth", "text"), cell("", "text")))
            ))
          else
            val shortest = paths.head
            val rows = shortest.nodes.zipWithIndex.map { case (node, idx) =>
                node match
                  case m: Method =>
                      Seq(
                        cellNum((idx + 1).toLong),
                        cell(m.name, "name"),
                        cell(m.fullName, "code"),
                        cell(Try(m.file.name.headOption.getOrElse("")).getOrElse(""), "path")
                      )
                  case n =>
                      Seq(
                        cellNum((idx + 1).toLong),
                        cell(n.id().toString, "num"),
                        cell("", "text"),
                        cell("", "text")
                      )
            }
            Right(algoTable(
              s"Shortest Path: $srcName → $snkName (${shortest.nodes.size} steps)",
              Seq("#", "Method", "Full Name", "File"),
              rows
            ))
          end if
      case _ => Left("shortest-path requires 'from' and 'to' method full names")
    end match
  end computeShortestPath

  // ---------------------------------------------------------------------------
  // Reachable-by (alias: tag-based reachability via dataflowengineoss)
  // ---------------------------------------------------------------------------

  private def computeReachableBy(cpg: Cpg, args: HCursor): Either[String, Json] =
    val sourceTag = args.get[String]("sourceTag").toOption
    val sinkTag   = args.get[String]("sinkTag").toOption
    val limit     = args.get[Int]("limit").getOrElse(DefaultLimit)

    given EngineContext = EngineContext()

    val (sources, sinks) = (sourceTag, sinkTag) match
      case (Some(src), Some(snk)) =>
          (
            cpg.tag.name(src).parameter ++ cpg.tag.name(src).identifier ++ cpg.tag.name(src).call,
            cpg.tag.name(snk).call ++ cpg.tag.name(snk).identifier ++ cpg.tag.name(snk).parameter
          )
      case (Some(src), None) =>
          (
            cpg.tag.name(src).parameter ++ cpg.tag.name(src).identifier ++ cpg.tag.name(src).call,
            cpg.call.where(_.tag.name(".*")).iterator
          )
      case (None, Some(snk)) =>
          (
            cpg.parameter ++ cpg.identifier ++ cpg.call.where(_.tag.name(".*")).iterator,
            cpg.tag.name(snk).call ++ cpg.tag.name(snk).identifier
          )
      case (None, None) =>
          return Left("reachable-by requires at least one of 'sourceTag' or 'sinkTag'")

    val allSources = sources.l
    val allSinks   = sinks.l

    if allSources.isEmpty then
      return Left(s"no source nodes found for tag: ${sourceTag.getOrElse("(any)")}")
    if allSinks.isEmpty then
      return Left(s"no sink nodes found for tag: ${sinkTag.getOrElse("(any)")}")

    val paths = allSinks.reachableByFlows(allSources).toList.take(limit)

    if paths.isEmpty then
      Right(algoTable(
        s"Reachable-by: ${sourceTag.getOrElse("*")} → ${sinkTag.getOrElse("*")}",
        Seq("Source", "Sink", "Steps"),
        Seq(Seq(cell("no paths found", "text"), cell("", "text"), cell("", "text")))
      ))
    else
      val rows = paths.map { path =>
        val elems    = path.elements
        val srcLabel = elems.headOption.map(_.code).getOrElse("")
        val snkLabel = elems.lastOption.map(_.code).getOrElse("")
        Seq(
          cell(srcLabel, "code"),
          cell(snkLabel, "code"),
          cellNum(elems.size.toLong)
        )
      }
      Right(algoTable(
        s"Reachable-by: ${sourceTag.getOrElse("*")} → ${sinkTag.getOrElse("*")} (${paths.size} paths)",
        Seq("Source", "Sink", "Steps"),
        rows
      ))
    end if
  end computeReachableBy

end AlgoHandler
