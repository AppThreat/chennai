package io.appthreat.chennai.engine.handlers

import io.circe.Json
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

import java.nio.file.{Files, Path, Paths}
import scala.io.Source
import scala.util.Try

object DetailHandler:

  private given NodeExtensionFinder = DefaultNodeExtensionFinder

  private object Kind:
    val Text = "text"
    val Code = "code"
    val Name = "name"
    val Path = "path"
    val Num  = "num"

  private def cell(v: String, k: String): Json =
      Json.obj("v" -> Json.fromString(v), "k" -> Json.fromString(k))

  private def prop(label: String, value: String): Json =
      Json.obj("label" -> Json.fromString(label), "value" -> Json.fromString(value))

  private def lineStr(line: Option[Integer]): String = line.map(_.toString).getOrElse("")

  /** Resolve a (possibly relative) CPG filename to an absolute path that exists on disk. When
    * `sourceRoot` is provided it is tried first; otherwise candidates are derived from the atom
    * path (atom dir, parent, grandparent — covers the common `reports/app.atom` layout).
    */
  private def resolveFile(
    filename: String,
    atomPath: String,
    sourceRoot: Option[String]
  ): Option[Path] =
      if filename.isEmpty then None
      else
        val p = Paths.get(filename)
        if p.isAbsolute && Files.isRegularFile(p) then return Some(p)
        val atomDir = Paths.get(atomPath).toAbsolutePath.getParent
        val roots = sourceRoot.map(Paths.get(_).toAbsolutePath).toSeq ++ Seq(
          atomDir,
          Option(atomDir.getParent).orNull,
          Option(atomDir.getParent).flatMap(q => Option(q.getParent)).orNull
        ).filter(_ != null)
        roots.map(_.resolve(filename)).find(Files.isRegularFile(_))

  /** Read lines [from, to] (1-based, inclusive) from a resolved file path. */
  private def readSourceLines(
    filename: String,
    atomPath: String,
    from: Int,
    to: Int,
    sourceRoot: Option[String] = None
  ): Option[String] =
      if from <= 0 || to < from then None
      else
        resolveFile(filename, atomPath, sourceRoot).flatMap { path =>
            Try {
                val src = Source.fromFile(path.toFile)
                val lines =
                    try src.getLines().toVector
                    finally src.close()
                val start = (from - 1).max(0)
                val end   = to.min(lines.length)
                if start >= lines.length then None
                else Some(lines.slice(start, end).mkString("\n"))
            }.toOption.flatten
        }

  def detail(
    cpg: Cpg,
    kind: String,
    key: String,
    file: Option[String],
    line: Option[Int],
    atomPath: String,
    sourceRoot: Option[String] = None
  ): Json =
      kind match
        case "files" =>
            val f = cpg.file.whereNot(_.name("<unknown>")).name(key).headOption
            f match
              case None => errorDetail(s"file not found: $key")
              case Some(file) =>
                  val methods = file.method.l
                  val props = Json.arr(
                    prop("File", file.name),
                    prop("Methods", methods.size.toString),
                    prop("Namespaces", Try(file.namespaceBlock.size.toString).getOrElse("0"))
                  )
                  val childRows = methods.take(500).map { m =>
                      Json.arr(
                        cell(m.name, Kind.Name),
                        cell(m.fullName, Kind.Code),
                        cell(lineStr(m.lineNumber), Kind.Num),
                        cell(Try(m.body.astChildren.size.toString).getOrElse(""), Kind.Num)
                      )
                  }
                  Json.obj(
                    "props"      -> props,
                    "childTitle" -> Json.fromString("Methods"),
                    "childColumns" -> Json.arr(
                      Json.fromString("Name"),
                      Json.fromString("Full Name"),
                      Json.fromString("Line"),
                      Json.fromString("Nodes")
                    ),
                    "childRows" -> Json.arr(childRows*),
                    "code"      -> Json.Null
                  )
            end match

        case "methods" | "externalMethods" | "internalMethods" =>
            val m = cpg.method.fullNameExact(key).headOption
            m match
              case None => errorDetail(s"method not found: $key")
              case Some(method) =>
                  val lineStart = method.lineNumber.map(_.toInt).getOrElse(0)
                  val lineEnd   = method.lineNumberEnd.map(_.toInt).getOrElse(lineStart)
                  val props = Json.arr(
                    prop("Name", method.name),
                    prop("Full Name", method.fullName),
                    prop("File", method.filename),
                    prop("Line", if lineStart > 0 then s"$lineStart–$lineEnd" else ""),
                    prop("Signature", method.signature)
                  )
                  val callTree = buildCallTree(cpg, method.fullName, maxDepth = 5, maxNodes = 300)
                  val code =
                      readSourceLines(method.filename, atomPath, lineStart, lineEnd, sourceRoot)
                  Json.obj(
                    "props"        -> props,
                    "childTitle"   -> Json.fromString("Calls"),
                    "childColumns" -> Json.arr(),
                    "childRows"    -> Json.arr(),
                    "callTree"     -> Json.arr(callTree*),
                    "code"         -> code.fold(Json.Null)(Json.fromString)
                  )
            end match

        case "calls" =>
            // Find call by name + file + line
            val c = line match
              case Some(ln) =>
                  file match
                    case Some(fn) =>
                        cpg.call.name(key).where(_.file.name(fn)).lineNumber(ln).headOption
                    case None => cpg.call.name(key).lineNumber(ln).headOption
              case None => cpg.call.name(key).headOption
            c match
              case None => errorDetail(s"call not found: $key")
              case Some(call) =>
                  val props = Json.arr(
                    prop("Name", call.name),
                    prop("Code", call.code),
                    prop("File", Try(call.file.name.headOption.getOrElse("")).getOrElse("")),
                    prop("Line", lineStr(call.lineNumber)),
                    prop("Dispatch", call.dispatchType)
                  )
                  val args = call.argument.l
                  val childRows = args.take(200).map { a =>
                      Json.arr(
                        cell(a.code, Kind.Code),
                        cell(a.order.toString, Kind.Num)
                      )
                  }
                  val callFile = Try(call.file.name.headOption.getOrElse("")).getOrElse("")
                  val callLine = call.lineNumber.map(_.toInt).getOrElse(0)
                  val code = readSourceLines(
                    callFile,
                    atomPath,
                    (callLine - 4).max(1),
                    callLine + 4,
                    sourceRoot
                  )
                  Json.obj(
                    "props"        -> props,
                    "childTitle"   -> Json.fromString("Arguments"),
                    "childColumns" -> Json.arr(Json.fromString("Code"), Json.fromString("Order")),
                    "childRows"    -> Json.arr(childRows*),
                    "code"         -> code.fold(Json.Null)(Json.fromString)
                  )
            end match

        case other =>
            errorDetail(s"detail not supported for kind: $other")

  /** Build a callee tree for `rootFullName` up to `maxDepth` levels, capped at `maxNodes` nodes.
    * Returns a flat list of `{label, depth, file, line}` objects for the TUI to render as a tree.
    * Cycle detection is done via a per-branch visited set.
    */
  private def buildCallTree(
    cpg: Cpg,
    rootFullName: String,
    maxDepth: Int,
    maxNodes: Int
  ): Seq[Json] =
    val result    = scala.collection.mutable.ArrayBuffer.empty[Json]
    val totalSeen = new java.util.concurrent.atomic.AtomicInteger(0)

    def treeNode(label: String, depth: Int, file: String, line: String): Json =
        Json.obj(
          "label" -> Json.fromString(label),
          "depth" -> Json.fromInt(depth),
          "file"  -> Json.fromString(file),
          "line"  -> Json.fromString(line)
        )

    def visit(methodFullName: String, depth: Int, visited: Set[String]): Unit =
      if depth > maxDepth || totalSeen.get >= maxNodes || visited.contains(methodFullName) then
        return
      val callees: List[Method] =
          cpg.method.fullNameExact(methodFullName).flatMap(
            _.callee(using NoResolve).whereNot(_.name(".*<operator.*"))
          ).distinctBy(_.fullName).l
      for callee <- callees do
        if totalSeen.incrementAndGet() <= maxNodes then
          val file = callee.filename
          val line = callee.lineNumber.map(_.toString).getOrElse("")
          result += treeNode(callee.fullName, depth, file, line)
          visit(callee.fullName, depth + 1, visited + methodFullName)

    val rootMethod = cpg.method.fullNameExact(rootFullName).headOption
    val rootFile   = rootMethod.map(_.filename).getOrElse("")
    val rootLine   = rootMethod.flatMap(_.lineNumber.map(_.toString)).getOrElse("")
    result += treeNode(rootFullName, 0, rootFile, rootLine)
    visit(rootFullName, 1, Set.empty)
    result.toSeq
  end buildCallTree

  private def errorDetail(msg: String): Json =
      Json.obj(
        "props" -> Json.arr(Json.obj(
          "label" -> Json.fromString("Error"),
          "value" -> Json.fromString(msg)
        )),
        "childTitle"   -> Json.fromString(""),
        "childColumns" -> Json.arr(),
        "childRows"    -> Json.arr(),
        "code"         -> Json.Null
      )
end DetailHandler
