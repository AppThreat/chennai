package io.appthreat.chennai.engine.handlers

import io.circe.Json
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.Overlays
import io.shiftleft.semanticcpg.language.*

import scala.util.Try

/** Executes node-type queries derived from the summary table and returns generic, paged tables.
  *
  * A table is `{ title, columns, rows, total, offset, lang }` where every cell is `{ "v": <text>,
  * "k": <kind> }` and `kind` lets the TUI apply column-appropriate styling (code, name, path,
  * number, …).
  *
  * Counting and windowing use independent traversals so only the visible window is materialised as
  * JSON — important for atoms with hundreds of thousands of calls/literals.
  */
object QueryHandler:

  private given NodeExtensionFinder = DefaultNodeExtensionFinder

  private object Kind:
    val Text = "text"
    val Code = "code"
    val Name = "name"
    val Path = "path"
    val Num  = "num"

  private def cell(value: String, kind: String): Json =
      Json.obj("v" -> Json.fromString(value), "k" -> Json.fromString(kind))

  private def lineStr(line: Option[Integer]): String = line.map(_.toString).getOrElse("")

  private def fileOf(node: StoredNode): String =
      Try(node.file.name.headOption.getOrElse("")).getOrElse("")

  def query(cpg: Cpg, kind: String, pattern: Option[String], offset: Int, limit: Int): Json =
    val lang  = Try(cpg.metaData.language.headOption).toOption.flatten.getOrElse("unknown")
    val from  = offset.max(0)
    val count = limit.max(0)

    /** Build a paged table from a by-name traversal (evaluated twice: once to count, once to render
      * the window) and a per-element renderer.
      */
    def page[A](
      title: String,
      columns: List[String]
    )(mk: => Iterator[A])(render: A => List[Json]): Json =
      val total  = mk.size
      val window = mk.slice(from, from + count).map(render).toList
      Json.obj(
        "title"   -> Json.fromString(title),
        "lang"    -> Json.fromString(lang),
        "columns" -> Json.arr(columns.map(Json.fromString)*),
        "rows"    -> Json.arr(window.map(r => Json.arr(r*))*),
        "total"   -> Json.fromInt(total),
        "offset"  -> Json.fromInt(from)
      )

    kind match
      case "files" =>
          page("Files", List("File", "Methods"))(cpg.file.whereNot(_.name("<unknown>")).iterator) {
              f =>
                  List(cell(f.name, Kind.Path), cell(f.method.size.toString, Kind.Num))
          }

      case "methods" | "externalMethods" | "internalMethods" =>
          val title = kind match
            case "externalMethods" => "External methods"
            case "internalMethods" => "Internal methods"
            case _                 => "Methods"
          def base: Iterator[?] = kind match
            case "externalMethods" => cpg.method.external.iterator
            case "internalMethods" => cpg.method.internal.iterator
            case _                 => cpg.method.iterator
          page(title, List("Name", "Full Name", "File", "Line Count"))(
            base.asInstanceOf[Iterator[io.shiftleft.codepropertygraph.generated.nodes.Method]]
          ) { m =>
              List(
                cell(m.name, Kind.Name),
                cell(m.fullName, Kind.Code),
                cell(if m.filename.isEmpty then "" else m.filename, Kind.Path),
                cell(lineStr(m.lineNumber), Kind.Num)
              )
          }

      case "calls" =>
          page("Calls", List("Name", "Code", "File", "Line Count"))(cpg.call.iterator) { c =>
              List(
                cell(c.name, Kind.Name),
                cell(c.code, Kind.Code),
                cell(fileOf(c), Kind.Path),
                cell(lineStr(c.lineNumber), Kind.Num)
              )
          }

      case "namespaces" =>
          page("Namespaces", List("Namespace"))(cpg.namespace.iterator)(n =>
              List(cell(n.name, Kind.Name))
          )

      case "annotations" =>
          page("Annotations", List("Name", "Code", "File", "Line Count"))(cpg.annotation.iterator) {
              a =>
                  List(
                    cell(a.name, Kind.Name),
                    cell(a.code, Kind.Code),
                    cell(fileOf(a), Kind.Path),
                    cell(lineStr(a.lineNumber), Kind.Num)
                  )
          }

      case "imports" =>
          page("Imports", List("Imported Entity", "As", "Code"))(cpg.imports.iterator) { i =>
              List(
                cell(i.importedEntity.getOrElse(""), Kind.Code),
                cell(i.importedAs.getOrElse(""), Kind.Name),
                cell(i.code, Kind.Code)
              )
          }

      case "literals" =>
          page("Literals", List("Code", "File", "Line Count"))(cpg.literal.iterator) { l =>
              List(
                cell(l.code, Kind.Code),
                cell(fileOf(l), Kind.Path),
                cell(lineStr(l.lineNumber), Kind.Num)
              )
          }

      case "configFiles" =>
          page("Config files", List("Name", "Size"))(cpg.configFile.iterator) { c =>
              List(cell(c.name, Kind.Path), cell(c.content.length.toString, Kind.Num))
          }

      case "overlays" =>
          page("Overlays", List("Overlay"))(Overlays.appliedOverlays(cpg).iterator)(o =>
              List(cell(o, Kind.Name))
          )

      case "tagNames" =>
          // Distinct tag names with how many nodes carry each, most-frequent first. Unlike "tags"
          // (one row per tagged node) this is a compact vocabulary view — used to surface the
          // atom's source/sink tag set up front (e.g. in the agent system prompt).
          val pat = pattern.getOrElse(".*")
          val counts = cpg.tag.name(pat).name.l.groupBy(identity).view.mapValues(_.size).toList
              .sortBy { case (name, n) => (-n, name) }
          page("Tag names", List("Tag", "Count"))(counts.iterator) { case (name, n) =>
              List(cell(name, Kind.Name), cell(n.toString, Kind.Num))
          }

      case "tags" =>
          val pat = pattern.getOrElse(".*")
          def tagged: Iterator[(io.shiftleft.codepropertygraph.generated.nodes.Tag, StoredNode)] =
              cpg.tag.name(pat).iterator.flatMap(t =>
                  t._taggedByIn.iterator.map(n => (t, n.asInstanceOf[StoredNode]))
              )
          page(s"Tags: $pat", List("Tag", "Value", "Node", "Symbol", "File", "Line Count"))(
            tagged
          ) { case (t, sn) =>
              val loc = LocationCreator(sn)
              List(
                cell(t.name, Kind.Name),
                cell(t.value, Kind.Text),
                cell(Option(loc.nodeLabel).getOrElse(sn.label), Kind.Text),
                cell(Option(loc.symbol).getOrElse(""), Kind.Code),
                cell(Option(loc.filename).getOrElse(""), Kind.Path),
                cell(lineStr(loc.lineNumber), Kind.Num)
              )
          }

      case other =>
          throw new IllegalArgumentException(s"unknown query kind: $other")
    end match
  end query
end QueryHandler
