package io.appthreat.chennai.engine.handlers

import io.appthreat.chennai.engine.ReplBridge
import io.circe.Json
import io.circe.parser.parse

/** Converts the JSON produced by a REPL `.toJson` evaluation into the same generic, paged table
  * shape the TUI already renders for `query` results.
  */
object EvalHandler:

  /** Columns shown first when present, so common node fields line up neatly across queries. */
  private val preferred =
      List(
        "_label",
        "name",
        "fullName",
        "methodFullName",
        "code",
        "typeFullName",
        "value",
        "filename",
        "lineNumber",
        "columnNumber",
        "order"
      )

  private val maxColumns = 8

  private def kindFor(col: String): String = col match
    case "name" | "fullName" | "methodFullName"                              => "name"
    case "code"                                                              => "code"
    case "filename" | "file"                                                 => "path"
    case "lineNumber" | "columnNumber" | "order" | "argumentIndex" | "index" => "num"
    case _                                                                   => "text"

  private def cellOf(j: Json, kind: String): Json =
    val v = j.asString.getOrElse(if j.isNull then "" else j.noSpaces)
    Json.obj("v" -> Json.fromString(v), "k" -> Json.fromString(kind))

  /** Evaluate `expr` via the REPL and shape the result into a table, or return an error string. */
  def eval(bridge: ReplBridge, expr: String): Either[String, Json] =
      bridge.eval(expr).flatMap { jsonStr =>
          parse(jsonStr) match
            case Left(err)   => Left(s"could not parse REPL output: ${err.getMessage}")
            case Right(json) => Right(toTable(expr, json))
      }

  private def toTable(expr: String, json: Json): Json =
    val elements = json.asArray.map(_.toVector).getOrElse(Vector(json))
    val objects  = elements.flatMap(_.asObject)

    val (columns, rows): (List[String], Vector[List[Json]]) =
        if objects.sizeIs == elements.size && objects.nonEmpty then
          // Array of node maps: union the keys, preferred-first, capped for readability.
          val present = objects.flatMap(_.keys).distinct
          val ordered =
              (preferred.filter(present.contains) ++ present.filterNot(preferred.contains))
                  .take(maxColumns)
          val rs = objects.map { obj =>
              ordered.map(c => cellOf(obj(c).getOrElse(Json.Null), kindFor(c)))
          }
          (ordered, rs)
        else
          // Array of scalars (e.g. `.name.toJson`).
          (List("value"), elements.map(e => List(cellOf(e, "text"))))

    Json.obj(
      "title"   -> Json.fromString(s"REPL: $expr"),
      "columns" -> Json.arr(columns.map(Json.fromString)*),
      "rows"    -> Json.arr(rows.map(r => Json.arr(r*))*),
      "total"   -> Json.fromInt(elements.size),
      "offset"  -> Json.fromInt(0)
    )
  end toTable
end EvalHandler
