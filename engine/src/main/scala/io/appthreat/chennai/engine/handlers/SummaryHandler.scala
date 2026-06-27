package io.appthreat.chennai.engine.handlers

import io.circe.Json
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.Overlays
import io.shiftleft.semanticcpg.language.*

import scala.util.Try

/** Computes the atom summary table: a list of (label, count) rows plus metadata.
  *
  * Mirrors the chen 2.x `summary` command but is computed in a single pass-friendly,
  * exception-tolerant fashion so that a partially-built atom still yields a useful table.
  */
object SummaryHandler:

  private def count(f: => Int): Long = Try(f.toLong).getOrElse(0L)

  def summary(cpg: Cpg): Json =
    val rows = List(
      "Files"            -> count(cpg.file.whereNot(_.name("<unknown>")).size),
      "Methods"          -> count(cpg.method.size),
      "External methods" -> count(cpg.method.external.size),
      "Internal methods" -> count(cpg.method.internal.size),
      "Calls"            -> count(cpg.call.size),
      "Namespaces"       -> count(cpg.namespace.size),
      "Annotations"      -> count(cpg.annotation.size),
      "Imports"          -> count(cpg.imports.size),
      "Literals"         -> count(cpg.literal.size),
      "Config files"     -> count(cpg.configFile.size),
      "Validation tags"  -> count(cpg.tag.name("(validation|sanitization).*").size),
      "Unique packages"  -> count(cpg.tag.name("pkg.*").name.dedup.size),
      "Framework tags"   -> count(cpg.tag.name("framework.*").size),
      "Framework input"  -> count(cpg.tag.name("framework-(input|route)").size),
      "Framework output" -> count(cpg.tag.name("framework-output").size),
      "Crypto tags"      -> count(cpg.tag.name("crypto.*").size),
      "Overlays"         -> count(Overlays.appliedOverlays(cpg).size)
    )

    val language = Try(cpg.metaData.language.headOption).toOption.flatten.getOrElse("unknown")
    val version  = Try(cpg.metaData.version.headOption).toOption.flatten.getOrElse("")

    Json.obj(
      "language" -> Json.fromString(language),
      "version"  -> Json.fromString(version),
      "rows" -> Json.arr(
        rows.map { case (label, c) =>
            Json.obj("label" -> Json.fromString(label), "count" -> Json.fromLong(c))
        }*
      )
    )
  end summary
end SummaryHandler
