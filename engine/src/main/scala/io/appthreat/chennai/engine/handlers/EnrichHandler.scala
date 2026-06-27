package io.appthreat.chennai.engine.handlers

import io.appthreat.x2cpg.passes.taggers.{CdxPass, EasyTagsPass}
import io.circe.Json
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.NewConfigFile
import io.shiftleft.passes.ConcurrentWriterCpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate

import java.nio.file.{Files, Paths}

/** Load a CycloneDX SBOM file into the open atom and run enrichment passes (CdxPass, EasyTagsPass)
  * so that dependency data (PURLs, framework tags) is available for reachability analysis.
  */
object EnrichHandler:

  /** Load an SBOM from `bomPath` into the CPG, adding it as a config file, then run enrichment
    * passes. Returns a JSON object with `"ok": true` on success, or an error message.
    */
  def enrich(cpg: Cpg, bomPath: String): Either[String, Json] =
      try
        val path = Paths.get(bomPath)
        if !Files.exists(path) then
          return Left(s"SBOM file not found: $bomPath")

        val content = Files.readString(path)
        val name    = path.getFileName.toString

        // Build a diff that adds a ConfigFile node with the SBOM content.
        val diff = BatchedUpdate.DiffGraphBuilder()
        diff.addNode(
          NewConfigFile()
              .name(name)
              .content(content)
        )
        // Apply the diff to the CPG in-place.
        BatchedUpdate.applyDiff(cpg.graph, diff)

        // Run CdxPass to tag CPG nodes with PURLs from the SBOM.
        new CdxPass(cpg).createAndApply()

        // Run EasyTagsPass to tag framework-input/output, sanitizers, etc.
        new EasyTagsPass(cpg).createAndApply()

        Right(
          Json.obj(
            "ok"     -> Json.True,
            "bom"    -> Json.fromString(name),
            "passes" -> Json.arr(Json.fromString("CdxPass"), Json.fromString("EasyTagsPass"))
          )
        )
      catch
        case e: Exception =>
            Left(s"enrich failed: ${e.getMessage}")

end EnrichHandler
