package io.appthreat.chennai.engine

import io.appthreat.chennai.engine.handlers.FlowHandler
import io.circe.parser
import io.shiftleft.semanticcpg.testing.MockCpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Exercises the argument plumbing and response shape of [[FlowHandler.flows]]. The reachability
  * computation itself needs a real data-flow overlay; here we use a tag-free [[MockCpg]] so the
  * preset enumerators short-circuit to empty, letting us assert the pagination/slicing contract
  * (offset, limit, capped, nextOffset) without standing up the dataflow engine.
  */
class FlowHandlerTests extends AnyWordSpec with Matchers:

  private val cpg =
      MockCpg()
          .withMetaData("JAVA", List("base"))
          .withFile("a.java")
          .withMethod("main", external = false, fileName = "a.java")
          .cpg

  // The REPL bridge is only consulted for `expr`/`source`+`sink` queries; preset and error-path
  // tests never touch it, so a null is safe and avoids embedding the REPL.
  private val noBridge: ReplBridge = null

  private def run(json: String): Either[String, io.circe.Json] =
      FlowHandler.flows(cpg, noBridge, parser.parse(json).toOption.get.hcursor)

  private def ok(json: String): io.circe.Json =
      run(json).getOrElse(fail(s"expected Right for $json"))

  "FlowHandler.flows" should:
    "echo offset/limit and report an empty, non-capped result for a preset on a tag-free atom" in:
      val c = ok("""{"preset":"reachables","take":10,"limit":5,"offset":0}""").hcursor
      c.get[Int]("total").toOption shouldBe Some(0)
      c.get[Int]("offset").toOption shouldBe Some(0)
      c.get[Int]("limit").toOption shouldBe Some(5)
      c.get[Boolean]("capped").toOption shouldBe Some(false)
      c.get[Option[Int]]("nextOffset").toOption.flatten shouldBe None
      c.downField("flows").values.map(_.size) shouldBe Some(0)

    "default the limit when not provided" in:
      ok("""{"preset":"dataflows"}""").hcursor.get[Int]("limit").toOption shouldBe Some(50)

    "accept sourceTags/sinkTags as a delimited string without error" in:
      val out = ok(
        """{"preset":"reachables","sinkTags":"sql|code-execution","sourceTags":"framework-input"}"""
      )
      out.hcursor.get[String]("title").toOption shouldBe Some("Reachable flows")

    "accept sinkTags as a JSON array" in:
      val out = ok("""{"preset":"dataflows","sinkTags":["sql","file-io"]}""")
      out.hcursor.get[String]("title").toOption shouldBe Some("Data flows")

    "reject a query with neither expr, preset, nor a source/sink pair" in:
      run("""{"source":"atom.tag.name(\"x\")"}""") shouldBe a[Left[?, ?]]
end FlowHandlerTests
