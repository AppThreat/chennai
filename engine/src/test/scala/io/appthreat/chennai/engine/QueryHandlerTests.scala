package io.appthreat.chennai.engine

import io.appthreat.chennai.engine.handlers.QueryHandler
import io.shiftleft.semanticcpg.testing.MockCpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class QueryHandlerTests extends AnyWordSpec with Matchers:

  private val cpg =
      MockCpg()
          .withMetaData("C", List("base"))
          .withFile("a.c")
          .withMethod("main", external = false, fileName = "a.c")
          .withMethod("strlen", external = true, fileName = "")
          .cpg

  "QueryHandler" should:
    "page the files table with column metadata" in:
      val json = QueryHandler.query(cpg, "files", None, 0, 100)
      json.hcursor.get[String]("title").toOption shouldBe Some("Files")
      json.hcursor.downField("columns").as[List[String]].toOption shouldBe Some(List(
        "File",
        "Methods"
      ))
      json.hcursor.get[Int]("total").toOption shouldBe Some(1)

    "list all methods with file/line columns" in:
      val json = QueryHandler.query(cpg, "methods", None, 0, 100)
      json.hcursor.get[Int]("total").toOption shouldBe Some(2)
      json.hcursor.downField("columns").as[List[String]].toOption shouldBe
          Some(List("Name", "Full Name", "File", "Line Count"))

    "filter external methods" in:
      val json = QueryHandler.query(cpg, "externalMethods", None, 0, 100)
      json.hcursor.get[Int]("total").toOption shouldBe Some(1)

    "filter internal methods" in:
      val json = QueryHandler.query(cpg, "internalMethods", None, 0, 100)
      json.hcursor.get[Int]("total").toOption shouldBe Some(1)

    "honour offset and limit" in:
      val json = QueryHandler.query(cpg, "methods", None, 1, 1)
      json.hcursor.get[Int]("offset").toOption shouldBe Some(1)
      json.hcursor.downField("rows").values.map(_.size) shouldBe Some(1)
      json.hcursor.get[Int]("total").toOption shouldBe Some(2)

    "reject unknown kinds" in:
      an[IllegalArgumentException] should be thrownBy QueryHandler.query(cpg, "bogus", None, 0, 10)
end QueryHandlerTests
