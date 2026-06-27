package io.appthreat.chennai.engine

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class ProtocolTests extends AnyWordSpec with Matchers:

  "Request.fromLine" should:
    "parse a well-formed request" in:
      val r = Request.fromLine("""{"id":7,"cmd":"summary","args":{"limit":10}}""")
      r.isRight shouldBe true
      val req = r.toOption.get
      req.id shouldBe 7L
      req.cmd shouldBe "summary"
      req.args.hcursor.get[Int]("limit").toOption shouldBe Some(10)

    "default args to an empty object when absent" in:
      val req = Request.fromLine("""{"id":1,"cmd":"ping"}""").toOption.get
      req.args shouldBe io.circe.Json.obj()

    "reject json without a cmd" in:
      Request.fromLine("""{"id":1}""").isLeft shouldBe true

    "reject malformed json" in:
      Request.fromLine("""not json""").isLeft shouldBe true

  "Response" should:
    "encode ok responses" in:
      val j = Response.ok(3, io.circe.Json.obj("x" -> io.circe.Json.fromInt(1)))
      j.noSpaces shouldBe """{"id":3,"ok":true,"data":{"x":1}}"""

    "encode error responses" in:
      val j = Response.error(4, "boom")
      j.noSpaces shouldBe """{"id":4,"ok":false,"error":"boom"}"""
end ProtocolTests
