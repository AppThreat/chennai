package io.appthreat.chennai.engine

import io.circe.{Json, ParsingFailure}
import io.circe.parser.parse

/** NDJSON wire protocol shared with the Rust TUI.
  *
  * Request : {"id":N,"cmd":"summary","args":{...}} Response: {"id":N,"ok":true,"data":{...}} |
  * {"id":N,"ok":false,"error":"..."}
  */
final case class Request(id: Long, cmd: String, args: Json)

object Request:
  /** Parse a single NDJSON line into a [[Request]]. */
  def fromLine(line: String): Either[String, Request] =
      parse(line) match
        case Left(ParsingFailure(msg, _)) => Left(s"invalid json: $msg")
        case Right(json) =>
            val c   = json.hcursor
            val id  = c.get[Long]("id").getOrElse(0L)
            val cmd = c.get[String]("cmd")
            cmd match
              case Left(_) => Left("missing 'cmd' field")
              case Right(v) =>
                  Right(Request(id, v, c.downField("args").focus.getOrElse(Json.obj())))

object Response:
  def ok(id: Long, data: Json): Json =
      Json.obj("id" -> Json.fromLong(id), "ok" -> Json.True, "data" -> data)

  def error(id: Long, message: String): Json =
      Json.obj("id" -> Json.fromLong(id), "ok" -> Json.False, "error" -> Json.fromString(message))
