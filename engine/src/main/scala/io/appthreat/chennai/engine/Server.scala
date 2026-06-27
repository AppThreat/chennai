package io.appthreat.chennai.engine

import io.appthreat.chennai.engine.handlers.{
    AlgoHandler,
    DetailHandler,
    EnrichHandler,
    EvalHandler,
    FlowHandler,
    QueryHandler,
    SummaryHandler
}
import io.circe.Json

import java.io.{BufferedReader, PrintStream}
import scala.util.{Failure, Success, Try}

/** stdio NDJSON server: reads one request per line from `in`, writes one response per line to
  * `out`. Designed to be spawned as a child process by the Rust TUI.
  */
final class Server(session: AtomSession, in: BufferedReader, out: PrintStream):

  def run(): Unit =
    var line = in.readLine()
    while line != null do
      if line.trim.nonEmpty then
        val response = Request.fromLine(line) match
          case Left(err)  => Response.error(0, err)
          case Right(req) => dispatch(req)
        out.println(response.noSpaces)
        out.flush()
      line = in.readLine()

  private def dispatch(req: Request): Json =
      req.cmd match
        case "open"     => handleOpen(req)
        case "close"    => session.close(); Response.ok(req.id, Json.obj("closed" -> Json.True))
        case "summary"  => withCpg(req)(cpg => Response.ok(req.id, SummaryHandler.summary(cpg)))
        case "query"    => handleQuery(req)
        case "flows"    => handleFlows(req)
        case "complete" => handleComplete(req)
        case "eval"     => handleEval(req)
        case "detail"   => handleDetail(req)
        case "algo"     => handleAlgo(req)
        case "enrich"   => handleEnrich(req)
        case "ping"     => Response.ok(req.id, Json.obj("pong" -> Json.True))
        case other      => Response.error(req.id, s"unknown command: $other")

  private def handleOpen(req: Request): Json =
    val c          = req.args.hcursor
    val pathOpt    = c.get[String]("path").toOption
    val sourceRoot = c.get[String]("sourceRoot").toOption
    pathOpt match
      case None => Response.error(req.id, "open requires 'path' argument")
      case Some(path) =>
          session.open(path, sourceRoot) match
            case Success(cpg) =>
                Response.ok(
                  req.id,
                  Json.obj(
                    "path"     -> Json.fromString(path),
                    "language" -> Json.fromString(Try(cpgLanguage(cpg)).getOrElse("unknown"))
                  )
                )
            case Failure(ex) => Response.error(req.id, s"failed to open atom: ${ex.getMessage}")

  private def handleQuery(req: Request): Json =
    val c       = req.args.hcursor
    val kind    = c.get[String]("kind").toOption
    val pattern = c.get[String]("pattern").toOption
    val offset  = c.get[Int]("offset").getOrElse(0)
    val limit   = c.get[Int]("limit").getOrElse(2000)
    kind match
      case None => Response.error(req.id, "query requires 'kind' argument")
      case Some(k) =>
          withCpg(req)(cpg =>
              Response.ok(req.id, QueryHandler.query(cpg, k, pattern, offset, limit))
          )

  private def handleFlows(req: Request): Json =
      session.cpg match
        case None => Response.error(req.id, "no atom open; send 'open' first")
        case Some(cpg) =>
            session.replBridge match
              case None => Response.error(req.id, "no atom open; send 'open' first")
              case Some(bridge) =>
                  Try(FlowHandler.flows(cpg, bridge, req.args.hcursor)) match
                    case Success(Right(flowSet)) => Response.ok(req.id, flowSet)
                    case Success(Left(err))      => Response.error(req.id, err)
                    case Failure(ex) => Response.error(req.id, s"flows failed: ${ex.getMessage}")

  private def handleComplete(req: Request): Json =
    val c      = req.args.hcursor
    val line   = c.get[String]("line").getOrElse("")
    val cursor = c.get[Int]("cursor").getOrElse(line.length)
    session.replBridge match
      case None => Response.error(req.id, "no atom open; send 'open' first")
      case Some(bridge) =>
          val items = bridge.complete(line, cursor)
          Response.ok(
            req.id,
            Json.obj("completions" -> Json.arr(items.map(Json.fromString)*))
          )

  private def handleEval(req: Request): Json =
    val expr = req.args.hcursor.get[String]("expr").toOption.map(_.trim).filter(_.nonEmpty)
    expr match
      case None => Response.error(req.id, "eval requires a non-empty 'expr' argument")
      case Some(e) =>
          session.replBridge match
            case None => Response.error(req.id, "no atom open; send 'open' first")
            case Some(bridge) =>
                EvalHandler.eval(bridge, e) match
                  case Right(table) => Response.ok(req.id, table)
                  case Left(err)    => Response.error(req.id, err)

  private def handleDetail(req: Request): Json =
    val c    = req.args.hcursor
    val kind = c.get[String]("kind").getOrElse("")
    val key  = c.get[String]("key").getOrElse("")
    val file = c.get[String]("file").toOption
    val line = c.get[Int]("line").toOption
    if kind.isEmpty || key.isEmpty then
      Response.error(req.id, "detail requires 'kind' and 'key' arguments")
    else
      withCpg(req)(cpg =>
          Response.ok(
            req.id,
            DetailHandler.detail(
              cpg,
              kind,
              key,
              file,
              line,
              session.path.getOrElse(""),
              session.sourceRoot
            )
          )
      )
  end handleDetail

  private def handleEnrich(req: Request): Json =
    val bomPath = req.args.hcursor.get[String]("bom").toOption
    bomPath match
      case None => Response.error(req.id, "enrich requires a 'bom' argument (path to SBOM file)")
      case Some(path) =>
          withCpg(req)(cpg =>
              EnrichHandler.enrich(cpg, path) match
                case Right(json) => Response.ok(req.id, json)
                case Left(err)   => Response.error(req.id, err)
          )

  private def handleAlgo(req: Request): Json =
      withCpg(req)(cpg =>
          AlgoHandler.algo(cpg, req.args.hcursor) match
            case Right(table) => Response.ok(req.id, table)
            case Left(err)    => Response.error(req.id, err)
      )

  private def withCpg(req: Request)(f: io.shiftleft.codepropertygraph.Cpg => Json): Json =
      session.cpg match
        case Some(cpg) =>
            Try(f(cpg)) match
              case Success(json) => json
              case Failure(ex)   => Response.error(req.id, s"command failed: ${ex.getMessage}")
        case None => Response.error(req.id, "no atom open; send 'open' first")

  private def cpgLanguage(cpg: io.shiftleft.codepropertygraph.Cpg): String =
    import io.shiftleft.semanticcpg.language.*
    cpg.metaData.language.headOption.getOrElse("unknown")
end Server
