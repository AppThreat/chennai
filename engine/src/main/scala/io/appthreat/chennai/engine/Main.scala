package io.appthreat.chennai.engine

import scopt.OParser

import java.io.{BufferedReader, InputStreamReader, PrintStream}

final case class Config(serve: Boolean = false, atom: Option[String] = None)

/** Entry point for the chennai engine.
  *
  * `chennai-engine --serve [--atom <path>]` starts the NDJSON stdio server. When `--atom` is given
  * the atom is opened eagerly so the first `summary` request can be answered immediately.
  */
object Main:

  private val builder = OParser.builder[Config]
  private val parser =
    import builder.*
    OParser.sequence(
      programName("chennai-engine"),
      head("chennai-engine", "0.2.0"),
      opt[Unit]("serve").action((_, c) => c.copy(serve = true)).text("run the NDJSON stdio server"),
      opt[String]("atom").action((p, c) => c.copy(atom = Some(p))).text(
        "path to an existing .atom file to open"
      ),
      help("help").text("print this usage text")
    )

  def main(args: Array[String]): Unit =
      OParser.parse(parser, args, Config()) match
        case Some(cfg) if cfg.serve => serve(cfg)
        case Some(_) =>
            System.err.println("nothing to do; pass --serve")
            sys.exit(2)
        case None => sys.exit(2)

  private def serve(cfg: Config): Unit =
    // Reserve real stdout exclusively for the NDJSON protocol; redirect any library chatter to stderr.
    val protocolOut: PrintStream = System.out
    System.setOut(System.err)

    val session = new AtomSession
    cfg.atom.foreach { path =>
        session.open(path) match
          case scala.util.Failure(ex) =>
              System.err.println(s"warning: could not open $path: ${ex.getMessage}")
          case _ => ()
    }

    val server =
        new Server(session, new BufferedReader(new InputStreamReader(System.in)), protocolOut)
    try server.run()
    finally session.close()
end Main
