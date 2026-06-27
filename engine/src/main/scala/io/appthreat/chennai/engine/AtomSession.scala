package io.appthreat.chennai.engine

import io.shiftleft.codepropertygraph.Cpg
import overflowdb.Config

import java.nio.file.{Files, Paths}
import scala.util.{Failure, Success, Try}

/** Holds the currently open atom (`Cpg`) for a session.
  *
  * The atom is an overflowdb2 storage file; opening it with a storage location loads the existing
  * graph without mutating it.
  */
final class AtomSession:

  private var cpgOpt: Option[Cpg]           = None
  private var pathOpt: Option[String]       = None
  private var sourceRootOpt: Option[String] = None
  private var bridgeOpt: Option[ReplBridge] = None

  def cpg: Option[Cpg]           = cpgOpt
  def path: Option[String]       = pathOpt
  def sourceRoot: Option[String] = sourceRootOpt

  /** The REPL bridge for the open atom, created lazily on first use (booting the compiler is
    * expensive). Recreated whenever a new atom is opened.
    */
  def replBridge: Option[ReplBridge] =
      cpgOpt.map { c =>
          bridgeOpt.getOrElse {
              val b = new ReplBridge(c)
              bridgeOpt = Some(b)
              b
          }
      }

  /** Open the atom at `atomPath`, closing any previously open atom. `sourceRoot` pins the project
    * root used for resolving relative file paths; when absent the engine falls back to
    * auto-detection from the atom directory.
    */
  def open(atomPath: String, sourceRoot: Option[String] = None): Try[Cpg] =
    val file = Paths.get(atomPath)
    if !Files.exists(file) then Failure(new IllegalArgumentException(s"atom not found: $atomPath"))
    else
      close()
      Try {
          val cpg = Cpg.withConfig(
            Config.withDefaults().withStorageLocation(file.toAbsolutePath.toString)
          )
          cpgOpt = Some(cpg)
          pathOpt = Some(atomPath)
          sourceRootOpt = sourceRoot
          cpg
      } match
        case s @ Success(_) => s
        case f @ Failure(_) =>
            cpgOpt = None
            pathOpt = None
            sourceRootOpt = None
            f
  end open

  def close(): Unit =
    cpgOpt.foreach(c => Try(c.close()))
    cpgOpt = None
    pathOpt = None
    sourceRootOpt = None
    bridgeOpt = None
end AtomSession
