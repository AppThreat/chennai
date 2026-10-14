package io.appthreat.chennai.engine

/** Runs a command, turning any failure the engine can survive into its message.
  *
  * The REPL fails with linkage errors and stack overflows as well as exceptions (the compiler not
  * finding its library, a class missing from a native image, a deeply nested expression), and none
  * of them should end the engine and leave the TUI without one. Running out of memory still does.
  */
object Guarded:
  def apply[A](f: => A): Either[String, A] =
      try Right(f)
      catch
        case e: VirtualMachineError if !e.isInstanceOf[StackOverflowError] => throw e
        case e: Throwable                                                  => Left(message(e))

  def message(e: Throwable): String =
      Option(e.getMessage).map(_.trim).filter(_.nonEmpty).getOrElse(e.getClass.getName)
