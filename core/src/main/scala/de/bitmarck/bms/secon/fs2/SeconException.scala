package de.bitmarck.bms.secon.fs2

class SeconException(message: String, cause: Throwable) extends Exception(message, cause) {
  def this(message: String) = this(message, null)
}
