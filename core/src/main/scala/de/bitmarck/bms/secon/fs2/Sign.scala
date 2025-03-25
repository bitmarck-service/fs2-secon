package de.bitmarck.bms.secon.fs2

import fs2.Pipe

trait Sign[F[_]] {
  def sign(identity: Identity): Pipe[F, Byte, Byte]
}
