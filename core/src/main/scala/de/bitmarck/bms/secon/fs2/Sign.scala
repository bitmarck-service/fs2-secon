package de.bitmarck.bms.secon.fs2

import fs2.Pipe

trait Sign[F[_]] {
  def sign(identity: Identity): Pipe[F, Byte, Byte]
}

object Sign {
  def apply[F[_]](implicit sign: Sign[F]): Sign[F] = sign
}
