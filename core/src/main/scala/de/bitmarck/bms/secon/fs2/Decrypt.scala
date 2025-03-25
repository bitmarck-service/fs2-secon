package de.bitmarck.bms.secon.fs2

import fs2.Pipe

trait Decrypt[F[_]] {
  def decrypt(identityLookup: IdentitySelectorLookup[F]): Pipe[F, Byte, Byte]
}

object Decrypt {
  def apply[F[_]](implicit decrypt: Decrypt[F]): Decrypt[F] = decrypt
}
