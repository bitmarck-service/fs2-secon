package de.bitmarck.bms.secon.fs2

import de.bitmarck.bms.secon.fs2.Decrypt.DecryptInfo
import fs2.{Pipe, Stream}

trait Decrypt[F[_]] {
  def decryptWithInfo(
                         identityLookup: IdentitySelectorLookup[F]
                       ): Stream[F, Byte] => (Stream[F, Byte], F[DecryptInfo])

  def decrypt(
               identityLookup: IdentitySelectorLookup[F]
             ): Pipe[F, Byte, Byte] =
    decryptWithInfo(identityLookup).andThen(_._1)
}

object Decrypt {
  def apply[F[_]](implicit decrypt: Decrypt[F]): Decrypt[F] = decrypt

  case class DecryptInfo(identity: Identity)
}
