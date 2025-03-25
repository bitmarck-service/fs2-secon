package de.bitmarck.bms.secon.fs2

import cats.Monad
import fs2.Pipe

trait Verify[F[_]] {
  protected def monadF: Monad[F]

  def verify(
              certLookup: CertSelectorLookup[F],
              verifier: Verifier[F] = Verifier.monoid[F](using monadF).empty
            ): Pipe[F, Byte, Byte]
}

object Verify {
  def apply[F[_]](implicit verify: Verify[F]): Verify[F] = verify
}
