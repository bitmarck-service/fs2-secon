package de.bitmarck.bms.secon.fs2

import cats.Monad
import fs2.Pipe

trait DecryptVerify[F[_]] extends Decrypt[F] with Verify[F] {
  protected def monadF: Monad[F]

  def decryptAndVerify(
                        identityLookup: IdentitySelectorLookup[F],
                        certLookup: CertSelectorLookup[F],
                        verifier: Verifier[F] = Verifier.monoid[F](using monadF).empty
                      ): Pipe[F, Byte, Byte] =
  _.through(decrypt(identityLookup))
    .through(verify(certLookup, verifier))
}

object DecryptVerify {
  def apply[F[_]](implicit decryptVerify: DecryptVerify[F]): DecryptVerify[F] = decryptVerify
}
