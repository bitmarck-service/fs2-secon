package de.bitmarck.bms.secon.fs2

import cats.Monad
import fs2.Pipe

trait DecryptVerify[F[_]] {
  protected def monadF: Monad[F]

  def decrypt(identityLookup: IdentityLookup[F]): fs2.Pipe[F, Byte, Byte]

  def verify(
              certLookup: CertLookup[F],
              verifier: Verifier[F] = Verifier.monoid[F](monadF).empty
            ): fs2.Pipe[F, Byte, Byte]

  def decryptAndVerify(
                        identityLookup: IdentityLookup[F],
                        certLookup: CertLookup[F],
                        verifier: Verifier[F] = Verifier.monoid[F](monadF).empty
                      ): Pipe[F, Byte, Byte] =
  _.through(decrypt(identityLookup))
    .through(verify(certLookup, verifier))
}

object DecryptVerify {
  def apply[F[_]](implicit decryptVerify: DecryptVerify[F]): DecryptVerify[F] = decryptVerify
}
