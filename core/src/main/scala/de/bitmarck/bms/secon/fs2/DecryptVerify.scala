package de.bitmarck.bms.secon.fs2

import cats.Monad
import de.bitmarck.bms.secon.fs2.Decrypt.DecryptInfo
import de.bitmarck.bms.secon.fs2.Verify.VerifyInfo
import fs2.{Pipe, Stream}

trait DecryptVerify[F[_]] extends Decrypt[F] with Verify[F] {
  protected def monadF: Monad[F]

  def decryptAndVerifyWithInfo(
                                  identityLookup: IdentitySelectorLookup[F],
                                  signerCertLookup: CertSelectorLookup[F],
                                  verifier: Verifier[F] = Verifier.monoid[F](using monadF).empty
                                ): Stream[F, Byte] => (Stream[F, Byte], F[DecryptInfo], F[VerifyInfo]) = {
    stream =>
      val (decryptedBytes, decryptInfo) = decryptWithInfo(identityLookup)(stream)
      val (verifiedBytes, verifyInfo) = verifyWithInfo(signerCertLookup, verifier)(decryptedBytes)
      (verifiedBytes, decryptInfo, verifyInfo)
  }

  def decryptAndVerify(
                        identityLookup: IdentitySelectorLookup[F],
                        signerCertLookup: CertSelectorLookup[F],
                        verifier: Verifier[F] = Verifier.monoid[F](using monadF).empty
                      ): Pipe[F, Byte, Byte] =
    _.through(decrypt(identityLookup))
      .through(verify(signerCertLookup, verifier))
}

object DecryptVerify {
  def apply[F[_]](implicit decryptVerify: DecryptVerify[F]): DecryptVerify[F] = decryptVerify
}
