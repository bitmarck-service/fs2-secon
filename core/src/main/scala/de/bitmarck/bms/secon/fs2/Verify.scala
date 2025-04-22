package de.bitmarck.bms.secon.fs2

import cats.Monad
import de.bitmarck.bms.secon.fs2.Verify.VerifyInfo
import fs2.{Pipe, Stream}

import java.security.cert.X509Certificate

trait Verify[F[_]] {
  protected def monadF: Monad[F]

  def verifyWithInfo(
                        signerCertLookup: CertSelectorLookup[F],
                        verifier: Verifier[F] = Verifier.monoid[F](using monadF).empty
                      ): Stream[F, Byte] => (Stream[F, Byte], F[VerifyInfo])

  def verify(
              signerCertLookup: CertSelectorLookup[F],
              verifier: Verifier[F] = Verifier.monoid[F](using monadF).empty
            ): Pipe[F, Byte, Byte] =
    verifyWithInfo(signerCertLookup, verifier).andThen(_._1)
}

object Verify {
  def apply[F[_]](implicit verify: Verify[F]): Verify[F] = verify

  case class VerifyInfo(signerCert: X509Certificate)
}
