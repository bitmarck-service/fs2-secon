package de.bitmarck.bms.secon.fs2

import cats.Monad
import cats.syntax.functor._

import java.security.cert.{X509CertSelector, X509Certificate}

trait CertSelectorLookup[F[_]] {
  protected def monadF: Monad[F]

  def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]]

  final def certificateBySelectorUnsafe(selector: X509CertSelector): F[X509Certificate] = {
    implicit val implicitMonadF: Monad[F] = monadF
    certificateBySelector(selector).map(_.getOrElse(throw new CertificateNotFoundException(selector.toString)))
  }
}
