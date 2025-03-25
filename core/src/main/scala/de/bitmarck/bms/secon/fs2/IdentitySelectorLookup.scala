package de.bitmarck.bms.secon.fs2

import cats.Monad
import cats.syntax.functor._

import java.security.cert.X509CertSelector

trait IdentitySelectorLookup[F[_]] {
  protected def monadF: Monad[F]

  def identityBySelector(selector: X509CertSelector): F[Option[Identity]]

  final def identityBySelectorUnsafe(selector: X509CertSelector): F[Identity] = {
    implicit val implicitMonadF: Monad[F] = monadF
    identityBySelector(selector).map(_.getOrElse(throw new CertificateNotFoundException(selector.toString)))
  }
}
