package de.bitmarck.bms.secon.fs2

import cats.data.OptionT
import cats.syntax.functor._
import cats.{Applicative, Monad, Monoid}

import java.security.cert.X509CertSelector

trait IdentitySelectorLookup[F[_]] {
  protected def monadF: Monad[F]

  def identityBySelector(selector: X509CertSelector): F[Option[Identity]]

  final def identityBySelectorUnsafe(selector: X509CertSelector): F[Identity] = {
    implicit val implicitMonadF: Monad[F] = monadF
    identityBySelector(selector).map(_.getOrElse(throw new CertificateNotFoundException(selector.toString)))
  }
}

object IdentitySelectorLookup {
  implicit def monoid[F[_] : Monad]: Monoid[IdentitySelectorLookup[F]] = Monoid.instance(
    new IdentitySelectorLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def identityBySelector(selector: X509CertSelector): F[Option[Identity]] = Applicative[F].pure(None)
    },
    (a, b) => new IdentitySelectorLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def identityBySelector(selector: X509CertSelector): F[Option[Identity]] =
        OptionT(a.identityBySelector(selector))
          .orElseF(b.identityBySelector(selector))
          .value
    }
  )
}
