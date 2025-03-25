package de.bitmarck.bms.secon.fs2

import cats.data.OptionT
import cats.syntax.functor._
import cats.{Applicative, Monad, Monoid}

import java.security.cert.{X509CertSelector, X509Certificate}

trait CertSelectorLookup[F[_]] {
  protected def monadF: Monad[F]

  def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]]

  final def certificateBySelectorUnsafe(selector: X509CertSelector): F[X509Certificate] = {
    implicit val implicitMonadF: Monad[F] = monadF
    certificateBySelector(selector).map(_.getOrElse(throw new CertificateNotFoundException(selector.toString)))
  }
}

object CertSelectorLookup {
  implicit def monoid[F[_] : Monad]: Monoid[CertSelectorLookup[F]] = Monoid.instance(
    new CertSelectorLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] = Applicative[F].pure(None)
    },
    (a, b) => new CertSelectorLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] =
        OptionT(a.certificateBySelector(selector))
          .orElseF(b.certificateBySelector(selector))
          .value
    }
  )

  def fromIdentityLookup[F[_] : Monad](identityLookup: IdentitySelectorLookup[F]): CertSelectorLookup[F] = new CertSelectorLookup[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] =
      identityLookup.identityBySelector(selector).map(_.map(_.certificate))
  }
}
