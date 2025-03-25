package de.bitmarck.bms.secon.fs2

import cats.data.OptionT
import cats.syntax.functor._
import cats.{Applicative, Monad, Monoid}

import java.security.cert.X509Certificate

trait CertAliasLookup[F[_]] {
  protected def monadF: Monad[F]

  def certificateByAlias(alias: String): F[Option[X509Certificate]]

  final def certificateByAliasUnsafe(alias: String): F[X509Certificate] = {
    implicit val implicitMonadF: Monad[F] = monadF
    certificateByAlias(alias).map(_.getOrElse(throw new CertificateNotFoundException(s"Alias: $alias")))
  }

  def filterByAlias(f: String => Boolean): CertAliasLookup[F] = new CertAliasLookup[F] {
    override protected def monadF: Monad[F] = CertAliasLookup.this.monadF

    override def certificateByAlias(alias: String): F[Option[X509Certificate]] =
      if (f(alias)) CertAliasLookup.this.certificateByAlias(alias)
      else monadF.pure(None)
  }
}

object CertAliasLookup {
  implicit def monoid[F[_] : Monad]: Monoid[CertAliasLookup[F]] = Monoid.instance(
    new CertAliasLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def certificateByAlias(alias: String): F[Option[X509Certificate]] = Applicative[F].pure(None)
    },
    (a, b) => new CertAliasLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def certificateByAlias(alias: String): F[Option[X509Certificate]] =
        OptionT(a.certificateByAlias(alias))
          .orElseF(b.certificateByAlias(alias))
          .value
    }
  )

  def fromIdentityLookup[F[_] : Monad](identityLookup: IdentityAliasLookup[F]): CertAliasLookup[F] = new CertAliasLookup[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def certificateByAlias(alias: String): F[Option[X509Certificate]] =
      identityLookup.identityByAlias(alias).map(_.map(_.certificate))
  }
}
