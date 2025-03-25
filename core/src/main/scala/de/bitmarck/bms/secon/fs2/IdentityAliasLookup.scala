package de.bitmarck.bms.secon.fs2

import cats.data.OptionT
import cats.syntax.functor._
import cats.{Applicative, Monad, Monoid}

trait IdentityAliasLookup[F[_]] {
  protected def monadF: Monad[F]

  def identityByAlias(alias: String): F[Option[Identity]]

  final def identityByAliasUnsafe(alias: String): F[Identity] = {
    implicit val implicitMonadF: Monad[F] = monadF
    identityByAlias(alias).map(_.getOrElse(throw new CertificateNotFoundException(s"Alias: $alias")))
  }

  def filterByAlias(f: String => Boolean): IdentityAliasLookup[F] = new IdentityAliasLookup[F] {
    override protected def monadF: Monad[F] = IdentityAliasLookup.this.monadF

    override def identityByAlias(alias: String): F[Option[Identity]] =
      if (f(alias)) IdentityAliasLookup.this.identityByAlias(alias)
      else monadF.pure(None)
  }
}

object IdentityAliasLookup {
  implicit def monoid[F[_] : Monad]: Monoid[IdentityAliasLookup[F]] = Monoid.instance(
    new IdentityAliasLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def identityByAlias(alias: String): F[Option[Identity]] = Applicative[F].pure(None)
    },
    (a, b) => new IdentityAliasLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def identityByAlias(alias: String): F[Option[Identity]] =
        OptionT(a.identityByAlias(alias))
          .orElseF(b.identityByAlias(alias))
          .value
    }
  )
}
