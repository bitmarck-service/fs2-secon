package de.bitmarck.bms.secon.fs2

import cats.Monad
import cats.syntax.functor._

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
