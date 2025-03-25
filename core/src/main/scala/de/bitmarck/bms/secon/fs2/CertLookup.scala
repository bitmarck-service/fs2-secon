package de.bitmarck.bms.secon.fs2

import cats.data.OptionT
import cats.effect.Sync
import cats.syntax.functor._
import cats.{Applicative, Monad, Monoid}

import java.security.KeyStore
import java.security.cert.{X509CertSelector, X509Certificate}
import scala.jdk.CollectionConverters._

trait CertLookup[F[_]] extends CertAliasLookup[F] with CertSelectorLookup[F] {
  override def filterByAlias(f: String => Boolean): CertLookup[F] = {
    val filteredAliasLookup = super.filterByAlias(f)
    new CertLookup[F] {
      override protected def monadF: Monad[F] = CertLookup.this.monadF

      override def certificateByAlias(alias: String): F[Option[X509Certificate]] =
        filteredAliasLookup.certificateByAlias(alias)

      override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] =
        CertLookup.this.certificateBySelector(selector)
    }
  }
}

object CertLookup {
  implicit def monoid[F[_] : Monad]: Monoid[CertLookup[F]] = Monoid.instance(
    new CertLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def certificateByAlias(alias: String): F[Option[X509Certificate]] = Applicative[F].pure(None)

      override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] = Applicative[F].pure(None)
    },
    (a, b) => new CertLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def certificateByAlias(alias: String): F[Option[X509Certificate]] =
        OptionT(a.certificateByAlias(alias))
          .orElseF(b.certificateByAlias(alias))
          .value

      override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] =
        OptionT(a.certificateBySelector(selector))
          .orElseF(b.certificateBySelector(selector))
          .value
    }
  )

  def fromCertificate[F[_] : Sync](
                                    certificate: X509Certificate,
                                    expectedAlias: Option[String] = None
                                  ): CertLookup[F] = new CertLookup[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def certificateByAlias(alias: String): F[Option[X509Certificate]] = Sync[F].delay {
      if (expectedAlias.forall(_ == alias)) Some(certificate)
      else None
    }

    override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] = Sync[F].delay {
      Option.when(selector.`match`(certificate))(certificate)
    }
  }

  def fromIdentityLookup[F[_] : Monad](identityLookup: IdentityLookup[F]): CertLookup[F] = new CertLookup[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def certificateByAlias(alias: String): F[Option[X509Certificate]] =
      identityLookup.identityByAlias(alias).map(_.map(_.certificate))

    override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] =
      identityLookup.identityBySelector(selector).map(_.map(_.certificate))
  }

  def fromKeyStore[F[_] : Sync](keyStore: KeyStore): CertLookup[F] = new CertLookup[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def certificateByAlias(alias: String): F[Option[X509Certificate]] = Sync[F].delay {
      keyStore.getCertificate(alias) match {
        case x509Certificate: X509Certificate => Some(x509Certificate)
        case _ => None
      }
    }

    override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] = Sync[F].delay {
      keyStore.aliases().asScala
        .flatMap(alias => keyStore.getCertificate(alias) match {
          case x509Certificate: X509Certificate if selector.`match`(x509Certificate) => Some(x509Certificate)
          case _ => None
        })
        .nextOption()
    }
  }
}
