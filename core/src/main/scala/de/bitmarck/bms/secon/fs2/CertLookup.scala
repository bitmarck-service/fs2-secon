package de.bitmarck.bms.secon.fs2

import cats.data.OptionT
import cats.effect.Sync
import cats.syntax.functor._
import cats.{Applicative, Monad, Monoid}
import fs2.Stream

import java.security.KeyStore
import java.security.cert.{X509CertSelector, X509Certificate}
import scala.jdk.CollectionConverters._

trait CertLookup[F[_]] extends CertAliasLookup[F] with CertSelectorLookup[F]

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

  def fromIdentityLookup[F[_] : Monad](identityLookup: IdentityLookup[F]): CertLookup[F] = new CertLookup[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def certificateByAlias(alias: String): F[Option[X509Certificate]] =
      identityLookup.identityByAlias(alias).map(_.map(_.certificate))

    override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] =
      identityLookup.identityBySelector(selector).map(_.map(_.certificate))
  }

  def fromCertificate[F[_] : Sync](
                                    certificate: X509Certificate,
                                    matchesAlias: String => Boolean = _ => false
                                  ): CertLookup[F] with CertList[F] = new CertLookup[F] with CertList[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def certificateByAlias(alias: String): F[Option[X509Certificate]] = Sync[F].delay {
      if (matchesAlias(alias)) Some(certificate)
      else None
    }

    override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] = Sync[F].delay {
      Option.when(selector.`match`(certificate))(certificate)
    }

    override def certificates: Stream[F, X509Certificate] =
      Stream.emit(certificate)
  }

  def fromKeyStore[F[_] : Sync](keyStore: KeyStore): CertLookup[F] with CertList[F] = new CertLookup[F] with CertList[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def certificateByAlias(alias: String): F[Option[X509Certificate]] = Sync[F].delay {
      keyStore.getCertificate(alias) match {
        case x509Certificate: X509Certificate => Some(x509Certificate)
        case _ => None
      }
    }

    override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] = Sync[F].delay {
      keyStore.aliases().asScala
        .flatMap { alias =>
          keyStore.getCertificate(alias) match {
            case x509Certificate: X509Certificate if selector.`match`(x509Certificate) => Some(x509Certificate)
            case _ => None
          }
        }
        .nextOption()
    }

    override def certificates: Stream[F, X509Certificate] =
      Stream.fromIterator[F](keyStore.aliases().asScala, 16)
        .flatMap { alias =>
          Stream.fromOption[F] {
            keyStore.getCertificate(alias) match {
              case x509Certificate: X509Certificate => Some(x509Certificate)
              case _ => None
            }
          }
        }
  }
}
