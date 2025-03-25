package de.bitmarck.bms.secon.fs2

import cats.data.OptionT
import cats.effect.Sync
import cats.{Applicative, Monad, Monoid}

import java.security.cert.{X509CertSelector, X509Certificate}
import java.security.{KeyStore, PrivateKey}
import java.util
import scala.jdk.CollectionConverters._

trait IdentityLookup[F[_]] extends IdentityAliasLookup[F] with IdentitySelectorLookup[F] {
  override def filterByAlias(f: String => Boolean): IdentityLookup[F] = {
    val filteredAliasLookup = super.filterByAlias(f)
    new IdentityLookup[F] {
      override protected def monadF: Monad[F] = IdentityLookup.this.monadF

      override def identityByAlias(alias: String): F[Option[Identity]] =
        filteredAliasLookup.identityByAlias(alias)

      override def identityBySelector(selector: X509CertSelector): F[Option[Identity]] =
        IdentityLookup.this.identityBySelector(selector)
    }
  }
}

object IdentityLookup {
  implicit def monoid[F[_] : Monad]: Monoid[IdentityLookup[F]] = Monoid.instance(
    new IdentityLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def identityByAlias(alias: String): F[Option[Identity]] = Applicative[F].pure(None)

      override def identityBySelector(selector: X509CertSelector): F[Option[Identity]] = Applicative[F].pure(None)
    },
    (a, b) => new IdentityLookup[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def identityByAlias(alias: String): F[Option[Identity]] =
        OptionT(a.identityByAlias(alias))
          .orElseF(b.identityByAlias(alias))
          .value

      override def identityBySelector(selector: X509CertSelector): F[Option[Identity]] =
        OptionT(a.identityBySelector(selector))
          .orElseF(b.identityBySelector(selector))
          .value
    }
  )

  def fromIdentity[F[_] : Sync](
                                 identity: Identity,
                                 expectedAlias: Option[String] = None
                               ): IdentityLookup[F] = new IdentityLookup[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def identityByAlias(alias: String): F[Option[Identity]] = Sync[F].delay {
      if (expectedAlias.forall(_ == alias)) Some(identity)
      else None
    }

    override def identityBySelector(selector: X509CertSelector): F[Option[Identity]] = Sync[F].delay {
      Option.when(selector.`match`(identity.certificate))(identity)
    }
  }

  def fromKeyStore[F[_] : Sync](keyStore: KeyStore, password: => Array[Char]): IdentityLookup[F] = new IdentityLookup[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def identityByAlias(alias: String): F[Option[Identity]] = Sync[F].delay {
      val pw = password
      val entry = try {
        keyStore.getEntry(alias, new KeyStore.PasswordProtection(pw))
      } finally {
        util.Arrays.fill(pw, 0.toChar)
      }

      entry match {
        case privateKeyEntry: KeyStore.PrivateKeyEntry =>
          privateKeyEntry.getCertificate match {
            case x509Certificate: X509Certificate => Some(Identity(
              privateKeyEntry.getPrivateKey,
              x509Certificate
            ))
            case _ => None
          }
        case _ => None
      }
    }

    override def identityBySelector(selector: X509CertSelector): F[Option[Identity]] = Sync[F].delay {
      keyStore.aliases().asScala
        .flatMap(alias => keyStore.getCertificate(alias) match {
          case x509Certificate: X509Certificate if selector.`match`(x509Certificate) =>
            val pw = password
            val key = try {
              keyStore.getKey(alias, pw)
            } finally {
              util.Arrays.fill(pw, 0.toChar)
            }

            key match {
              case privateKey: PrivateKey => Some(Identity(
                privateKey,
                x509Certificate
              ))
              case _ => None
            }
          case _ => None
        })
        .nextOption()
    }
  }
}
