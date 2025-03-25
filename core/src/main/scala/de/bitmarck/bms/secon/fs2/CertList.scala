package de.bitmarck.bms.secon.fs2

import cats.{Monad, Monoid}
import fs2.Stream

import java.security.cert.X509Certificate

trait CertList[F[_]] {
  def certificates: Stream[F, X509Certificate]
}

object CertList {
  implicit def monoid[F[_]]: Monoid[CertList[F]] = Monoid.instance(
    new CertList[F] {
      override def certificates: Stream[F, X509Certificate] = Stream.empty
    },
    (a, b) => new CertList[F] {
      override def certificates: Stream[F, X509Certificate] =
        a.certificates ++
          b.certificates
    }
  )

  def fromIdentityList[F[_] : Monad](identityList: IdentityList[F]): CertList[F] = new CertList[F] {
    override def certificates: Stream[F, X509Certificate] =
      identityList.identities.map(_.certificate)

  }
}
