package de.bitmarck.bms.secon.fs2

import cats.data.EitherT
import cats.{Applicative, Monad, Monoid}

import java.security.cert.X509Certificate

trait Verifier[F[_]] {
  def verify(certificate: X509Certificate): F[Either[String, Unit]]
}

object Verifier {
  implicit def monoid[F[_] : Monad]: Monoid[Verifier[F]] = Monoid.instance(
    new Verifier[F] {
      override def verify(certificate: X509Certificate): F[Either[String, Unit]] = Applicative[F].pure(Right(()))
    },
    (a, b) => new Verifier[F] {
      override def verify(certificate: X509Certificate): F[Either[String, Unit]] =
        EitherT(a.verify(certificate))
          .flatMapF(_ => b.verify(certificate))
          .value
    }
  )
}
