package de.bitmarck.bms.secon.fs2

import cats.data.EitherT
import cats.effect.std.Dispatcher
import cats.syntax.either._
import cats.{Applicative, Monad, Monoid}
import de.tk.opensource.secon.{CertificateVerificationException, Verifier => SeconVerifier}

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

  private[fs2] def toSeconVerifier[F[_]](verifier: Verifier[F], dispatcher: Dispatcher[F]): SeconVerifier = new SeconVerifier {
    override def verify(cert: X509Certificate): Unit =
      dispatcher.unsafeRunSync(verifier.verify(cert))
        .valueOr(msg => throw new CertificateVerificationException(msg))
  }
}
