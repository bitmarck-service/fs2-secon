package de.bitmarck.bms.secon.fs2

import cats.Monad
import cats.data.NonEmptyList
import cats.syntax.traverse._
import fs2.{Pipe, Stream}

import java.security.cert.X509Certificate

trait SignEncrypt[F[_]] extends Sign[F] with Encrypt[F] {
  protected def monadF: Monad[F]

  def signAndEncrypt(
                      identity: Identity,
                      recipients: NonEmptyList[X509Certificate]
                    ): Pipe[F, Byte, Byte] =
    _.through(sign(identity))
      .through(encrypt(recipients))

  final def signAndEncrypt(
                            identity: Identity,
                            certLookup: CertAliasLookup[F],
                            recipientAliases: NonEmptyList[String]
                          ): Pipe[F, Byte, Byte] = { stream =>
    implicit val implicitMonadF: Monad[F] = monadF
    Stream.eval(recipientAliases.map(certLookup.certificateByAliasUnsafe).sequence).flatMap { recipients =>
      signAndEncrypt(identity, recipients)(stream)
    }
  }
}

object SignEncrypt {
  def apply[F[_]](implicit signEncrypt: SignEncrypt[F]): SignEncrypt[F] = signEncrypt
}
