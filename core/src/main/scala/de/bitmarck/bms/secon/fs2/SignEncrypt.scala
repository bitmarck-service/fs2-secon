package de.bitmarck.bms.secon.fs2

import cats.Monad
import cats.data.NonEmptyList
import cats.effect.Async
import cats.syntax.traverse._
import de.tk.opensource.secon.{SECON, Directory => SeconDirectory}
import fs2.io._
import fs2.{Pipe, Stream}

import java.security.cert.{X509CertSelector, X509Certificate}
import java.util.Optional

trait SignEncrypt[F[_]] {
  protected def monadF: Monad[F]

  //def sign(identity: Identity): Pipe[F, Byte, Byte]

  //def encrypt(recipients: NonEmptyList[X509Certificate]): Pipe[F, Byte, Byte]

  def signAndEncrypt(
                      identity: Identity,
                      recipients: NonEmptyList[X509Certificate]
                    ): fs2.Pipe[F, Byte, Byte]
  /*_.through(sign(identity))
    .through(encrypt(recipients))*/

  final def signAndEncrypt(
                            identity: Identity,
                            certLookup: CertLookup[F],
                            recipientAliases: NonEmptyList[String]
                          ): fs2.Pipe[F, Byte, Byte] = { stream =>
    implicit val implicitMonadF: Monad[F] = monadF
    Stream.eval(recipientAliases.map(certLookup.certificateByAliasUnsafe).sequence).flatMap { recipients =>
      signAndEncrypt(identity, recipients)(stream)
    }
  }
}

object SignEncrypt {
  def apply[F[_]](implicit signEncrypt: SignEncrypt[F]): SignEncrypt[F] = signEncrypt

  private val dummySeconDirectory = new SeconDirectory {
    override def certificate(selector: X509CertSelector): Optional[X509Certificate] =
      throw new UnsupportedOperationException()

    override def certificate(identifier: String): Optional[X509Certificate] =
      throw new UnsupportedOperationException()

    override def issuer(cert: X509Certificate): Optional[X509Certificate] =
      throw new UnsupportedOperationException()
  }

  def make[F[_] : Async](chunkSize: Int = 1024 * 64): SignEncrypt[F] = {
    new SignEncrypt[F] {
      override protected def monadF: Monad[F] = Monad[F]

      override def signAndEncrypt(
                                   identity: Identity,
                                   recipients: NonEmptyList[X509Certificate]
                                 ): Pipe[F, Byte, Byte] = { stream =>
        val subscriber = SECON.subscriber(
          Identity.toSeconIdentity(identity),
          dummySeconDirectory
        )
        readOutputStream(chunkSize) { output =>
          stream
            .through(writeOutputStream(Async[F].blocking(
              subscriber.signAndEncryptTo(
                () => output,
                recipients.head,
                recipients.tail: _*
              ).call()
            )))
            .compile
            .drain
        }
      }
    }
  }
}
