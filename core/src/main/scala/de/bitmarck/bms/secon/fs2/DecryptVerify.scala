package de.bitmarck.bms.secon.fs2

import cats.Monad
import cats.effect.Async
import cats.effect.std.Dispatcher
import de.tk.opensource.secon.SECON
import fs2.io._
import fs2.{Pipe, Stream}

import java.io.BufferedInputStream

trait DecryptVerify[F[_]] {
  protected def monadF: Monad[F]

  //def decrypt(identityLookup: IdentityLookup[F]): fs2.Pipe[F, Byte, Byte]

  //def verify(certLookup: CertLookup[F], verifier: Verifier[F] = noopVerifier): fs2.Pipe[F, Byte, Byte]

  def decryptAndVerify(
                        identityLookup: IdentityLookup[F],
                        certLookup: CertLookup[F],
                        verifier: Verifier[F] = Verifier.monoid[F](monadF).empty
                      ): fs2.Pipe[F, Byte, Byte]
  /*_.through(decrypt(identityLookup))
    .through(verify(certLookup, verifier))*/
}

object DecryptVerify {
  def apply[F[_]](implicit decryptVerify: DecryptVerify[F]): DecryptVerify[F] = decryptVerify

  def make[F[_] : Async](chunkSize: Int = 1024 * 64): DecryptVerify[F] = new DecryptVerify[F] {
    protected def monadF: Monad[F] = Monad[F]

    override def decryptAndVerify(
                                   identityLookup: IdentityLookup[F],
                                   certLookup: CertLookup[F],
                                   verifier: Verifier[F]
                                 ): Pipe[F, Byte, Byte] = { stream =>
      Stream.resource(Dispatcher.sequential[F]).flatMap { dispatcher =>
        val subscriber = SECON.subscriber(
          IdentityLookup.toSeconIdentity(identityLookup, dispatcher),
          CertLookup.toSeconDirectory(certLookup, dispatcher)
        )
        stream
          .through(toInputStream[F]).map(new BufferedInputStream(_, chunkSize))
          .flatMap { input =>
            readInputStream(Async[F].blocking(
              subscriber.decryptAndVerifyFrom(
                () => input,
                Verifier.toSeconVerifier(verifier, dispatcher)
              ).call()
            ), chunkSize)
          }
      }
    }
  }
}
