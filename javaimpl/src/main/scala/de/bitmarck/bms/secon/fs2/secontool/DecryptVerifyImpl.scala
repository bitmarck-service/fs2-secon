package de.bitmarck.bms.secon.fs2.secontool

import cats.Monad
import cats.effect.Async
import cats.effect.std.Dispatcher
import de.bitmarck.bms.secon.fs2._
import de.tk.opensource.secon.SECON
import fs2.io.{readInputStream, toInputStream}
import fs2.{Pipe, Stream}

import java.io.BufferedInputStream

object DecryptVerifyImpl {
  def make[F[_] : Async](chunkSize: Int = 1024 * 64): DecryptVerify[F] = new DecryptVerify[F] {
    protected def monadF: Monad[F] = Monad[F]

    override def decrypt(identityLookup: IdentityLookup[F]): Pipe[F, Byte, Byte] = { stream =>
      Stream.resource(Dispatcher.sequential[F]).flatMap { dispatcher =>
        val subscriber = SECON.subscriber(
          toSeconIdentity(identityLookup, dispatcher),
          dummySeconDirectory
        )
        stream
          .through(toInputStream[F]).map(new BufferedInputStream(_, chunkSize))
          .flatMap { input =>
            readInputStream(Async[F].blocking(
              Unsafe.decrypt(
                subscriber,
                input
              )
            ), chunkSize)
          }
      }
    }

    override def verify(certLookup: CertLookup[F], verifier: Verifier[F]): Pipe[F, Byte, Byte] = { stream =>
      Stream.resource(Dispatcher.sequential[F]).flatMap { dispatcher =>
        val subscriber = SECON.subscriber(
          dummySeconIdentity,
          toSeconDirectory(certLookup, dispatcher)
        )
        stream
          .through(toInputStream[F]).map(new BufferedInputStream(_, chunkSize))
          .flatMap { input =>
            readInputStream(Async[F].blocking(
              Unsafe.verify(
                subscriber,
                input,
                toSeconVerifier(verifier, dispatcher)
              )
            ), chunkSize)
          }
      }
    }

    override def decryptAndVerify(
                                   identityLookup: IdentityLookup[F],
                                   certLookup: CertLookup[F],
                                   verifier: Verifier[F]
                                 ): Pipe[F, Byte, Byte] = { stream =>
      Stream.resource(Dispatcher.sequential[F]).flatMap { dispatcher =>
        val subscriber = SECON.subscriber(
          toSeconIdentity(identityLookup, dispatcher),
          toSeconDirectory(certLookup, dispatcher)
        )
        stream
          .through(toInputStream[F]).map(new BufferedInputStream(_, chunkSize))
          .flatMap { input =>
            readInputStream(Async[F].blocking(
              subscriber.decryptAndVerifyFrom(
                () => input,
                toSeconVerifier(verifier, dispatcher)
              ).call()
            ), chunkSize)
          }
      }
    }
  }
}
