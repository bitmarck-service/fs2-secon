package de.bitmarck.bms.secon.fs2.secontool

import cats.Monad
import cats.data.NonEmptyList
import cats.effect.Async
import de.bitmarck.bms.secon.fs2.{Identity, SignEncrypt}
import de.tk.opensource.secon.SECON
import fs2.Pipe
import fs2.io._

import java.security.cert.X509Certificate
import java.util.concurrent.Callable

object SignEncryptImpl {
  def make[F[_] : Async](chunkSize: Int = 1024 * 64): SignEncrypt[F] = new SignEncrypt[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def sign(identity: Identity): Pipe[F, Byte, Byte] = { stream =>
      val subscriber = SECON.subscriber(
        toSeconIdentity(identity),
        dummySeconDirectory
      )
      readOutputStream(chunkSize) { output =>
        stream
          .through(writeOutputStream(Async[F].blocking(
            Unsafe.sign(
              subscriber,
              output
            )
          )))
          .compile
          .drain
      }
    }

    override def encrypt(recipients: NonEmptyList[X509Certificate]): Pipe[F, Byte, Byte] = { stream =>
      val subscriber = SECON.subscriber(
        dummySeconIdentity,
        dummySeconDirectory
      )
      readOutputStream(chunkSize) { output =>
        stream
          .through(writeOutputStream(Async[F].blocking(
            Unsafe.encrypt(
              subscriber,
              output,
              recipients.iterator.map[Callable[X509Certificate]](e => () => e).toArray
            )
          )))
          .compile
          .drain
      }
    }

    override def signAndEncrypt(
                                 identity: Identity,
                                 recipients: NonEmptyList[X509Certificate]
                               ): Pipe[F, Byte, Byte] = { stream =>
      val subscriber = SECON.subscriber(
        toSeconIdentity(identity),
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
