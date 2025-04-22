package de.bitmarck.bms.secon.fs2.secontool

import cats.Monad
import cats.effect.std.Dispatcher
import cats.effect.{Async, Deferred}
import cats.syntax.all._
import de.bitmarck.bms.secon.fs2.Decrypt.DecryptInfo
import de.bitmarck.bms.secon.fs2.Verify.VerifyInfo
import de.bitmarck.bms.secon.fs2._
import de.tk.opensource.secon.SECON
import fs2.io.{readInputStream, toInputStream}
import fs2.{Pipe, Stream}

import java.io.BufferedInputStream
import java.security.cert.{X509CertSelector, X509Certificate}

object DecryptVerifyImpl {
  def make[F[_] : Async](dispatcher: Dispatcher[F], chunkSize: Int = 1024 * 64): DecryptVerify[F] = new DecryptVerify[F] {
    protected def monadF: Monad[F] = Monad[F]

    private def identityLookupWithDecryptInfo(
                                               identityLookup: IdentitySelectorLookup[F]
                                             ): (IdentitySelectorLookup[F], F[DecryptInfo]) = {
      val deferred = Deferred.unsafe[F, DecryptInfo]
      (new IdentitySelectorLookup[F] {
        override protected def monadF: Monad[F] = Async[F]

        override def identityBySelector(selector: X509CertSelector): F[Option[Identity]] =
          identityLookup.identityBySelector(selector).flatTap {
            case Some(identity) => deferred.complete(DecryptInfo(identity)).void
            case None => Async[F].unit
          }
      }, deferred.get)
    }

    private def certLookupWithVerifyInfo(
                                          certLookup: CertSelectorLookup[F]
                                        ): (CertSelectorLookup[F], F[VerifyInfo]) = {
      val deferred = Deferred.unsafe[F, VerifyInfo]
      (new CertSelectorLookup[F] {
        override protected def monadF: Monad[F] = Async[F]

        override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] =
          certLookup.certificateBySelector(selector).flatTap {
            case Some(signerCert) => deferred.complete(VerifyInfo(signerCert)).void
            case None => Async[F].unit
          }
      }, deferred.get)
    }

    override def decryptWithInfo(
                                  identityLookup: IdentitySelectorLookup[F]
                                ): Stream[F, Byte] => (Stream[F, Byte], F[DecryptInfo]) = {
      stream =>
        val (newIndentityLookup, decryptInfo) = identityLookupWithDecryptInfo(identityLookup)

        (
          stream.through(decrypt(newIndentityLookup)),
          decryptInfo
        )
    }

    override def decrypt(identityLookup: IdentitySelectorLookup[F]): Pipe[F, Byte, Byte] = { stream =>
      Stream.eval(Async[F].delay {
        SECON.subscriber(
          toSeconIdentity(identityLookup, dispatcher),
          dummySeconDirectory
        )
      }).flatMap { subscriber =>
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

    override def verifyWithInfo(
                                 signerCertLookup: CertSelectorLookup[F],
                                 verifier: Verifier[F]
                               ): Stream[F, Byte] => (Stream[F, Byte], F[VerifyInfo]) = {
      stream =>
        val (newSignerCertLookup, verifyInfo) = certLookupWithVerifyInfo(signerCertLookup)

        (
          stream.through(verify(
            newSignerCertLookup,
            verifier
          )),
          verifyInfo
        )
    }

    override def verify(signerCertLookup: CertSelectorLookup[F], verifier: Verifier[F]): Pipe[F, Byte, Byte] = { stream =>
      Stream.eval(Async[F].delay {
        SECON.subscriber(
          dummySeconIdentity,
          toSeconDirectory(signerCertLookup, dispatcher)
        )
      }).flatMap { subscriber =>
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

    override def decryptAndVerifyWithInfo(
                                           identityLookup: IdentitySelectorLookup[F],
                                           signerCertLookup: CertSelectorLookup[F],
                                           verifier: Verifier[F]
                                         ): Stream[F, Byte] => (Stream[F, Byte], F[DecryptInfo], F[VerifyInfo]) = {
      stream =>
        val (newIndentityLookup, decryptInfo) = identityLookupWithDecryptInfo(identityLookup)
        val (newSignerCertLookup, verifyInfo) = certLookupWithVerifyInfo(signerCertLookup)

        (
          stream.through(decryptAndVerify(
            newIndentityLookup,
            newSignerCertLookup,
            verifier
          )),
          decryptInfo,
          verifyInfo
        )
    }

    override def decryptAndVerify(
                                   identityLookup: IdentitySelectorLookup[F],
                                   certLookup: CertSelectorLookup[F],
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
