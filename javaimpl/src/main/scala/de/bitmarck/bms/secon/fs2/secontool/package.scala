package de.bitmarck.bms.secon.fs2

import cats.effect.std.Dispatcher
import cats.syntax.either._
import de.tk.opensource.secon.{CertificateVerificationException, Directory => SeconDirectory, Identity => SeconIdentity, Verifier => SeconVerifier}

import java.security.PrivateKey
import java.security.cert.{X509CertSelector, X509Certificate}
import java.util.Optional
import scala.jdk.OptionConverters._

package object secontool {
  private[secontool] val dummySeconIdentity = new SeconIdentity {
    override def privateKey(): PrivateKey =
      throw new UnsupportedOperationException()

    override def certificate(): X509Certificate =
      throw new UnsupportedOperationException()
  }

  private[secontool] def toSeconIdentity(identity: Identity): SeconIdentity = new SeconIdentity {
    override def privateKey(): PrivateKey = identity.privateKey

    override def certificate(): X509Certificate = identity.certificate
  }

  private[secontool] def toSeconIdentity[F[_]](
                                     identityLookup: IdentitySelectorLookup[F],
                                     dispatcher: Dispatcher[F]
                                   ): SeconIdentity = new SeconIdentity {
    override def privateKey(): PrivateKey = throw new UnsupportedOperationException()

    override def certificate(): X509Certificate = throw new UnsupportedOperationException()

    override def privateKey(selector: X509CertSelector): Optional[PrivateKey] =
      dispatcher.unsafeRunSync(identityLookup.identityBySelector(selector)).map(_.privateKey).toJava
  }

  private[secontool] val dummySeconDirectory = new SeconDirectory {
    override def certificate(selector: X509CertSelector): Optional[X509Certificate] =
      throw new UnsupportedOperationException()

    override def certificate(identifier: String): Optional[X509Certificate] =
      throw new UnsupportedOperationException()

    override def issuer(cert: X509Certificate): Optional[X509Certificate] =
      throw new UnsupportedOperationException()
  }

  private[secontool] def toSeconDirectory[F[_]](
                                      certLookup: CertSelectorLookup[F],
                                      dispatcher: Dispatcher[F]
                                    ): SeconDirectory = new SeconDirectory {
    override def certificate(selector: X509CertSelector): Optional[X509Certificate] =
      dispatcher.unsafeRunSync(certLookup.certificateBySelector(selector)).toJava

    override def issuer(cert: X509Certificate): Optional[X509Certificate] =
      certificate(CertSelectors.issuerOf(cert))

    override def certificate(identifier: String): Optional[X509Certificate] =
      throw new UnsupportedOperationException()
  }

  private[secontool] def toSeconVerifier[F[_]](verifier: Verifier[F], dispatcher: Dispatcher[F]): SeconVerifier = new SeconVerifier {
    override def verify(cert: X509Certificate): Unit =
      dispatcher.unsafeRunSync(verifier.verify(cert))
        .valueOr(msg => throw new CertificateVerificationException(msg))
  }

}
