package de.bitmarck.bms.secon.fs2

import de.tk.opensource.secon.{Identity => SeconIdentity}

import java.security.PrivateKey
import java.security.cert.X509Certificate

case class Identity(
                     privateKey: PrivateKey,
                     certificate: X509Certificate
                   )

object Identity {
  private[fs2] def toSeconIdentity(identity: Identity): SeconIdentity = new SeconIdentity {
    override def privateKey(): PrivateKey = identity.privateKey

    override def certificate(): X509Certificate = identity.certificate
  }
}
