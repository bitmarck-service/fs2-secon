package de.bitmarck.bms.secon.fs2

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cms.{KeyTransRecipientId, SignerId}

import java.security.cert.{X509CertSelector, X509Certificate}
import javax.security.auth.x500.X500Principal

object CertSelectors {
  def subject(principal: X500Principal): X509CertSelector = {
    val selector = new X509CertSelector()
    selector.setSubject(principal)
    selector
  }

  def issuerOf(certificate: X509Certificate): X509CertSelector =
    subject(certificate.getIssuerX500Principal)

  private def principal(name: X500Name): X500Principal =
    new X500Principal(name.getEncoded)

  def keyTransRecipientId(recipientId: KeyTransRecipientId): X509CertSelector = {
    val selector = new X509CertSelector()
    Option(recipientId.getIssuer).foreach(issuer => selector.setIssuer(principal(issuer)))
    selector.setSerialNumber(recipientId.getSerialNumber)
    selector.setSubjectKeyIdentifier(recipientId.getSubjectKeyIdentifier)
    selector
  }

  def signerId(signerId: SignerId): X509CertSelector = {
    val selector = new X509CertSelector()
    Option(signerId.getIssuer).foreach(issuer => selector.setIssuer(principal(issuer)))
    selector.setSerialNumber(signerId.getSerialNumber)
    selector.setSubjectKeyIdentifier(signerId.getSubjectKeyIdentifier)
    selector
  }

  def cert(certificate: X509Certificate): X509CertSelector = {
    val selector = new X509CertSelector()
    selector.setSerialNumber(certificate.getSerialNumber)
    selector.setSubject(certificate.getSubjectX500Principal)
    selector.setIssuer(certificate.getIssuerX500Principal)
    selector
  }
}
