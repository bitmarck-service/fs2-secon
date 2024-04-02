package de.bitmarck.bms.secon.fs2

import java.security.PrivateKey
import java.security.cert.X509Certificate

case class Identity(
                     privateKey: PrivateKey,
                     certificate: X509Certificate
                   )
