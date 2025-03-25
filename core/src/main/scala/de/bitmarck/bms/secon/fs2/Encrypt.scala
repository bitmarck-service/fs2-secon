package de.bitmarck.bms.secon.fs2

import cats.data.NonEmptyList
import fs2.Pipe

import java.security.cert.X509Certificate

trait Encrypt[F[_]] {
  def encrypt(recipients: NonEmptyList[X509Certificate]): Pipe[F, Byte, Byte]
}
