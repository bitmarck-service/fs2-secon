package de.bitmarck.bms.secon

import _root_.fs2.io._
import _root_.fs2.{Pipe, Stream}
import cats.effect.Async

import java.security.KeyStore
import java.util

package object fs2 {
  def loadKeyStore[F[_] : Async](
                                  password: => Array[Char],
                                  keyStoreType: String = "PKCS12"
                                ): Pipe[F, Byte, KeyStore] = { stream =>
    stream
      .through(toInputStream[F])
      .flatMap(input => Stream.eval(Async[F].blocking {
        val keyStore = KeyStore.getInstance(keyStoreType)
        val pw = password
        keyStore.load(input, pw)
        util.Arrays.fill(password, 0.toChar)
        keyStore
      }))
  }
}
