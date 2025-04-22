package de.bitmarck.bms.secon.fs2.secontool

import de.tk.opensource.secon.{Subscriber, Verifier => SeconVerifier}

import java.io.{InputStream, OutputStream}
import java.lang.reflect.InvocationTargetException
import java.security.cert.X509Certificate
import java.util.concurrent.Callable

object Unsafe {
  private lazy val defaultSubscriberClass = Class.forName("de.tk.opensource.secon.DefaultSubscriber")

  private lazy val signMethod = {
    val method = defaultSubscriberClass.getDeclaredMethod("sign", classOf[OutputStream])
    method.setAccessible(true)
    method
  }

  private[secontool] def sign(subscriber: Subscriber, out: OutputStream): OutputStream =
    try {
      signMethod.invoke(subscriber, out).asInstanceOf[OutputStream]
    } catch {
      case invocationTargetException: InvocationTargetException =>
        throw invocationTargetException.getCause
    }

  private lazy val verifyMethod = {
    val method = defaultSubscriberClass.getDeclaredMethod("verify", classOf[InputStream], classOf[SeconVerifier])
    method.setAccessible(true)
    method
  }

  private[secontool] def verify(subscriber: Subscriber, in: InputStream, verifier: SeconVerifier): InputStream =
    try {
      verifyMethod.invoke(subscriber, in, verifier).asInstanceOf[InputStream]
    } catch {
      case invocationTargetException: InvocationTargetException =>
        throw invocationTargetException.getCause
    }

  private lazy val encryptMethod = {
    val method = defaultSubscriberClass.getDeclaredMethod("encrypt", classOf[OutputStream], classOf[Array[Callable[X509Certificate]]])
    method.setAccessible(true)
    method
  }

  private[secontool] def encrypt(subscriber: Subscriber, out: OutputStream, recipients: Array[Callable[X509Certificate]]): OutputStream =
    try {
      encryptMethod.invoke(subscriber, out, recipients).asInstanceOf[OutputStream]
    } catch {
      case invocationTargetException: InvocationTargetException =>
        throw invocationTargetException.getCause
    }

  private lazy val decryptMethod = {
    val method = defaultSubscriberClass.getDeclaredMethod("decrypt", classOf[InputStream])
    method.setAccessible(true)
    method
  }

  private[secontool] def decrypt(subscriber: Subscriber, in: InputStream): InputStream =
    try {
      decryptMethod.invoke(subscriber, in).asInstanceOf[InputStream]
    } catch {
      case invocationTargetException: InvocationTargetException =>
        throw invocationTargetException.getCause
    }
}
