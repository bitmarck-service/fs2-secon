package de.bitmarck.bms.secon.fs2

import cats.Monad
import cats.data.NonEmptyList
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import de.bitmarck.bms.secon.fs2.secontool.{DecryptVerifyImpl, SignEncryptImpl}
import fs2.io.file.{Files, Path}
import fs2.{Chunk, Pipe, Stream}

import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import scala.concurrent.duration.{Duration, FiniteDuration}
import scala.util.Random

class RoundTrip extends CatsEffectSuite {
  implicit val signEncrypt: SignEncrypt[IO] = SignEncryptImpl.make[IO]()
  implicit val decryptVerify: DecryptVerify[IO] = DecryptVerifyImpl.make[IO]()
  val keyStore = fs2.io.readClassLoaderResource[IO]("keystore.p12").through(loadKeyStore("secret".toCharArray)).compile.lastOrError.unsafeRunSync()
  val certLookup = CertLookup.fromKeyStore[IO](keyStore)
  val identityLookup = IdentityLookup.fromKeyStore[IO](keyStore, "secret".toCharArray)
  val alice = "alice_rsa_256"
  val bob = "bob_rsa_256"
  val carol = "carol_rsa_256"
  val aliceId = identityLookup.identityByAliasUnsafe(alice).unsafeRunSync()
  val bobId = identityLookup.identityByAliasUnsafe(bob).unsafeRunSync()
  val carolId = identityLookup.identityByAliasUnsafe(carol).unsafeRunSync()

  override def munitTimeout: Duration = new FiniteDuration(120, TimeUnit.SECONDS)

  test("round trip") {
    val string = "Hello World"
    Stream.emit(string)
      .covary[IO]
      .through(fs2.text.utf8.encode)
      .through(SignEncrypt[IO].signAndEncrypt(aliceId, NonEmptyList.one(bobId.certificate)))
      .prefetch
      .through(DecryptVerify[IO].decryptAndVerify(identityLookup, certLookup))
      .through(fs2.text.utf8.decode)
      .compile
      .string
      .map { result =>
        assertEquals(result, string)
      }
  }

  test("round trip 2") {
    val string = "Hello World"
    Stream.emit(string)
      .covary[IO]
      .through(fs2.text.utf8.encode)
      .through(SignEncrypt[IO].signAndEncrypt(aliceId, certLookup, NonEmptyList.one(bob)))
      .prefetch
      .through(DecryptVerify[IO].decryptAndVerify(IdentityLookup.fromIdentity(bobId), CertLookup.fromCertificate(aliceId.certificate)))
      .through(fs2.text.utf8.decode)
      .compile
      .string
      .map { result =>
        assertEquals(result, string)
      }
  }

  test("round trip with wrong recipient".fail) {
    val string = "Hello World"
    Stream.emit(string)
      .covary[IO]
      .through(fs2.text.utf8.encode)
      .through(SignEncrypt[IO].signAndEncrypt(aliceId, NonEmptyList.one(bobId.certificate)))
      .prefetch
      .through(DecryptVerify[IO].decryptAndVerify(IdentityLookup.fromIdentity(bobId), CertLookup.fromCertificate(bobId.certificate)))
      .through(fs2.text.utf8.decode)
      .compile
      .string
      .map { result =>
        assertEquals(result, string)
      }
  }

  test("round trip with wrong recipient 2".fail) {
    val string = "Hello World"
    Stream.emit(string)
      .covary[IO]
      .through(fs2.text.utf8.encode)
      .through(SignEncrypt[IO].signAndEncrypt(aliceId, NonEmptyList.one(bobId.certificate)))
      .prefetch
      .through(DecryptVerify[IO].decryptAndVerify(IdentityLookup.fromIdentity(aliceId), CertLookup.fromCertificate(aliceId.certificate)))
      .through(fs2.text.utf8.decode)
      .compile
      .string
      .map { result =>
        assertEquals(result, string)
      }
  }

  test("round trip with unknown recipient".fail) {
    val string = "Hello World"
    Stream.emit(string)
      .covary[IO]
      .through(fs2.text.utf8.encode)
      .through(SignEncrypt[IO].signAndEncrypt(aliceId, certLookup, NonEmptyList.one("unknown")))
      .prefetch
      .through(DecryptVerify[IO].decryptAndVerify(identityLookup, certLookup))
      .through(fs2.text.utf8.decode)
      .compile
      .string
      .map { result =>
        assertEquals(result, string)
      }
  }

  private def signEncryptUnsafe[F[_] : Monad](signEncrypt: SignEncrypt[F]) = new SignEncrypt[F] {
    override protected def monadF: Monad[F] = implicitly[Monad[F]]

    override def sign(identity: Identity): Pipe[F, Byte, Byte] =
      signEncrypt.sign(identity)

    override def encrypt(recipients: NonEmptyList[X509Certificate]): Pipe[F, Byte, Byte] =
      signEncrypt.encrypt(recipients)
  }

  private def decryptVerifyUnsafe[F[_] : Monad](decryptVerify: DecryptVerify[F]) = new DecryptVerify[F] {
    override protected def monadF: Monad[F] = implicitly[Monad[F]]

    override def decrypt(identityLookup: IdentityLookup[F]): Pipe[F, Byte, Byte] =
      decryptVerify.decrypt(identityLookup)

    override def verify(certLookup: CertLookup[F], verifier: Verifier[F]): Pipe[F, Byte, Byte] =
      decryptVerify.verify(certLookup, verifier)
  }

  test("round trip unsafe signEncrypt") {
    val string = "Hello World"

    Stream.emit(string)
      .covary[IO]
      .through(fs2.text.utf8.encode)
      .through(signEncryptUnsafe(SignEncrypt[IO]).signAndEncrypt(aliceId, NonEmptyList.one(bobId.certificate)))
      .prefetch
      .through(DecryptVerify[IO].decryptAndVerify(identityLookup, certLookup))
      .through(fs2.text.utf8.decode)
      .compile
      .string
      .map { result =>
        assertEquals(result, string)
      }
  }

  test("round trip unsafe decryptVerify") {
    val string = "Hello World"

    Stream.emit(string)
      .covary[IO]
      .through(fs2.text.utf8.encode)
      .through(SignEncrypt[IO].signAndEncrypt(aliceId, NonEmptyList.one(bobId.certificate)))
      .prefetch
      .through(decryptVerifyUnsafe(DecryptVerify[IO]).decryptAndVerify(identityLookup, certLookup))
      .through(fs2.text.utf8.decode)
      .compile
      .string
      .map { result =>
        assertEquals(result, string)
      }
  }

  test("binary") {
    val bytes = Chunk.array(Random.nextBytes(200_000_000))
    val time = System.currentTimeMillis()
    Stream.chunk(bytes)
      .covary[IO]
      .through(SignEncrypt[IO].signAndEncrypt(aliceId, certLookup, NonEmptyList.one(bob)))
      .prefetchN(10)
      .through(DecryptVerify[IO].decryptAndVerify(identityLookup, certLookup))
      .chunkAll
      .compile
      .lastOrError
      .map { result =>
        val diff = System.currentTimeMillis() - time
        println(s"${diff / 1000.0} sec, ${(bytes.size / diff) / 1000.0} MB/s")
        assertEquals(result.toByteVector.sha1, bytes.toByteVector.sha1)
      }
  }
}
