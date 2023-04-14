package de.bitmarck.bms.secon.fs2

import cats.data.NonEmptyList
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import fs2.{Chunk, Stream}

import scala.util.Random

class RoundTrip extends CatsEffectSuite {
  implicit val signEncrypt: SignEncrypt[IO] = SignEncrypt.make[IO]()
  implicit val decryptVerify: DecryptVerify[IO] = DecryptVerify.make[IO]()
  val keyStore = fs2.io.readClassLoaderResource[IO]("keystore.p12").through(loadKeyStore("secret".toCharArray)).compile.lastOrError.unsafeRunSync()
  val certLookup = CertLookup.fromKeyStore[IO](keyStore)
  val identityLookup = IdentityLookup.fromKeyStore[IO](keyStore, "secret".toCharArray)
  val alice = "alice_rsa_256"
  val bob = "bob_rsa_256"
  val carol = "carol_rsa_256"
  val aliceId = identityLookup.identityByAliasUnsafe(alice).unsafeRunSync()
  val bobId = identityLookup.identityByAliasUnsafe(bob).unsafeRunSync()
  val carolId = identityLookup.identityByAliasUnsafe(carol).unsafeRunSync()

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
