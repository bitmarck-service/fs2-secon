package de.bitmarck.bms.secon.fs2

import cats.{Monad, Monoid}
import fs2.Stream

trait IdentityList[F[_]] {
  def identities: Stream[F, Identity]
}

object IdentityList {
  implicit def monoid[F[_] : Monad]: Monoid[IdentityList[F]] = Monoid.instance(
    new IdentityList[F] {
      override def identities: Stream[F, Identity] = Stream.empty
    },
    (a, b) => new IdentityList[F] {
      override def identities: Stream[F, Identity] =
        a.identities ++ b.identities
    }
  )
}
