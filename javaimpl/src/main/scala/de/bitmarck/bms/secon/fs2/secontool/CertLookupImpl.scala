package de.bitmarck.bms.secon.fs2.secontool

import cats.Monad
import cats.effect.{Resource, Sync}
import de.bitmarck.bms.secon.fs2.CertLookup
import de.tk.opensource.secon.{SECON, Directory => SeconDirectory}

import java.net.URI
import java.security.cert.{X509CertSelector, X509Certificate}
import java.util
import javax.naming.Context
import javax.naming.directory.{DirContext, InitialDirContext}
import scala.jdk.OptionConverters._

object CertLookupImpl {
  private def fromSeconDirectory[F[_] : Sync](seconDirectory: SeconDirectory): CertLookup[F] = new CertLookup[F] {
    override protected def monadF: Monad[F] = Monad[F]

    override def certificateByAlias(alias: String): F[Option[X509Certificate]] = Sync[F].blocking {
      seconDirectory.certificate(alias).toScala
    }

    override def certificateBySelector(selector: X509CertSelector): F[Option[X509Certificate]] = Sync[F].blocking {
      seconDirectory.certificate(selector).toScala
    }
  }

  def fromLdap[F[_] : Sync](dirContext: => DirContext): Resource[F, CertLookup[F]] =
    Resource.make(
      Sync[F].blocking(dirContext)
    )(dirContext =>
      Sync[F].blocking(dirContext.close())
    ).map(dirContext =>
      fromSeconDirectory[F](SECON.directory(() => dirContext))
    )

  def fromLdapUri[F[_] : Sync](
                                ldapUri: URI,
                                configure: util.Hashtable[String, String] => Unit = _ => ()
                              ): Resource[F, CertLookup[F]] = {
    val env = new util.Hashtable[String, String]
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, ldapUri.toString)
    env.put("com.sun.jndi.ldap.connect.pool", "true")
    configure(env)
    fromLdap[F](new InitialDirContext(env))
  }
}
