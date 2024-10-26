lazy val scalaVersions = Seq("3.4.3", "2.13.14")

ThisBuild / scalaVersion := scalaVersions.head
ThisBuild / versionScheme := Some("early-semver")
ThisBuild / organization := "de.bitmarck.bms"
name := (core.projectRefs.head / name).value

val V = new {
  val betterMonadicFor = "0.3.1"
  val bouncyCastle = "1.78.1"
  val catsEffect = "3.5.4"
  val fs2 = "3.11.0"
  val logbackClassic = "1.5.12"
  val munit = "0.7.29"
  val munitTaglessFinal = "0.3.0"
  val seconTool = "1.2.0"
}

lazy val commonSettings: SettingsDefinition = Def.settings(
  version := {
    val Tag = "refs/tags/v?([0-9]+(?:\\.[0-9]+)+(?:[+-].*)?)".r
    sys.env.get("CI_VERSION").collect { case Tag(tag) => tag }
      .getOrElse("0.0.1-SNAPSHOT")
  },

  licenses += License.Apache2,

  homepage := scmInfo.value.map(_.browseUrl),
  scmInfo := Some(
    ScmInfo(
      url("https://github.com/bitmarck-service/fs2-secon"),
      "scm:git@github.com:bitmarck-service/fs2-secon.git"
    )
  ),
  developers := List(
    Developer(id = "u016595", name = "Pierre Kisters", email = "pierre.kisters@bitmarck.de", url = url("https://github.com/lhns/"))
  ),

  libraryDependencies ++= Seq(
    "ch.qos.logback" % "logback-classic" % V.logbackClassic % Test,
    "de.lhns" %% "munit-tagless-final" % V.munitTaglessFinal % Test,
    "org.scalameta" %% "munit" % V.munit % Test,
  ),

  testFrameworks += new TestFramework("munit.Framework"),

  libraryDependencies ++= virtualAxes.?.value.getOrElse(Seq.empty).collectFirst {
    case VirtualAxis.ScalaVersionAxis(version, _) if version.startsWith("2.") =>
      compilerPlugin("com.olegpy" %% "better-monadic-for" % V.betterMonadicFor)
  },

  Compile / doc / sources := Seq.empty,

  publishMavenStyle := true,

  publishTo := sonatypePublishToBundle.value,

  sonatypeCredentialHost := "oss.sonatype.org",

  credentials ++= (for {
    username <- sys.env.get("SONATYPE_USERNAME")
    password <- sys.env.get("SONATYPE_PASSWORD")
  } yield Credentials(
    "Sonatype Nexus Repository Manager",
    sonatypeCredentialHost.value,
    username,
    password
  )).toList
)

lazy val root: Project =
  project
    .in(file("."))
    .settings(commonSettings)
    .settings(
      publishArtifact := false,
      publish / skip := true
    )
    .aggregate(core.projectRefs: _*)
    .aggregate(javaImpl.projectRefs: _*)

lazy val core = projectMatrix.in(file("core"))
  .settings(commonSettings)
  .settings(
    name := "fs2-secon",
    libraryDependencies ++= Seq(
      "co.fs2" %% "fs2-io" % V.fs2,
      "org.bouncycastle" % "bcpkix-jdk18on" % V.bouncyCastle,
      "org.typelevel" %% "cats-effect" % V.catsEffect,
    ),
  )
  .jvmPlatform(scalaVersions)

lazy val javaImpl = projectMatrix.in(file("javaimpl"))
  .dependsOn(core)
  .settings(commonSettings)
  .settings(
    name := "fs2-secon-javaimpl",
    libraryDependencies ++= Seq(
      "de.tk.opensource" % "secon-tool" % V.seconTool exclude("org.bouncycastle", "bcpkix-jdk15on"),
    ),
    licenses += ("LGPL-3.0", url("https://www.gnu.org/licenses/lgpl-3.0-standalone.html")),
  )
  .jvmPlatform(scalaVersions)
