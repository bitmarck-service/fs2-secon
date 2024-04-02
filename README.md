# fs2-secon

[![build](https://github.com/bitmarck-service/fs2-secon/actions/workflows/build.yml/badge.svg)](https://github.com/bitmarck-service/fs2-secon/actions/workflows/build.yml)
[![Release Notes](https://img.shields.io/github/release/bitmarck-service/fs2-secon.svg?maxAge=3600)](https://github.com/bitmarck-service/fs2-secon/releases/latest)
[![Maven Central](https://img.shields.io/maven-central/v/de.bitmarck.bms/fs2-secon_2.13)](https://search.maven.org/artifact/de.bitmarck.bms/fs2-secon_2.13)
[![Apache License 2.0](https://img.shields.io/github/license/bitmarck-service/fs2-secon.svg?maxAge=3600)](https://www.apache.org/licenses/LICENSE-2.0)

["Verschlüsselung nach GKV Datenaustausch" (SECON)](https://gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security_Schnittstelle.pdf) for [Fs2](https://fs2.io/) using [DieTechniker/secon-tool](https://github.com/DieTechniker/secon-tool).

## Usage

### build.sbt

```sbt
libraryDependencies += "de.bitmarck.bms" %% "fs2-secon" % "0.2.1"
```

## License

This project uses the Apache 2.0 License. See the file called LICENSE.

The module fs2-secon-javaimpl uses GNU Lesser General Public License. See the file called javaimpl/LICENSE.
