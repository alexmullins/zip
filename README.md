# Go `archive/zip` plus encryption support

[![GoDoc](https://godoc.org/github.com/hillu/go-archive-zip-crypto?status.svg)](https://godoc.org/github.com/hillu/go-archive-zip-crypto)
[![Go Report Card](https://goreportcard.com/badge/github.com/hillu/go-archive-zip-crypto)](https://goreportcard.com/report/github.com/hillu/go-archive-zip-crypto)

This is a fork of the `archive/zip` package from the Go standard
library which adds support for both the legacy
(insecure) ZIP encryption scheme and for newer AES-based encryption
schemes introduced with WinZip. It is based on Go 1.14.

This is based on work by [Alex Mullins](https://github.com/alexmullins/zip) and
[Yakub Kristianto](https://github.com/yeka/zip). The forward-port was done to
introduce bugfixes and enhancements, such as missing support for large
(>= 4GB) ZIP files like those distributed by [VirusShare](https://virusshare.com/).
