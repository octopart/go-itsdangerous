[![license](http://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](https://github.com/iromli/go-itsdangerous/blob/master/LICENSE)
[![Codeship Status](https://img.shields.io/codeship/886e3e40-82aa-0132-cd65-72ed2dde02fa.svg?style=flat-square&label=codeship)](https://codeship.com/projects/57917)

go-itsdangerous
===============

Like [itsdangerous](https://pythonhosted.org/itsdangerous/) but for Go.


# Updates for 2016

Forked from https://github.com/iromli/go-itsdangerous,
and updated to work with latest version of itsdangerous,
specifically the flask secure cookie defaults (URLSafeTimedSerializer):

* Removed EPOCH (see https://github.com/pallets/itsdangerous/issues/46)
* Added zlib compression / decompression (see [comment](https://github.com/pallets/itsdangerous/blob/ce5e2cd0afebadb5dd732ee1c151824a0de8b5d4/itsdangerous.py#L845-L848))
* Added helper functions `SignB64`, `UnsignB64` for ease of use with the `URLSafeTimedSerializer` / `URLSafeSerializer`

Also:

* Replaced use of `string` with `[]byte` to avoid casting back and forth
