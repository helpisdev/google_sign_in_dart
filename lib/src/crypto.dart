// Copyright (C) Hellenic Progressive Internet Services, Inc.
// All Rights Reserved. 2022.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Proprietary and confidential.
// Written by Elias Kapareliotis <helpis@tutamail.com>.

// File created by
// Lung Razvan <long1eu>
// on 02/03/2020

part of '../google_sign_in_dartio.dart';

const String _charset =
    '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._';

/// Generates a random code verifier string using the provided entropy source
/// and the specified length.
///
/// See "Proof Key for Code Exchange by OAuth Public Clients (RFC 7636)
/// <https://tools.ietf.org/html/rfc7636>"
String _generateSecureRandomString([
  Random? entropySource,
  final int entropyBytes = 64,
]) {
  entropySource ??= Random.secure();

  final StringBuffer buffer = StringBuffer();
  int remainingLength = entropyBytes;
  while (remainingLength > 0) {
    final int i = entropySource.nextInt(_charset.length);
    buffer.write(_charset[i]);
    remainingLength = entropyBytes - buffer.length;
  }

  return buffer.toString();
}

/// Produces a code challenge as a Base64URL (with no padding) encoded SHA256
/// hash of the code verifier.
String _deriveCodeVerifierChallenge(final String codeVerifier) => base64Url
    .encode(sha256.convert(ascii.encode(codeVerifier)).bytes)
    .replaceAll('=', '');
