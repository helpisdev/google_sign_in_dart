// Copyright (C) Hellenic Progressive Internet Services, Inc.
// All Rights Reserved. 2022.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Proprietary and confidential.
// Written by Elias Kapareliotis <helpis@tutamail.com>.

// File created by
// Lung Razvan <long1eu>
// on 02/03/2020

part of '../google_sign_in_dartio.dart';

/// Creates an authentication Uri and listens on the local web server for the
/// authorization response.
///
/// Using this implementation will not provide a refresh token, that means that
/// the user will need to login again after the access token expires (~1 hour)
Future<Map<String, dynamic>> _tokenSignIn({
  required final String clientId,
  required final String scope,
  required final UrlPresenter presenter,
  final String? hostedDomains,
  final String? uid,
  int? port,
  final String? successUrl,
  final String? failUrl,
}) async {
  final Completer<Map<String, dynamic>> completer =
      Completer<Map<String, dynamic>>();

  final String state = _generateSecureRandomString();
  final String nonce = _generateSecureRandomString();
  final String codeVerifier = _generateSecureRandomString();
  final String codeVerifierChallenge =
      _deriveCodeVerifierChallenge(codeVerifier);

  final InternetAddress address = InternetAddress.loopbackIPv4;
  final HttpServer server = await HttpServer.bind(address, port ?? 0);
  port = port ?? server.port;
  server.listen((final HttpRequest request) async {
    final Uri uri = request.requestedUri;

    if (uri.path == '/') {
      return _sendData(request, _verifyFragmentHtml);
    } else if (uri.path == '/response') {
      if (successUrl != null && failUrl != null) {
        await _validateTokenWithCustomScreen(
          request,
          state,
          successUrl,
          failUrl,
        )
            .then(completer.complete)
            .catchError(completer.completeError)
            .whenComplete(server.close);
      } else {
        await _validateTokenResponse(request, state)
            .then(completer.complete)
            .catchError(completer.completeError)
            .whenComplete(server.close);
      }
    } else {
      return _sendData(request, _imageData, 'image/png; base64');
    }
  });

  final Map<String, String> queryParameters = <String, String>{
    'client_id': clientId,
    'redirect_uri': 'http://${address.host}:$port',
    'response_type': 'code token id_token',
    'scope': scope,
    'code_challenge': codeVerifierChallenge,
    'code_challenge_method': 'S256',
    'nonce': nonce,
    'state': state,
    'include_granted_scopes': 'true',
    'prompt': 'select_account',
  };

  if (hostedDomains != null && hostedDomains.isNotEmpty) {
    queryParameters['hd'] = hostedDomains;
  }
  if (uid != null && uid.isNotEmpty) {
    queryParameters['login_hint'] = uid;
  }

  final Uri authenticationUri =
      Uri.https('accounts.google.com', '/o/oauth2/v2/auth', queryParameters);

  presenter(authenticationUri);
  return completer.future.timeout(const Duration(minutes: 1));
}

Future<Map<String, String>> _validateTokenResponse(
  final HttpRequest request,
  final String state,
) async {
  final Map<String, String> authResponse = request.requestedUri.queryParameters;
  final String? returnedState = authResponse['state'];
  final String? accessToken = authResponse['access_token'];
  final String? idToken = authResponse['id_token'];

  String? message;
  if (state != returnedState) {
    message = 'Invalid response from server (state did not match).';
  }
  if (accessToken == null || accessToken.isEmpty) {
    message = 'Invalid response from server (no accessToken transmitted).';
  }
  if (idToken == null || idToken.isEmpty) {
    message = 'Invalid response from server (no idToken transmitted).';
  }

  if (message != null) {
    return _sendErrorAndThrow(request, message);
  } else {
    await _sendData(request, _successHtml);
    return authResponse;
  }
}

Future<Map<String, String>> _validateTokenWithCustomScreen(
  final HttpRequest request,
  final String state,
  final String successUrl,
  final String failUrl,
) async {
  final Map<String, String> authResponse = request.requestedUri.queryParameters;
  final String? returnedState = authResponse['state'];
  final String? accessToken = authResponse['access_token'];
  final String? idToken = authResponse['id_token'];
  if (state != returnedState ||
      accessToken == null ||
      accessToken.isEmpty ||
      idToken == null ||
      idToken.isEmpty) {
    request.response
      ..statusCode = 500
      ..write('');
    await request.response.redirect(Uri.parse(failUrl));
    await launch(failUrl);
  } else {
    request.response
      ..statusCode = 200
      ..write('');
    await request.response.redirect(Uri.parse(successUrl));
  }
  await request.response.close();
  return authResponse;
}
