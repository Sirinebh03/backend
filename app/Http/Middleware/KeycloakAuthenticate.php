<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Firebase\JWT\Key;

class KeycloakAuthenticate
{
    public function handle(Request $request, Closure $next)
{
    $token = $request->bearerToken();

    if (!$token) {
        Log::error('No token provided');
        return response()->json(['message' => 'Unauthorized - No token provided'], 401);
    }

    try {
        $realm = env('KEYCLOAK_REALM');
        $baseUrl = rtrim(env('KEYCLOAK_BASE_URL'), '/');
        $jwksUrl = "$baseUrl/realms/$realm/protocol/openid-connect/certs";

        Log::info("Attempting to fetch JWKS from: $jwksUrl");

        $response = Http::get($jwksUrl);

        if (!$response->successful()) {
            Log::error('Failed to fetch JWKS', [
                'status' => $response->status(),
                'body' => $response->body()
            ]);
            throw new \Exception("Failed to fetch JWKS from Keycloak. Status: " . $response->status());
        }

        $jwks = $response->json();
        Log::debug('JWKS response', ['jwks' => $jwks]);

        if (!isset($jwks['keys'])) {
            Log::error('Invalid JWKS format', ['jwks' => $jwks]);
            throw new \Exception("Invalid JWKS format from Keycloak");
        }

        $keys = JWK::parseKeySet($jwks);
        Log::debug('Parsed keys', ['keys' => array_keys($keys)]);

        // Décoder le token
        $decoded = JWT::decode($token, $keys);

        $request->attributes->set('keycloak_user', (array) $decoded);

        return $next($request);

    } catch (\Exception $e) {
        Log::error('Keycloak auth error', [
            'message' => $e->getMessage(),
            'token' => $token, // Attention: ne pas faire ça en production avec des vrais tokens
            'trace' => $e->getTraceAsString()
        ]);
        return response()->json([
            'message' => 'Unauthorized - Invalid token',
            'error' => $e->getMessage()
        ], 401);
    }
}
}
