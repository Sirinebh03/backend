<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class AuthController extends Controller
{
    protected $provider;

    public function __construct()
    {
        $this->provider = new Keycloak([
            'authServerUrl' => config('services.keycloak.base_url'),
            'realm' => config('services.keycloak.realm'),
            'clientId' => config('services.keycloak.client_id'),
            'clientSecret' => config('services.keycloak.client_secret'),
            'redirectUri' => config('services.keycloak.redirect'),
        ]);
    }

    // Endpoint de déconnexion API
    public function logoutApi(Request $request)
    {
        $token = $request->user()->token();
        $token->revoke();
        
        // Optionnel : invalider le token Keycloak
        $logoutUrl = $this->provider->getLogoutUrl([
            'redirect_uri' => config('app.url'),
            'id_token_hint' => $request->user()->id_token // Si vous stockez l'id_token
        ]);
        
        return response()->json([
            'message' => 'Déconnexion réussie',
            'logout_url' => $logoutUrl // Le frontend peut rediriger vers cette URL
        ]);
    }

    // Pour les sessions web
    public function logoutWeb(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        
        $logoutUrl = $this->provider->getLogoutUrl([
            'redirect_uri' => config('app.url')
        ]);
        
        return redirect($logoutUrl);
    }
}
