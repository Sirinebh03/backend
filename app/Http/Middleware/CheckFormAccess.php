<?php
// app/Http/Middleware/CheckFormAccess.php

namespace App\Http\Middleware;


use Closure;
use Illuminate\Http\Request;
use App\Models\Form;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
class CheckFormAccess
{
    public function handle(Request $request, Closure $next, $formId)
    {
        $user = $request->attributes->get('keycloak_user');
        
        if (!$user || !isset($user['sub'])) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        $form = Form::findOrFail($formId);
        $requiredRole = 'form_' . Str::slug($form->name, '_');

        // Vérifier si l'utilisateur a le rôle requis
        $token = $request->bearerToken();
        $hasAccess = $this->checkUserHasRole($token, $user['sub'], $requiredRole);

        if (!$hasAccess) {
            return response()->json(['message' => 'Access denied to this form'], 403);
        }

        return $next($request);
    }
private function checkUserHasRole($token, $userId, $roleName)
{
    $clientId = config('services.keycloak.client_id');
    $url = config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/users/'.$userId.'/role-mappings/clients/'.$clientId;

    $response = Http::withHeaders([
        'Authorization' => 'Bearer ' . $token,
        'Accept' => 'application/json'
    ])->get($url);

    if (!$response->successful()) {
        Log::error('Failed to check user roles', [
            'status' => $response->status(),
            'response' => $response->body()
        ]);
        return false;
    }

    $roles = $response->json();
    return collect($roles)->contains('name', $roleName);
}
}