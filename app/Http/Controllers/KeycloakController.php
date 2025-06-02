<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
    use Illuminate\Support\Str;

class KeycloakController extends Controller
{
    public function getAvailableRoles()
    {
        try {
            $token = $this->getAdminToken();
            $clientId = $this->getClientId($token);
            
            $url = config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/clients/'.$clientId.'/roles';
            
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $token,
                'Content-Type' => 'application/json'
            ])->get($url);

            if ($response->successful()) {
                return $response->json();
            }

            throw new \Exception('Failed to get roles: '.$response->body());
            
        } catch (\Exception $e) {
            Log::error('Failed to get roles', ['error' => $e->getMessage()]);
            return [];
        }
    }


public function getFormUser($userId)
{
    \Log::info("Début de récupération des formulaires accessibles par l'utilisateur", ['userId' => $userId]);

    try {
        // 1. Obtenir l'utilisateur depuis Keycloak via la méthode existante
        $response = $this->getUser($userId);
        $data = $response->getData(true);

        if (!isset($data['form_roles']) || !is_array($data['form_roles'])) {
            return response()->json(['forms' => []]);
        }

        $userRoles = $data['form_roles'];

        // 2. Récupérer tous les formulaires disponibles dans la base
        $forms = \App\Models\Form::all();
        $accessibleForms = [];

        foreach ($forms as $form) {
            $expectedRole = 'form_' . Str::slug($form->name, '_');

            if (in_array($expectedRole, $userRoles)) {
                $accessibleForms[] = [
                    'id' => $form->id,
                    'name' => $form->name,
                    'created_at' => $form->created_at,
                    // Ajoute d'autres champs si nécessaire
                ];
            }
        }

        \Log::info("Formulaires accessibles récupérés avec succès", [
            'userId' => $userId,
            'form_count' => count($accessibleForms)
        ]);

        return response()->json(['forms' => $accessibleForms]);

    } catch (\Exception $e) {
        \Log::error("Erreur lors de la récupération des formulaires de l'utilisateur", [
            'userId' => $userId,
            'error' => $e->getMessage()
        ]);

        return response()->json([
            'error' => 'Failed to retrieve forms for user',
            'message' => $e->getMessage(),
        ], 500);
    }
}

public function getUser($userId)
{
    \Log::info("Début de la récupération de l'utilisateur Keycloak", ['userId' => $userId]);

    try {
        // 1. Get Keycloak configuration
        $keycloakBaseUrl = config('services.keycloak.base_url');
        $realm = config('services.keycloak.realm');
        $clientId = config('services.keycloak.backend_client_id');
        $clientSecret = config('services.keycloak.backend_client_secret');
        
        \Log::debug("Configuration Keycloak récupérée", [
            'base_url' => $keycloakBaseUrl,
            'realm' => $realm,
            'client_id' => $clientId,
            'client_secret' => !empty($clientSecret) ? '***'.substr($clientSecret, -4) : null,
        ]);

        if (empty($keycloakBaseUrl) || empty($realm) || empty($clientId) || empty($clientSecret)) {
            $missing = [];
            empty($keycloakBaseUrl) && $missing[] = 'base_url';
            empty($realm) && $missing[] = 'realm';
            empty($clientId) && $missing[] = 'client_id';
            empty($clientSecret) && $missing[] = 'client_secret';
            
            $errorMsg = 'Configuration Keycloak incomplète. Paramètres manquants: '.implode(', ', $missing);
            \Log::error($errorMsg);
            throw new \Exception($errorMsg);
        }

        // 2. Get admin access token
        $tokenUrl = "$keycloakBaseUrl/realms/$realm/protocol/openid-connect/token";
        \Log::debug("Tentative d'obtention du token admin", ['url' => $tokenUrl]);
        
        $tokenResponse = Http::asForm()->post($tokenUrl, [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ]);

        \Log::debug("Réponse de l'endpoint token", [
            'status' => $tokenResponse->status(),
            'body' => $tokenResponse->successful() ? '***' : $tokenResponse->body()
        ]);

        if (!$tokenResponse->successful()) {
            $errorMsg = 'Échec de récupération du token admin: '.$tokenResponse->body();
            \Log::error($errorMsg, [
                'status' => $tokenResponse->status(),
                'headers' => $tokenResponse->headers(),
            ]);
            throw new \Exception($errorMsg);
        }

        $accessToken = $tokenResponse->json('access_token');
        \Log::debug("Token admin obtenu avec succès", ['token' => '***'.substr($accessToken, -10)]);

        // 3. Get user details from Keycloak
        $userUrl = "$keycloakBaseUrl/admin/realms/$realm/users/$userId";
        \Log::debug("Tentative de récupération des détails utilisateur", ['url' => $userUrl]);

        $userResponse = Http::withHeaders([
            'Authorization' => "Bearer $accessToken",
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
        ])->get($userUrl);

        \Log::debug("Réponse des détails utilisateur", [
            'status' => $userResponse->status(),
            'body' => $userResponse->successful() ? '***' : $userResponse->body()
        ]);

        if ($userResponse->status() === 404) {
            \Log::warning("Utilisateur non trouvé dans Keycloak", ['userId' => $userId]);
            return response()->json(['error' => 'User not found'], 404);
        }

        if (!$userResponse->successful()) {
            $errorMsg = 'Échec de récupération des détails utilisateur: '.$userResponse->body();
            \Log::error($errorMsg, [
                'status' => $userResponse->status(),
                'headers' => $userResponse->headers(),
            ]);
            throw new \Exception($errorMsg);
        }

        $userData = $userResponse->json();
        \Log::debug("Détails utilisateur obtenus", ['userData' => array_keys($userData)]);

        // 4. Get client-level roles for laravel client
        $formRoles = [];
        
        // First get laravel client ID
        $clientsUrl = "$keycloakBaseUrl/admin/realms/$realm/clients";
        $clientsResponse = Http::withHeaders([
            'Authorization' => "Bearer $accessToken",
            'Accept' => 'application/json',
        ])->get($clientsUrl, ['clientId' => 'laravel']);

        if ($clientsResponse->successful() && !empty($clientsResponse->json())) {
            $laravelClient = $clientsResponse->json()[0];
            $laravelClientId = $laravelClient['id'];
            
            // Get role mappings for this client
            $clientRolesUrl = "$keycloakBaseUrl/admin/realms/$realm/users/$userId/role-mappings/clients/$laravelClientId";
            $clientRolesResponse = Http::withHeaders([
                'Authorization' => "Bearer $accessToken",
                'Accept' => 'application/json',
            ])->get($clientRolesUrl);

            if ($clientRolesResponse->successful()) {
                $clientRoles = $clientRolesResponse->json();
                
                // Filter only the roles we want
                foreach ($clientRoles as $role) {
                    if (in_array($role['name'], ['form_maaa', 'form_employe'])) {
                        $formRoles[] = $role['name'];
                    }
                }
            }
        }

        // 5. Format the response
        $responseData = [
            'id' => $userData['id'] ?? null,
            'username' => $userData['username'] ?? null,
            'email' => $userData['email'] ?? null,
            'firstName' => $userData['firstName'] ?? null,
            'lastName' => $userData['lastName'] ?? null,
            'enabled' => $userData['enabled'] ?? false,
            'emailVerified' => $userData['emailVerified'] ?? false,
            'form_roles' => $formRoles, // Only the specific roles we want
            'attributes' => $userData['attributes'] ?? [],
            'createdAt' => isset($userData['createdTimestamp']) 
                ? date('Y-m-d H:i:s', $userData['createdTimestamp'] / 1000)
                : null,
        ];

        \Log::info("Utilisateur récupéré avec succès", [
            'userId' => $userId,
            'form_roles' => $formRoles
        ]);
        return response()->json($responseData);

    } catch (\Exception $e) {
        \Log::error("Échec critique lors de la récupération de l'utilisateur Keycloak", [
            'userId' => $userId,
            'error' => $e->getMessage(),
            'stackTrace' => $e->getTraceAsString()
        ]);
        
        return response()->json([
            'error' => 'Failed to retrieve user information',
            'message' => $e->getMessage(),
            'request_id' => request()->header('X-Request-ID')
        ], 500);
    }
}
public function countUsers()
{
    try {
        $token = $this->getAdminToken();
        $realm = config('services.keycloak.realm');

        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json'
        ])->get(config('services.keycloak.base_url') . '/admin/realms/' . $realm . '/users', [
            'briefRepresentation' => false,
            'max' => 1000 // tu peux ajuster selon la taille de ton Keycloak
        ]);

        if ($response->successful()) {
         $data = $response->json();
if (is_array($data)) {
    $keys = array_keys($data); // ✅ OK
} else {
    $keys = []; // ou autre logique si tu sais que ce n’est pas un tableau
}


        }

        // Si la requête HTTP a échoué
        throw new \Exception("HTTP error: " . $response->status() . " - " . $response->body());

    } catch (\Exception $e) {
        return response()->json([
            'count' => 0,
            'error' => $e->getMessage()
        ], 500);
    }
}

       public function createUser(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'username' => 'required|string|min:3',
                'email' => 'required|email',
                'firstName' => 'required|string',
                'lastName' => 'required|string',
                'password' => 'required|string|min:8',
                'confirmPassword' => 'required|same:password'
            ]);

            if ($validator->fails()) {
                return response()->json(['errors' => $validator->errors()], 422);
            }

            $validated = $validator->validated();

          //  $token = $this->getAdminToken();
 $token = $request->header('authorization'); // Assuming the token is passed in the request
              $response = Http::withHeaders([
        'Authorization' => $token,
        'Content-Type' => 'application/json',
    ])->post(config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/users', [
        'username' => $validated['username'],
        'email' => $validated['email'],
        'firstName' => $validated['firstName'],
        'lastName' => $validated['lastName'],
        'enabled' => true,
        'emailVerified' => true, 
        'credentials' => [[
            'type' => 'password',
            'value' => $validated['password'],
            'temporary' => false
        ]]
        //         'username' => 'ali',
        // 'email' =>'ali@gmail.com',
        // 'firstName' => 'ali',
        // 'lastName' => 'ali',
        // 'enabled' => true,
        // 'emailVerified' => true, 
        // 'credentials' => [[
        //     'type' => 'password',
        //     'value' => 'ali123',
        //     'temporary' => false
        // ]]
    ]);

            if ($response->successful()) {
                return response()->json(['message' => 'User created successfully'], 201);
            }

            Log::error('Keycloak API error', [
                'status' => $response->status(),
                'response' => $response->body()
            ]);
            throw new \Exception('Keycloak API error: ' . $response->body());

        } catch (\Exception $e) {
            Log::error('Keycloak error: ' . $e->getMessage());
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }

    // In KeycloakController.php
public function checkUsername(Request $request)
{
    try {
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|min:3'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => 'Invalid username'], 400);
        }

        $token = $this->getAdminToken();
        $username = $request->query('username');

        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json',
        ])->get(config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/users', [
            'username' => $username,
            'exact' => 'true'
        ]);

        if ($response->successful()) {
            $users = $response->json();
            return response()->json([
                'available' => count($users) === 0
            ]);
        }

        Log::error('Keycloak username check failed', [
            'status' => $response->status(),
            'response' => $response->body()
        ]);
        
        return response()->json(['error' => 'Failed to check username'], 500);

    } catch (\Exception $e) {
        Log::error('Username check error', ['exception' => $e]);
        return response()->json(['error' => 'Server error'], 500);
    }
}
public function getUsers(Request $request)
{
    try {
        $token = $this->getAdminToken();
        $realm = config('services.keycloak.realm');

        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json'
        ])->get(config('services.keycloak.base_url').'/admin/realms/'.$realm.'/users', [
            'briefRepresentation' => false,
            'max' => 100 // Limite de résultats
        ]);

        if ($response->successful()) {
            return response()->json($response->json());
        }

        // Log détaillé en cas d'erreur
        Log::error('Failed to fetch users from Keycloak', [
            'status' => $response->status(),
            'response' => $response->body(),
            'request_url' => config('services.keycloak.base_url').'/admin/realms/'.$realm.'/users'
        ]);

        return response()->json([
            'error' => 'Failed to fetch users',
            'details' => $response->json()
        ], $response->status());

    } catch (\Exception $e) {
        Log::error('Keycloak getUsers error', [
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ]);
        
        return response()->json([
            'error' => 'Internal server error',
            'message' => $e->getMessage()
        ], 500);
    }
}

    /**
     * Get user's current roles
     */
    public function getUserRoles($userId)
    {
        try {
            $token = $this->getAdminToken();
            $clientId = $this->getClientId($token);
            
            $url = config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/users/'.$userId.'/role-mappings/clients/'.$clientId;
            
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $token,
                'Content-Type' => 'application/json'
            ])->get($url);

            if ($response->successful()) {
                return $response->json();
            }

            throw new \Exception('Failed to get user roles: '.$response->body());
            
        } catch (\Exception $e) {
            Log::error('Failed to get user roles', ['error' => $e->getMessage()]);
            return [];
        }
    }

    /**
     * Assign multiple roles to a user
     */
    public function assignRolesToUser(Request $request, $userId)
    {
        $validator = Validator::make($request->all(), [
            'roles' => 'required|array',
            'roles.*' => 'string'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 400);
        }

        
    try {
        $token = $this->getAdminToken();
        $clientId = $this->getClientId($token);
        $roles = $request->input('roles');
        
        // Get role objects
        $roleObjects = [];
        foreach ($roles as $roleName) {
            $roleResponse = Http::withHeaders([
                'Authorization' => 'Bearer ' . $token
            ])->get(config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/clients/'.$clientId.'/roles/'.$roleName);

            if (!$roleResponse->successful()) {
                return response()->json(['error' => "Role $roleName not found"], 404);
            }
            
            $role = $roleResponse->json();
            unset($role['attributes']);
            if ($role['containerId'] !== $clientId) {
                Log::error('Client ID mismatch', [
                    'roleContainerId' => $role['containerId'],
                    'requestClientId' => $clientId
                ]);
                return response()->json(['error' => 'Client ID mismatch for role'], 400);
            }
            
            $roleObjects[] = $role;
        }

        Log::debug('Attempting role assignment', [
            'url' => config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/users/'.$userId.'/role-mappings/clients/'.$clientId,
            'payload' => $roleObjects
        ]);

        $assignResponse = Http::withHeaders([
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json'
        ])->post(
            config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/users/'.$userId.'/role-mappings/clients/'.$clientId,
            $roleObjects
        );

        if ($assignResponse->successful()) {
            return response()->json(['message' => 'Roles assigned successfully']);
        }

        // Enhanced error logging
        Log::error('Keycloak role assignment failed', [
            'status' => $assignResponse->status(),
            'response' => $assignResponse->body(),
            'headers' => $assignResponse->headers(),
            'payload' => $roleObjects
        ]);
        
        return response()->json([
            'error' => 'Role assignment failed',
            'details' => $assignResponse->json()
        ], $assignResponse->status());
        
    } catch (\Exception $e) {
        Log::error('Role assignment error', [
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ]);
        return response()->json(['error' => $e->getMessage()], 500);
    }
}

    /**
     * Revoke multiple roles from a user
     */public function revokeRolesFromUser(Request $request, $userId)
{
    $validator = Validator::make($request->all(), [
        'roles' => 'required|array',
        'roles.*' => 'string'
    ]);

    if ($validator->fails()) {
        return response()->json(['error' => $validator->errors()], 400);
    }

    try {
        $token = $this->getAdminToken();
        $clientId = $this->getClientId($token);
        $roles = $request->input('roles');

        $roleObjects = [];
        foreach ($roles as $roleName) {
            $roleResponse = Http::withHeaders([
                'Authorization' => 'Bearer ' . $token
            ])->get(config('services.keycloak.base_url') . '/admin/realms/' . config('services.keycloak.realm') . '/clients/' . $clientId . '/roles/' . $roleName);

            if (!$roleResponse->successful()) {
                return response()->json(['error' => "Role $roleName not found"], 404);
            }

            $role = $roleResponse->json();

            unset($role['attributes']);

            if ($role['containerId'] !== $clientId) {
                Log::error('Client ID mismatch during role revocation', [
                    'roleContainerId' => $role['containerId'],
                    'requestClientId' => $clientId
                ]);
                return response()->json(['error' => 'Client ID mismatch for role'], 400);
            }

            $roleObjects[] = $role;
        }

        Log::debug('Attempting to revoke roles', [
            'userId' => $userId,
            'clientId' => $clientId,
            'roles' => $roleObjects
        ]);

        $revokeResponse = Http::withHeaders([
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json'
        ])->delete(
            config('services.keycloak.base_url') . '/admin/realms/' . config('services.keycloak.realm') . '/users/' . $userId . '/role-mappings/clients/' . $clientId,
            $roleObjects
        );

        if ($revokeResponse->successful()) {
            return response()->json(['message' => 'Roles revoked successfully']);
        }

        Log::error('Role revocation failed', [
            'status' => $revokeResponse->status(),
            'response' => $revokeResponse->body()
        ]);

        return response()->json([
            'error' => 'Role revocation failed',
            'details' => $revokeResponse->json()
        ], $revokeResponse->status());

    } catch (\Exception $e) {
        Log::error('Role revocation error', [
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ]);
        return response()->json(['error' => $e->getMessage()], 500);
    }
}


    private function getAdminToken()
    {
        try {
            $response = Http::asForm()->post(config('services.keycloak.base_url').'/realms/'.config('services.keycloak.realm').'/protocol/openid-connect/token', [
                'client_id' => config('services.keycloak.backend_client_id'),
                'client_secret' => config('services.keycloak.backend_client_secret'),
                'grant_type' => 'client_credentials',
            ]);

            if ($response->successful()) {
                $token = $response->json()['access_token'];
                Log::debug('Obtained token', ['token' => $token]);
                return $token;
            }

            $errorDetails = $response->json();
            Log::error('Failed to get admin token', [
                'status' => $response->status(),
                'error' => $errorDetails['error'] ?? 'unknown',
                'error_description' => $errorDetails['error_description'] ?? 'No description',
                'response' => $response->body()
            ]);
            
            throw new \Exception('Keycloak error: ' . ($errorDetails['error_description'] ?? $response->status()));
            
        } catch (\Exception $e) {
            Log::error('Keycloak connection failed', ['error' => $e->getMessage()]);
            throw new \Exception('Failed to connect to Keycloak: ' . $e->getMessage());
        }
    }

    public function createRole(string $roleName, string $description = '')
    {
        try {
            // Obtenir le token admin
            $token = $this->getAdminToken();
            Log::debug('Attempting to create role', ['role' => $roleName]);
            
            // Récupérer l'ID du client
            $clientId = $this->getClientId($token);
            Log::debug('Retrieved client ID', ['clientId' => $clientId]);
            
            // Construire l'URL correcte pour la création de rôle
            $url = config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/clients/'.$clientId.'/roles';
            Log::debug('Using URL', ['url' => $url]);

            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $token,
                'Content-Type' => 'application/json'
            ])->post($url, [
                'name' => $roleName,
                'description' => $description,
                'clientRole' => true
            ]);

            Log::debug('Role creation response', [
                'status' => $response->status(),
                'body' => $response->body()
            ]);

            if ($response->successful()) {
                return true;
            }

            throw new \Exception('Role creation failed: '.$response->body());
            
        } catch (\Exception $e) {
            Log::error('Role creation error', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return false;
        }
    }

    private function getClientId(string $token): string
    {
        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $token
        ])->get(config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/clients', [
            'clientId' => config('services.keycloak.backend_client_id') // Utiliser backend_client_id ici
        ]);

        if (!$response->successful()) {
            Log::error('Failed to get clients', [
                'status' => $response->status(),
                'response' => $response->body()
            ]);
            throw new \Exception('Failed to get clients: '.$response->status());
        }

        $clients = $response->json();
        if (count($clients) === 0) {
            throw new \Exception('No client found with ID: '.config('services.keycloak.backend_client_id'));
        }

        return $clients[0]['id'];
    }

   


public function assignRoleToUser($userId, $roleName)
{
    $token = $this->getAdminToken();
    
    // 1. Récupérer le rôle
    $roleResponse = Http::withHeaders([
        'Authorization' => 'Bearer ' . $token
    ])->get(config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/clients/'.config('services.keycloak.client_id').'/roles/'.$roleName);

    if (!$roleResponse->successful()) {
        throw new \Exception('Role not found');
    }

    $role = $roleResponse->json();

    // 2. Assigner le rôle à l'utilisateur
    $assignResponse = Http::withHeaders([
        'Authorization' => 'Bearer ' . $token,
        'Content-Type' => 'application/json'
    ])->post(config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/users/'.$userId.'/role-mappings/clients/'.config('services.keycloak.client_id'), [
        $role
    ]);

    return $assignResponse->successful();
}
public function hasRole(Request $request)
{
    $userId = $request->query('userId');
    $roleName = $request->query('roleName');

    if (!$userId || !$roleName) {
        return response()->json(['hasRole' => false, 'error' => 'Missing parameters'], 400);
    }

    try {
        $token = $this->getAdminToken();
        $clientId = $this->getClientId($token);
        
        $url = config('services.keycloak.base_url') . '/admin/realms/' . config('services.keycloak.realm') . '/users/' . $userId . '/role-mappings/clients/' . $clientId;
        
        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json'
        ])->get($url);

        if ($response->successful()) {
            $roles = $response->json();
            $hasRole = collect($roles)->contains('name', $roleName);
            return response()->json(['hasRole' => $hasRole]);
        }

        throw new \Exception('Failed to get user roles: '.$response->body());

    } catch (\Exception $e) {
        Log::error('Failed to check user role', ['error' => $e->getMessage()]);
        return response()->json(['hasRole' => false, 'error' => $e->getMessage()], 500);
    }
}
public function hasRoles($userId, $roleName)
{
    try {
        $token = $this->getAdminToken();
        $clientId = $this->getClientId($token);
        
        $url = config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/users/'.$userId.'/role-mappings/clients/'.$clientId;
        
        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json'
        ])->get($url);

        if ($response->successful()) {
            $roles = $response->json();
            return collect($roles)->contains('name', $roleName);
        }

        throw new \Exception('Failed to get user roles: '.$response->body());
        
    } catch (\Exception $e) {
        Log::error('Failed to check user role', ['error' => $e->getMessage()]);
        return false;
    }
}
public function revokeRoleFromUser($userId, $roleName)
{
    $token = $this->getAdminToken();
    
    // 1. Récupérer le rôle
    $roleResponse = Http::withHeaders([
        'Authorization' => 'Bearer ' . $token
    ])->get(config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/clients/'.config('services.keycloak.client_id').'/roles/'.$roleName);

    if (!$roleResponse->successful()) {
        throw new \Exception('Role not found');
    }

    $role = $roleResponse->json();

    // 2. Révoquer le rôle de l'utilisateur
    $revokeResponse = Http::withHeaders([
        'Authorization' => 'Bearer ' . $token,
        'Content-Type' => 'application/json'
    ])->delete(config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/users/'.$userId.'/role-mappings/clients/'.config('services.keycloak.client_id'), [
        [$role]
    ]);

    return $revokeResponse->successful();
}
}