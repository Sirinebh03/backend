<?php

namespace App\Http\Controllers;

use App\Models\Form;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Http\Controllers\Controller;
use App\Http\Controllers\KeycloakController;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use App\Notifications\RoleUpdatedNotification;
use Illuminate\Support\Facades\Http;

class FormController extends Controller  
{
    
    

public function index(Request $request)
{
    try {
        $authorizationHeader = $request->header('Authorization');
        if (!$authorizationHeader || !str_starts_with($authorizationHeader, 'Bearer ')) {
            return response()->json(['error' => 'Token not provided'], 401);
        }

        $publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuACz7povdg/9LIf7Ddhq8dEeC/UyBkVKbZBTNyZ6HIeO538P2QzGP/9UkO5wBqRE/ItxV+PP+siC0t49so2RDllqph9MDPm9fMUbjHUbkHePKAph8Eme5kplwlUayyVuzi1VBmVfr1Z6mnoZYhdliRaeORxnza7ZnW5wIt4hdE3C0n0kcHLr8jnKc6X5m1MA5wG/WOkdpYpgQ6sCmw/pYi6WpnmIxicfJ5A+bbfWsdbDbqPumkBI28cgq5WaRY0IEmIVs8avaZ7Cva4nZ2tacmadw9UqEbBSPRHOhe8aOI4dRmU3R3+JPXM2uYVnk7RZfG1vsxYV/M4cpiVmuMj4ywIDAQAB
-----END PUBLIC KEY-----
EOD;

        $jwt = str_replace('Bearer ', '', $authorizationHeader);
        $decoded = JWT::decode($jwt, new Key($publicKey, 'RS256'));
        $payload = json_decode(json_encode($decoded), true);

        // Extraire les rôles depuis le token
        $roles = $payload['resource_access']['laravel']['roles'] ?? [];
        $role= $payload['realm_access']['roles'] ?? [];
        $forms = Form::all();

        // Si l'utilisateur est admin, retourner tous les formulaires
        if (in_array('admin', $role)) {
            return response()->json($forms);
        }

        // Sinon, filtrer selon les rôles
        $filteredForms = $forms->filter(function ($form) use ($roles) {
            $roleName = 'form_' . Str::slug($form->name, '_');
            return in_array($roleName, $roles);
        });

        return response()->json($filteredForms->values());

    } catch (\Exception $e) {
        return response()->json(['error' => $e->getMessage()], 500);
    }
}
    public function store(Request $request)
    {
        // Valider les données de base
        $validator = Validator::make($request->all(), [
            'name' => [
                'required',
                'string',
                'max:255',
                'regex:/^[a-zA-Z0-9_\- ]+$/',
                'not_regex:/[\/\\\\]/'
            ],
            'form_data' => 'required|array',
            'form_data.*.name' => 'required|string',
            'form_data.*.type' => 'required|string',
            'description' => 'nullable|string',
            'files.*' => 'file|max:10240' // 10MB max per file
        ], [
            'name.regex' => 'The name can only contain letters, numbers, spaces, hyphens and underscores',
            'name.not_regex' => 'The name cannot contain slashes'
        ]);
    
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation error',
                'errors' => $validator->errors()
            ], 422);
        }
    
        // Sanitize et valider le nom de la table
        $tableName = $this->sanitizeTableName($request->name);
        if (!$tableName) {
            return response()->json([
                'message' => 'Invalid table name',
                'errors' => ['name' => ['The name contains invalid characters']]
            ], 422);
        }
    
        // Vérifier si la table existe déjà
        if (Schema::hasTable($tableName)) {
            return response()->json([
                'message' => 'Table already exists',
                'errors' => ['name' => ['A table with this name already exists']]
            ], 400);
        }
    
      
    
        try {
            // Traitement des fichiers
            $filePaths = [];
            if ($request->hasFile('files')) {
                foreach ($request->file('files') as $file) {
                    $path = $file->store('public/uploads');
                    $filePaths[] = str_replace('public/', 'storage/', $path);
                }
            }
    
            // Créer le formulaire
            $form = Form::create([
                'name' => $request->name,
                'description' => $request->description,
                'form_data' => json_encode($request->form_data)
            ]);
          // Création du rôle dans Keycloak
    $keycloak = new KeycloakController();
    $roleName = 'form_' . Str::slug($form->name, '_');
    
    if (!$keycloak->createRole($roleName, 'Role for form '.$form->name)) {
        DB::rollBack();
        return response()->json([
            'message' => 'Form created but failed to create Keycloak role',
            'warning' => 'Role creation failed'
        ], 201); // Ou 500 si c'est critique pour vous
    }
            // Créer la table dynamique
            $this->createDynamicTable($tableName, $request->form_data);
    
            // Créer les tables pour les multiselect si nécessaire
            $hasMultiselect = collect($request->form_data)->contains('type', 'multiselect');
            if ($hasMultiselect) {
                $this->createMultiSelectTables($tableName);
            }
    
            DB::commit();
    
            return response()->json([
                'message' => 'Form created successfully',
                'data' => $form
            ], 201);
    
        } catch (\Exception $e) {
            DB::rollBack();
            
            // Supprimer les fichiers uploadés en cas d'erreur
            if (!empty($filePaths)) {
                foreach ($filePaths as $path) {
                    $storagePath = str_replace('storage/', 'public/', $path);
                    Storage::delete($storagePath);
                }
            }
            
            \Log::error('Form creation error: '.$e->getMessage());
            \Log::error('Stack trace: '.$e->getTraceAsString());
            
            return response()->json([
                'message' => 'Error creating form',
                'error' => $e->getMessage(),
                'trace' => config('app.debug') ? $e->getTrace() : null
            ], 500);
        }
    }

    public function getFormsWithPermissions(Request $request)
{
    try {
        $user = $request->attributes->get('keycloak_user');
        $keycloak = new KeycloakController();
        
        $forms = Form::all();
        $user['roles'];
        if ($user && isset($user['roles'])) {
            if (in_array('admin', $user['roles'])) {
                return response()->json($forms);
            }
        }

        
        $filteredForms = $forms->filter(function($form) use ($user, $keycloak) {
            $roleName = 'form_' . Str::slug($form->name, '_');
            return $keycloak->hasRoles($user['sub'] ?? '', $roleName);
        });
        
        return response()->json($filteredForms->values());
        
    } catch (\Exception $e) {
        return response()->json(['error' => $e->getMessage()], 500);
    }
}
 public function update(Request $request, $id)
{
    \Log::info('Update Request Data:', $request->all());

    $validator = Validator::make($request->all(), [
        'name' => [
            'required', 
            'string', 
            'max:255',
            'regex:/^[a-zA-Z0-9_\- ]+$/',
            'not_regex:/[\/\\\\]/'
        ],
        'form_data' => 'required|array',
        'form_data.*.name' => 'required|string',
        'form_data.*.type' => 'required|string',
    ], [
        'name.regex' => 'The name can only contain letters, numbers, spaces, hyphens and underscores',
        'name.not_regex' => 'The name cannot contain slashes'
    ]);

    if ($validator->fails()) {
        return response()->json([
            'message' => 'Validation error',
            'errors' => $validator->errors()
        ], 422);
    }

    $form = Form::findOrFail($id);
    $oldTableName = $this->sanitizeTableName($form->name);
    $newTableName = $this->sanitizeTableName($request->name);
    $oldRoleName = 'form_' . Str::slug($form->name, '_');
    $newRoleName = 'form_' . Str::slug($request->name, '_');

    try {
        DB::beginTransaction();

        // Mettre à jour le formulaire
        $form->update([
            'name' => $request->name,
            'form_data' => json_encode($request->form_data),
            'description' => $request->description ?? null
        ]);

        // Renommer les tables si nécessaire
        if ($oldTableName !== $newTableName) {
            Schema::rename($oldTableName, $newTableName);
            Schema::rename($oldTableName.'_multi_option', $newTableName.'_multi_option');
            Schema::rename($oldTableName.'_multi_value', $newTableName.'_multi_value');
        }

        // Mettre à jour la structure de la table
        $this->updateDynamicTableStructure($newTableName, $request->form_data);

        // Mettre à jour le rôle dans Keycloak si le nom a changé
        if ($oldRoleName !== $newRoleName) {
            $keycloak = new KeycloakController();
            
            // 1. Créer le nouveau rôle
            if (!$keycloak->createRole($newRoleName, 'Role for form '.$request->name)) {
                throw new \Exception('Failed to create new Keycloak role');
            }
            
            // 2. Récupérer tous les utilisateurs ayant l'ancien rôle
            $usersWithRole = $this->getUsersWithRole($oldRoleName);
            
            // 3. Assigner le nouveau rôle et révoquer l'ancien pour chaque utilisateur
            foreach ($usersWithRole as $userId) {
                if (!$keycloak->assignRoleToUser($userId, $newRoleName)) {
                    throw new \Exception("Failed to assign new role to user $userId");
                }
                
                if (!$keycloak->revokeRoleFromUser($userId, $oldRoleName)) {
                    throw new \Exception("Failed to revoke old role from user $userId");
                }
            }
            
            // 4. Supprimer l'ancien rôle
            if (!$keycloak->deleteRole($oldRoleName)) {
                throw new \Exception('Failed to delete old Keycloak role');
            }
        }

        DB::commit();

        return response()->json([
            'message' => 'Form updated successfully',
            'data' => $form
        ]);

    } catch (\Exception $e) {
        DB::rollBack();
        \Log::error('Form update error: '.$e->getMessage());
        return response()->json([
            'message' => 'Error updating form',
            'error' => $e->getMessage()
        ], 500);
    }
}
private function getUsersWithRole($roleName)
{
    try {
        $keycloak = new KeycloakController();
        $token = $keycloak->getAdminToken();
        $clientId = $keycloak->getClientId($token);


        $url = config('services.keycloak.base_url').'/admin/realms/'.config('services.keycloak.realm').'/clients/'.$clientId.'/roles/'.$roleName.'/users';

        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json'
        ])->get($url);

        if ($response->successful()) {
            $users = $response->json();
            return array_column($users, 'id');
        }

        throw new \Exception('Failed to get users with role: '.$response->body());
        
    } catch (\Exception $e) {
        \Log::error('Failed to get users with role: '.$e->getMessage());
        return [];
    }
}

public function handleFileUpload(Request $request)
{
    // Get the first file from the request
    $file = $request->file($request->keys()[0] ?? 'file');
    
    if (!$file) {
        return response()->json([
            'success' => false,
            'message' => 'No file was uploaded'
        ], 422);
    }

    $validator = Validator::make(['file' => $file], [
        'file' => 'required|file|max:10240', // 10MB max
    ]);

    if ($validator->fails()) {
        return response()->json([
            'success' => false,
            'message' => 'Validation error',
            'errors' => $validator->errors()
        ], 422);
    }

    try {
        $path = $file->store('public/uploads');
        $publicPath = str_replace('public/', 'storage/', $path);

        return response()->json([
            'success' => true,
            'filePath' => $publicPath,
            'url' => asset($publicPath)
        ]);
    } catch (\Exception $e) {
        return response()->json([
            'success' => false,
            'message' => 'Upload failed',
            'error' => $e->getMessage()
        ], 500);
    }
}    private function parseFormData($formData)
    {
        if (is_string($formData)) {
            try {
                $formData = json_decode($formData, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                return response()->json([
                    'message' => 'Invalid JSON data',
                    'errors' => ['form_data' => ['The form_data must be a valid JSON string']]
                ], 422);
            }
        }

        if (!is_array($formData)) {
            return response()->json([
                'message' => 'Invalid form data',
                'errors' => ['form_data' => ['The form_data must be an array']]
            ], 422);
        }

        return $formData;
    }

    private function sanitizeTableName(string $name): ?string
    {
        $name = Str::lower(Str::slug($name, '_'));
        return preg_match('/^[a-z][a-z0-9_]*$/', $name) ? $name : null;
    }


    private function sanitizeColumnName(string $name): string
    {
        return Str::lower(Str::slug($name, '_'));
    }
    
    private function createDynamicTable(string $tableName, array $fields)
{
    try {
        // Ne créer la table que si elle n'existe pas
        if (!Schema::hasTable($tableName)) {
            Schema::create($tableName, function ($table) use ($fields, $tableName) {
                $table->increments('id')->unsigned();
                $table->string('user_id')->nullable()->index(); // Pour Keycloak

                foreach ($fields as $field) {
                    if (!isset($field['name']) || !isset($field['type'])) {
                        continue;
                    }

                    $columnName = $this->sanitizeColumnName($field['name']);
                    $type = $field['type'];

                    if ($type === 'multiselect') continue;

                    $columnType = $this->mapFieldTypeToMySQL($type);
                    if ($columnType) {
                        $column = $table->{$columnType}($columnName)->nullable();
                        if ($columnType === 'integer') {
                            $column->unsigned();
                        }
                    }
                }

                $table->timestamps();
                $table->engine = 'InnoDB';
            });
        }

        // Créer les tables annexes uniquement si champ multiselect présent
        $hasMultiselect = collect($fields)->contains('type', 'multiselect');
        if ($hasMultiselect) {
            $this->createMultiSelectTables($tableName);
        }

    } catch (\Exception $e) {
        \Log::error('Table creation error: ' . $e->getMessage());
        throw $e;
    }
}

private function createMultiSelectTables(string $tableName)
{
    $multiOptionTable = $tableName . '_multi_option';
    $multiValueTable = $tableName . '_multi_value';

    if (!Schema::hasTable($multiOptionTable)) {
        Schema::create($multiOptionTable, function ($table) {
            $table->increments('id')->unsigned();
            $table->string('field_name', 255);
            $table->string('option_value', 255);
            $table->unique(['field_name', 'option_value']);
            $table->engine = 'InnoDB';
        });
    }

    if (!Schema::hasTable($multiValueTable)) {
        Schema::create($multiValueTable, function ($table) use ($tableName, $multiOptionTable) {
            $table->integer('entry_id')->unsigned();
            $table->integer('option_id')->unsigned();
            $table->string('field_name', 255);

            $table->foreign('entry_id')
                  ->references('id')
                  ->on($tableName)
                  ->onDelete('cascade');

            $table->foreign('option_id')
                  ->references('id')
                  ->on($multiOptionTable)
                  ->onDelete('cascade');

            $table->primary(['entry_id', 'option_id', 'field_name']);
            $table->engine = 'InnoDB';
        });
    }
}

    private function mapFieldTypeToMySQL(string $fieldType): ?string
    {
        return match ($fieldType) {
            'text', 'email', 'password', 'select', 'radio' => 'string',
            'number' => 'integer',
            'date' => 'date',
            'textarea' => 'text',
            'checkbox' => 'boolean',
            'multiselect' => null,
            'boolean' => 'boolean',
            'file', 'image' => 'string',
            'color' => 'string',
            'range' => 'float',
            'time' => 'time',
            'datetime-local' => 'datetime',
            default => 'string',
        };
    }
    
    public function getFormConfig($id)
    {
        try {
            $form = Form::findOrFail($id);
            $formData = json_decode($form->form_data, true);
            
            if (!is_array($formData)) {
                throw new \Exception('Invalid form data format');
            }
    
            foreach ($formData as &$field) {
                if (!isset($field['type'])) continue;
    
                // Pour les champs avec options statiques
                if (in_array($field['type'], ['select', 'radio', 'checkbox'])) {
                    if (!empty($field['options'])) {
                        $field['options'] = array_map(function($opt) {
                            return is_array($opt) ? $opt : ['value' => $opt, 'label' => $opt];
                        }, (array)$field['options']);
                    }
                }
                
        $tableName = $this->sanitizeTableName($form->name);
        $multiOptionTable = $tableName . '_multi_option';
        $multiValueTable = $tableName . '_multi_value';
        
                // Pour les champs dynamiques
                if (!empty($field['dynamic']) && !empty($field['sourceTable'])) {
                    if (!Schema::hasTable($field['sourceTable'])) {
                        continue;
                    }
    
                    $options = DB::table($field['sourceTable'])
                        ->select([
                            $field['keyColumn'].' as value',
                            $field['valueColumn'].' as label'
                        ])
                        ->when(!empty($field['whereClause']), function($query) use ($field) {
                            $query->whereRaw($field['whereClause']);
                        })
                        ->get()
                        ->toArray();
                    
                    $field['options'] = $options;
                }
                elseif ($field['type'] === 'multiselect') {
                // Vérifier si la table d'options existe
                if (Schema::hasTable($multiOptionTable)) {
                    $options = DB::table($multiOptionTable)
                        ->where('field_name', $field['name'])
                        ->select('option_value as value', 'option_value as label')
                        ->distinct()
                        ->get()
                        ->toArray();
                    
                    $field['options'] = $options;
                } else {
                    $field['options'] = [];
                }
            }
            }
            
            return response()->json($formData);
            
        } catch (\Exception $e) {
            \Log::error('Error getting form config: '.$e->getMessage());
            return response()->json(['message' => 'Error retrieving form configuration'], 500);
        }
    }
      
public function saveFieldOptions(Request $request, $formId)
{
    $form = Form::findOrFail($formId);
    $tableName = strtolower(str_replace(' ', '_', $form->name));
    $optionsTableName = $tableName . '_options';

    $request->validate([
        'field_name' => 'required|string',
        'options' => 'required|array',
        'options.*.key' => 'required|string',
        'options.*.value' => 'required|string',
    ]);

    DB::table($optionsTableName)
        ->where('field_name', $request->field_name)
        ->delete();

    foreach ($request->options as $option) {
        DB::table($optionsTableName)->insert([
            'field_name' => $request->field_name,
            'option_key' => $option['key'],
            'option_value' => $option['value'],
        ]);
    }

    return response()->json(['message' => 'Options sauvegardées avec succès']);
}

    public function addFieldOption(Request $request, $formId, $fieldName)
{
    $form = Form::findOrFail($formId);
    $tableName = strtolower(str_replace(' ', '_', $form->name));
    $optionsTableName = $tableName . '_options';

    $request->validate([
        'key' => 'required|string',
        'value' => 'required|string',
    ]);

    DB::table($optionsTableName)->insert([
        'field_name' => $fieldName,
        'option_key' => $request->key,
        'option_value' => $request->value,
    ]);

    return response()->json(['message' => 'Option ajoutée avec succès']);
}
   

    
    public function show($id)
    {
        $form = Form::findOrFail($id);
        return response()->json($form);
    }
  
    public function getByName(Request $request, $name)
    {
        $form = Form::where('name', $name)->first();
        if (!$form) {
            return response()->json(['message' => 'Form not found'], 404);
        }
        return response()->json($form);
    }
     public function getIdByName($name)
    {
        // Validation basique du paramètre
        if (empty($name)) {
            return response()->json([
                'error' => 'Le nom du formulaire est requis'
            ], 400);
        }

        // Recherche dans la base de données
        $form = Form::where('name', $name)->first();

        if (!$form) {
            return response()->json([
                'error' => 'Formulaire non trouvé'
            ], 404);
        }

        return response()->json([
            'id' => $form->id
        ]);
    }
    private function parseFormDataForUpdate($formData)
    {
        if (is_string($formData)) {
            try {
                $formData = json_decode($formData, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                return response()->json([
                    'message' => 'Invalid JSON data',
                    'errors' => ['form_data' => ['The form_data must be a valid JSON string']]
                ], 422);
            }
        }
    
        if (!is_array($formData)) {
            return response()->json([
                'message' => 'Invalid form data',
                'errors' => ['form_data' => ['The form_data must be an array']]
            ], 422);
        }
    
        return $formData;
    }private function updateDynamicTableStructure(string $tableName, array $fields)
    {
        $existingColumns = Schema::getColumnListing($tableName);
        $columnsToKeep = ['id', 'created_at', 'updated_at', 'user_id'];
        
        $hasMultiselect = false;
    
        foreach ($fields as $field) {
            if (!isset($field['name'], $field['type'])) {
                continue;
            }
    
            $columnName = $this->sanitizeColumnName($field['name']);
            $type = $field['type'];
            
            if ($type === 'multiselect') {
                $hasMultiselect = true;
                continue;
            }
    
            $columnType = $this->mapFieldTypeToMySQL($type);
    
            if ($columnType && !in_array($columnName, $existingColumns)) {
                Schema::table($tableName, function ($table) use ($columnName, $columnType) {
                    $column = $table->{$columnType}($columnName)->nullable();
                    if ($columnType === 'integer') $column->unsigned();
                });
            }
    
            $columnsToKeep[] = $columnName;
        }
    
        // Supprimer les colonnes qui ne sont plus dans le formulaire
        foreach ($existingColumns as $column) {
            if (!in_array($column, $columnsToKeep)) {
                Schema::table($tableName, function ($table) use ($column) {
                    $table->dropColumn($column);
                });
            }
        }
    
        // Gérer les tables multiselect si nécessaire
        if ($hasMultiselect) {
            $this->ensureMultiselectTablesExist($tableName);
        } else {
            // Supprimer les tables multiselect si elles existent mais ne sont plus nécessaires
            $this->dropMultiSelectTablesIfExist($tableName);
        }
    }
    private function dropMultiSelectTablesIfExist(string $tableName)
{
    $optionsTable = $tableName.'_multi_option';
    $valuesTable = $tableName.'_multi_value';
    
    if (Schema::hasTable($valuesTable)) {
        Schema::drop($valuesTable);
    }
    
    if (Schema::hasTable($optionsTable)) {
        Schema::drop($optionsTable);
    }
}
    private function ensureMultiselectTablesExist(string $tableName)
    {
        if (!Schema::hasTable($tableName.'_multi_option')) {
            $this->createMultiSelectTables($tableName);
        }
    }

    public function destroy($id)
    {
        if (!is_numeric($id) || $id <= 0) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid form ID'
            ], 400);
        }
    
        $form = Form::find($id);
    
        if (!$form) {
            return response()->json([
                'success' => false,
                'message' => 'Form not found'
            ], 404);
        }
    
        $tableName = $this->sanitizeTableName($form->name);
        $multiSelectOptionsTable = $tableName . '_multi_option';
        $multiSelectValuesTable = $tableName . '_multi_value';
    
        try {
            // Commencer la transaction
            
    
            // 1. Vérifier les dépendances (optionnel, selon vos besoins)
            $databaseName = config('database.connections.mysql.database');
            $dependencies = DB::select("
                SELECT TABLE_NAME as table_name 
                FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
                WHERE 
                    REFERENCED_TABLE_NAME = ? 
                    AND REFERENCED_TABLE_SCHEMA = ?
                    AND TABLE_NAME NOT LIKE ?
            ", [$tableName, $databaseName, $tableName . '%']);
    
            if (!empty($dependencies)) {
                DB::rollBack();
                return response()->json([
                    'success' => false,
                    'message' => 'Cannot delete: external tables depend on this form.',
                    'dependencies' => $dependencies
                ], 422);
            }
    
            // 2. Supprimer les fichiers associés
            $formData = json_decode($form->form_data, true);
            if (is_array($formData)) {
                foreach ($formData as $field) {
                    if (isset($field['type'], $field['filePath']) && 
                        in_array($field['type'], ['file', 'image']) && 
                        !empty($field['filePath'])) {
                        $path = str_replace('storage/', 'public/', $field['filePath']);
                        if (Storage::exists($path)) {
                            Storage::delete($path);
                        }
                    }
                }
            }
    
            // 3. Supprimer les tables liées dans le bon ordre
            if (Schema::hasTable($multiSelectValuesTable)) {
                Schema::drop($multiSelectValuesTable);
            }
    
            if (Schema::hasTable($multiSelectOptionsTable)) {
                Schema::drop($multiSelectOptionsTable);
            }
    
            if (Schema::hasTable($tableName)) {
                Schema::drop($tableName);
            }
    
            // 4. Supprimer l'enregistrement du formulaire
            $form->delete();
    
            // Valider la transaction
            DB::commit();
    
            return response()->json([
                'success' => true,
                'message' => 'Form deleted successfully'
            ]);
    
        } catch (\Exception $e) {
            // Annuler la transaction en cas d'erreur
            if (DB::transactionLevel() > 0) {
                DB::rollBack();
            }
    
            \Log::error("Error deleting form ID {$id}: " . $e->getMessage());
            \Log::error("Stack trace: " . $e->getTraceAsString());
    
            return response()->json([
                'success' => false,
                'message' => 'Error during deletion',
                'error' => $e->getMessage(),
                'trace' => config('app.debug') ? $e->getTrace() : null
            ], 500);
        }
    }


 public function getFormData($id)
{
    try {
        $form = Form::findOrFail($id);
        $tableName = $this->sanitizeTableName($form->name);
        
        // Récupérer les entrées avec une limite raisonnable pour éviter les problèmes de mémoire
        $entries = DB::table($tableName)->paginate(100);
        
        $formData = json_decode($form->form_data, true) ?: [];
        
        // Préparer les types de champs
        $fieldTypes = collect($formData)
            ->mapWithKeys(function ($field) {
                return [$field['name'] => $field['type'] ?? null];
            })
            ->filter();
        
        $multiselectFields = $fieldTypes->filter(fn($type) => $type === 'multiselect')->keys()->toArray();
        $mediaFields = $fieldTypes->filter(fn($type) => in_array($type, ['image', 'file']))->keys()->toArray();
        
        // Récupérer tous les user_id distincts pour optimisation
        $userIds = collect($entries->items())->pluck('user_id')->unique()->filter()->values()->toArray();
        
        // Précharger les informations utilisateur en une seule fois
        $usersInfo = $this->getUsersInfoBatch($userIds);
        
        // Transformer les entrées
        $transformedItems = collect($entries->items())->map(function ($entry) use (
            $tableName, 
            $multiselectFields, 
            $mediaFields, 
            $id,
            $usersInfo
        ) {
            // Convertir en tableau pour manipulation
            $entryArray = (array)$entry;
            
            // Ajouter les informations utilisateur si user_id existe
            if (!empty($entryArray['user_id'])) {
                $entryArray['user_info'] = $usersInfo[$entryArray['user_id']] ?? null;
            }
            
            // Gestion des multiselects
            if (!empty($multiselectFields)) {
                $this->processMultiselectFields($entryArray, $tableName, $multiselectFields);
            }
            
            // Gestion des fichiers
            $this->processMediaFields($entryArray, $mediaFields, $id);
            
            return $entryArray;
        });
        
        // Construire la réponse paginée
        $response = [
            'form_data' => $formData,
            'entries' => new \Illuminate\Pagination\LengthAwarePaginator(
                $transformedItems,
                $entries->total(),
                $entries->perPage(),
                $entries->currentPage(),
                [
                    'path' => \Illuminate\Pagination\Paginator::resolveCurrentPath(),
                    'pageName' => 'page',
                ]
            )
        ];
        
        return response()->json($response);
        
    } catch (\Exception $e) {
        \Log::error("Error getting form data for form {$id}: " . $e->getMessage());
        return response()->json([
            'message' => 'Error retrieving form data',
            'error' => $e->getMessage()
        ], 500);
    }
}

protected function getUsersInfoBatch(array $userIds): array
{
    if (empty($userIds)) {
        return [];
    }
    
    $usersInfo = [];
    $keycloak = new KeycloakController();
    
    foreach ($userIds as $userId) {
        try {
            $response = $keycloak->getUser($userId);
            
            if ($response->getStatusCode() === 200) {
                $userData = $response->getData(true);
                $usersInfo[$userId] = [
                    'username' => $userData['username'] ?? null,
                    'email' => $userData['email'] ?? null,
                    'firstName' => $userData['firstName'] ?? null,
                    'lastName' => $userData['lastName'] ?? null
                ];
            } else {
                \Log::warning("Failed to fetch user info for {$userId}, status: ".$response->getStatusCode());
                $usersInfo[$userId] = null;
            }
        } catch (\Exception $e) {
            \Log::error("Failed to fetch user info for {$userId}: " . $e->getMessage());
            $usersInfo[$userId] = null;
        }
    }
    
    return $usersInfo;
}

protected function processMultiselectFields(array &$entry, string $tableName, array $multiselectFields): void
{
    if (!Schema::hasTable($tableName.'_multi_value')) {
        return;
    }
    
    try {
        $multiselects = DB::table($tableName.'_multi_value')
            ->join($tableName.'_multi_option', 'option_id', '=', 'id')
            ->where('entry_id', $entry['id'])
            ->whereIn($tableName.'_multi_value.field_name', $multiselectFields)
            ->get()
            ->groupBy('field_name');
        
        foreach ($multiselects as $field => $options) {
            $entry[$field] = $options->pluck('option_value')->toArray();
        }
        
        // Initialiser les champs multiselect vides
        foreach ($multiselectFields as $field) {
            if (!isset($entry[$field])) {
                $entry[$field] = [];
            }
        }
    } catch (\Exception $e) {
        \Log::error("Error processing multiselect fields for entry {$entry['id']}: " . $e->getMessage());
    }
}

protected function processMediaFields(array &$entry, array $mediaFields, int $formId): void
{
    foreach ($mediaFields as $field) {
        try {
            if (!empty($entry[$field])) {
                $filePath = $entry[$field];
                
                if (strpos($filePath, 'storage/') === 0) {
                    $entry[$field] = [
                        'path' => $filePath,
                        'url' => asset($filePath),
                        'filename' => basename($filePath),
                        'exists' => Storage::exists(str_replace('storage/', 'public/', $filePath))
                    ];
                } else {
                    $relativePath = "uploads/forms/{$formId}/".basename($filePath);
                    $storagePath = "storage/{$relativePath}";
                    $publicPath = "public/{$relativePath}";
                    
                    $entry[$field] = [
                        'path' => $storagePath,
                        'url' => asset($storagePath),
                        'filename' => basename($filePath),
                        'exists' => Storage::exists($publicPath)
                    ];
                }
            } else {
                $entry[$field] = null;
            }
        } catch (\Exception $e) {
            \Log::error("Error processing media field {$field} for form {$formId}: " . $e->getMessage());
            $entry[$field] = null;
        }
    }
}
    public function getFormMetadata($id)
{
    try {
        // Retrieve the form and its metadata
        $form = Form::findOrFail($id);
        
        // Return the metadata - adjust this based on your actual data structure
        return response()->json([
            'success' => true,
            'metadata' => [
                'id' => $form->id,
                'name' => $form->name,
                'created_at' => $form->created_at,
                'updated_at' => $form->updated_at,
                // Add any other metadata fields you need
            ]
        ]);
    } catch (\Exception $e) {
        return response()->json([
            'success' => false,
            'message' => 'Failed to retrieve form metadata',
            'error' => $e->getMessage()
        ], 404);
    }
}

 public function submitFormData(Request $request, $id)
{
    $form = Form::findOrFail($id);
    $tableName = $this->sanitizeTableName($form->name);
    $formData = json_decode($form->form_data, true);

    // Log pour débogage
    \Log::info('Début de traitement de la soumission pour le formulaire: '.$form->name);
    \Log::debug('Données reçues:', $request->except(['password', 'token']));
    \Log::debug('Fichiers reçus:', $request->allFiles());

    // Validation des données
    $validator = Validator::make($request->all(), [
        // Vos règles de validation existantes
    ]);

    // Ajout des règles de validation pour les fichiers
    foreach ($formData as $field) {
        if (isset($field['type']) && in_array($field['type'], ['file', 'image'])) {
            $validator->sometimes($field['name'], 'file|max:10240', function() use ($request, $field) {
                return $request->hasFile($field['name']);
            });
        }
    }

    if ($validator->fails()) {
        \Log::error('Erreurs de validation:', $validator->errors()->toArray());
        return response()->json([
            'message' => 'Validation error',
            'errors' => $validator->errors()
        ], 422);
    }

    try {
        DB::beginTransaction();

        // 1. Préparation des données avec votre logique existante
        $user = $request->attributes->get('keycloak_user');
        $dataToInsert = ['user_id' => $user['sub'] ?? null];

        // 2. Traitement des champs avec votre logique originale
        foreach ($formData as $field) {
            if (!isset($field['name'], $field['type'])) continue;

            $fieldName = $field['name'];
            $fieldType = $field['type'];
            $inputValue = $request->input($fieldName);
                // Handle date fields
            if ($fieldType === 'date') {
                if (!empty($inputValue)) {
                    try {
                        // Convert ISO 8601 to MySQL date format
                        $date = new \DateTime($inputValue);
                        $dataToInsert[$fieldName] = $date->format('Y-m-d');
                    } catch (\Exception $e) {
                        \Log::error("Invalid date format for field {$fieldName}: {$inputValue}");
                        $dataToInsert[$fieldName] = null;
                    }
                } else {
                    $dataToInsert[$fieldName] = null;
                }
                continue;
            }

            // 3. Gestion des fichiers (partie corrigée)
            if ($fieldType === 'file' || $fieldType === 'image') {
                if ($request->hasFile($fieldName)) {
                    $file = $request->file($fieldName);
                    
                    // Structure de dossiers: /public/uploads/forms/[form_id]/[year]/[month]
                    $directory = "public/uploads/forms/{$id}/" . date('Y/m');
                    $filename = Str::uuid() . '.' . $file->getClientOriginalExtension();
                    
                    $path = $file->storeAs($directory, $filename);
                    $publicPath = str_replace('public/', 'storage/', $path);
                    
                    $dataToInsert[$fieldName] = $publicPath;
                    \Log::info("Fichier uploadé: {$publicPath}");
                } elseif ($request->filled($fieldName.'_existing')) {
                    // Conservation du fichier existant en cas d'édition
                    $dataToInsert[$fieldName] = $request->input($fieldName.'_existing');
                } else {
                    $dataToInsert[$fieldName] = null;
                }
            } 
            // 4. Conservation de votre logique pour les autres types de champs
            elseif ($fieldType === 'checkbox' && empty($field['options'])) {
                $dataToInsert[$fieldName] = $inputValue ? 1 : 0;
            } elseif ($fieldType === 'multiselect') {
                continue; // Géré séparément
            } else {
                $dataToInsert[$fieldName] = $inputValue;
            }
        }

        // 5. Insertion principale (votre logique originale)
        $entryId = DB::table($tableName)->insertGetId($dataToInsert);
        \Log::info("Entrée créée avec ID: {$entryId}");

        // 6. Gestion des multiselect (votre logique originale complète)
        $optionsTable = $tableName.'_multi_option';
        if (Schema::hasTable($optionsTable)) {
            foreach ($formData as $field) {
                if ($field['type'] === 'multiselect') {
                    $key = $field['name'];
                    $values = $request->input($key, []);

                    // Conversion depuis JSON si nécessaire
                    if (is_string($values)) {
                        try {
                            $values = json_decode($values, true);
                        } catch (\Exception $e) {
                            $values = [];
                        }
                    }

                    foreach ((array)$values as $value) {
                        if (empty($value)) continue;

                        // Recherche ou création de l'option
                        $optionId = DB::table($optionsTable)
                            ->where('field_name', $key)
                            ->where('option_value', $value)
                            ->value('id');

                        if (!$optionId) {
                            $optionId = DB::table($optionsTable)->insertGetId([
                                'field_name' => $key,
                                'option_value' => $value,
                                'created_at' => now()
                            ]);
                        }

                        // Liaison avec l'entrée
                        DB::table($tableName.'_multi_value')->insert([
                            'entry_id' => $entryId,
                            'option_id' => $optionId,
                            'field_name' => $key,
                            'created_at' => now()
                        ]);
                    }
                }
            }
        }

        DB::commit();

        // 7. Préparation de la réponse (votre format original amélioré)
        $response = [
            'message' => 'Data saved successfully',
            'entry_id' => $entryId,
            'data' => $dataToInsert
        ];
       // $notification = new RoleUpdatedNotification(
   // "Vous avez soumis le formulaire : {$form->name}",
  //  [],
    //'formulaire_soumis'
//);

// Enregistrement manuel dans la table notifications
//DB::table('notifications')->insert([
   // 'id' => Str::uuid(),
    //'type' => get_class($notification),
    //'notifiable_type' => 'keycloak_user',
   // 'notifiable_id' => $user['sub'], // ID Keycloak
   // 'data' => json_encode($notification->toArray(null)),
   // 'created_at' => now(),
    //'updated_at' => now(),
//]);

        // Ajout des URLs des fichiers
        foreach ($formData as $field) {
            if (in_array($field['type'], ['file', 'image']) && !empty($dataToInsert[$field['name']])) {
                $response['files'][$field['name']] = [
                    'path' => $dataToInsert[$field['name']],
                    'url' => asset($dataToInsert[$field['name']]),
                    'filename' => basename($dataToInsert[$field['name']])
                ];
            }
        }

        return response()->json($response, 201);

    } catch (\Exception $e) {
        DB::rollBack();
        \Log::error("Erreur lors de la soumission: ".$e->getMessage());
        \Log::error("Stack trace: ".$e->getTraceAsString());
        
        return response()->json([
            'message' => 'Error saving data',
            'error' => $e->getMessage(),
            'trace' => config('app.debug') ? $e->getTraceAsString() : null
        ], 500);
    }
}
  public function getUserFormEntries(Request $request, $formId)
{
    // Récupérer l'utilisateur depuis le middleware Keycloak
    $user = $request->attributes->get('keycloak_user');
    
    if (!$user || !isset($user['sub'])) {
        return response()->json(['message' => 'Unauthorized - Invalid Keycloak token or missing user ID'], 401);
    }

    $form = Form::findOrFail($formId);
    $tableName = $this->sanitizeTableName($form->name);
     $formData = json_decode($form->form_data, true) ?: [];
    // Récupérer les entrées de l'utilisateur
    $entries = DB::table($tableName)
                ->where('user_id', $user['sub'])
                ->get();

    // Si vous avez besoin de traiter les champs multiselect ou fichiers :
    $formData = json_decode($form->form_data, true);
    $fieldTypes = collect($formData)
        ->mapWithKeys(function ($field) {
            return [$field['name'] => $field['type'] ?? null];
        })
        ->filter();

    $multiselectFields = $fieldTypes->filter(fn($type) => $type === 'multiselect')->keys()->toArray();
    $mediaFields = $fieldTypes->filter(fn($type) => in_array($type, ['image', 'file']))->keys()->toArray();

    // Traiter chaque entrée pour ajouter les données supplémentaires
    $entries->transform(function ($entry) use ($tableName, $multiselectFields, $mediaFields, $formId) {
        // Gestion des multiselects
        if (!empty($multiselectFields)) {
            foreach ($multiselectFields as $field) {
                $options = DB::table($tableName.'_multi_value')
                    ->join($tableName.'_multi_option', 'option_id', '=', 'id')
                    ->where('entry_id', $entry->id)
                    ->where('field_name', $field)
                    ->pluck('option_value')
                    ->toArray();
                
                $entry->{$field} = $options;
            }
        }

        // Gestion des fichiers/images
        foreach ($mediaFields as $field) {
            if (!empty($entry->{$field})) {
                $filePath = $entry->{$field};
                
                if (strpos($filePath, 'storage/') === 0) {
                    $entry->{$field} = [
                        'path' => $filePath,
                        'url' => asset($filePath),
                        'filename' => basename($filePath)
                    ];
                } else {
                    $relativePath = "uploads/forms/{$formId}/".basename($filePath);
                    $storagePath = "storage/{$relativePath}";
                    
                    $entry->{$field} = [
                        'path' => $storagePath,
                        'url' => asset($storagePath),
                        'filename' => basename($filePath)
                    ];
                }
            }
        }

        return $entry;
    });

    return response()->json([
        'entries' => $entries,
        'form_data' => $formData 
    ]);
}

public function getUserFormDetails($formId, $userId)
{
    try {
        // Vérifier que le formulaire existe
        $form = Form::findOrFail($formId);
        $tableName = $this->sanitizeTableName($form->name);
        $formData = json_decode($form->form_data, true) ?? [];

        // Obtenir la première entrée de l'utilisateur pour ce formulaire
        $entry = DB::table($tableName)
            ->where('user_id', $userId)
            ->first();

        if (!$entry) {
            return response()->json([
                'message' => 'Aucune entrée trouvée pour cet utilisateur et ce formulaire.'
            ], 404);
        }

        // Déterminer les types de champs (multiselect, fichier, etc.)
        $fieldTypes = collect($formData)
            ->mapWithKeys(fn($field) => [$field['name'] => $field['type'] ?? null])
            ->filter();

        $multiselectFields = $fieldTypes->filter(fn($type) => $type === 'multiselect')->keys()->toArray();
        $mediaFields = $fieldTypes->filter(fn($type) => in_array($type, ['image', 'file']))->keys()->toArray();

        // Convertir l'entrée en objet modifiable
        $entry = collect((array) $entry);

        // Gestion des multiselects
        foreach ($multiselectFields as $field) {
            $options = DB::table($tableName . '_multi_value')
                ->join($tableName . '_multi_option', $tableName . '_multi_value.option_id', '=', $tableName . '_multi_option.id')
                ->where('entry_id', $entry['id'])
                ->where('field_name', $field)
                ->pluck('option_value')
                ->toArray();

            $entry[$field] = $options;
        }

        // Gestion des fichiers/images
        foreach ($mediaFields as $field) {
            if (!empty($entry[$field])) {
                $filePath = $entry[$field];

                if (strpos($filePath, 'storage/') === 0) {
                    $entry[$field] = [
                        'path' => $filePath,
                        'url' => asset($filePath),
                        'filename' => basename($filePath)
                    ];
                } else {
                    $relativePath = "uploads/forms/{$formId}/" . basename($filePath);
                    $storagePath = "storage/{$relativePath}";

                    $entry[$field] = [
                        'path' => $storagePath,
                        'url' => asset($storagePath),
                        'filename' => basename($filePath)
                    ];
                }
            }
        }

        return response()->json([
            'entry' => $entry,
            'form_data' => $formData,
            'form' => $form
        ]);
    } catch (\Exception $e) {
        return response()->json([
            'message' => 'Erreur lors de la récupération des données',
            'error' => $e->getMessage()
        ], 500);
    }
}


/**
 * Traite une entrée de formulaire pour structurer les données
 */
private function processFormEntry($entry, $formData, $tableName, $formId)
{
    $result = (array)$entry;
    unset($result['created_at'], $result['updated_at']);

    $fieldTypes = collect($formData)
        ->mapWithKeys(function ($field) {
            return [$field['name'] => $field['type'] ?? null];
        })
        ->filter();

    // Traitement des champs multiselect
    $multiSelectFields = $fieldTypes->filter(fn($type) => $type === 'multiselect')->keys()->toArray();
    if (!empty($multiSelectFields)) {
        $this->processMultiSelectFields($result, $tableName,
         $multiSelectFields);

    }

    // Traitement des fichiers/images
    $mediaFields = $fieldTypes->filter(fn($type) => in_array($type, ['file', 'image']))->keys()->toArray();
    if (!empty($mediaFields)) {
        $this->processMediaFields($result, $mediaFields, $formId);
    }

    return $result;
}

public function getTableFieldOptions(Request $request, $table)
{
    $request->validate([
        'key_column' => 'required|string',
        'value_column' => 'required|string',
    ]);

    if (!Schema::hasTable($table)) {
        return response()->json(['error' => 'Table non trouvée'], 404);
    }

    $keyColumn = $request->key_column;
    $valueColumn = $request->value_column;

    if (!Schema::hasColumn($table, $keyColumn) || !Schema::hasColumn($table, $valueColumn)) {
        return response()->json(['error' => 'Colonne(s) non trouvée(s)'], 404);
    }

    try {
        $options = DB::table($table)
            ->select([$keyColumn, $valueColumn])
            ->distinct()
            ->get()
            ->map(function ($item) use ($keyColumn, $valueColumn) {
                return [
                    'value' => $item->$valueColumn, // On utilise la valeur comme "value"
                    'label' => $item->$valueColumn  // Et aussi comme "label"
                ];
            })
            ->toArray();

        return response()->json($options);
    } catch (\Exception $e) {
        return response()->json(['error' => 'Erreur lors de la récupération des options'], 500);
    }
}
public function updateFormData(Request $request, $formId, $entryId)
{
    $form = Form::findOrFail($formId);
    $tableName = strtolower(str_replace(' ', '_', $form->name));
    $multiSelectOptionsTable = $tableName . '_multi_option';
    $multiSelectPivotTable = $tableName . '_multi_value';

    DB::beginTransaction();

    try {
        $formFields = json_decode($form->form_data, true);
        $dataToUpdate = [];

        // 1. Update normal fields
        foreach ($formFields as $field) {
            $key = $field['name'];
            $type = $field['type'];
            
            if ($type === 'file' || $type === 'image') {
                if ($request->hasFile($key)) {
                    $file = $request->file($key);
                    $path = $file->store('public/uploads');
                    $relativePath = 'uploads/'.$file->hashName();
                    $dataToUpdate[$key] = $relativePath;
                }
                continue;
            }
            
            if ($type === 'multiselect') {
                continue; // handled separately
            }

            if ($request->has($key)) {
                // Handle date fields conversion
                if ($type === 'date' || $type === 'datetime') {
                    $inputValue = $request->input($key);
                    if (!empty($inputValue)) {
                        try {
                            $date = new \DateTime($inputValue);
                            $dataToUpdate[$key] = $type === 'date' 
                                ? $date->format('Y-m-d') 
                                : $date->format('Y-m-d H:i:s');
                        } catch (\Exception $e) {
                            \Log::error("Invalid date format for field {$key}: {$inputValue}");
                            continue; // Skip this field update
                        }
                    }
                } else {
                    $dataToUpdate[$key] = $request->input($key);
                }
            }
        }

        if (!empty($dataToUpdate)) {
            DB::table($tableName)->where('id', $entryId)->update($dataToUpdate);
        }

        // 2. Update multiselects if table exists
        if (Schema::hasTable($multiSelectOptionsTable)) {
            foreach ($formFields as $field) {
                if ($field['type'] === 'multiselect') {
                    $key = $field['name'];
                    $newValues = $request->input($key, []);
                    
                    // Convert from JSON string if needed
                    if (is_string($newValues)) {
                        try {
                            $newValues = json_decode($newValues, true);
                        } catch (\Exception $e) {
                            $newValues = [];
                        }
                    }
                    
                    // Ensure it's an array
                    $newValues = is_array($newValues) ? $newValues : [];

                    // Delete old values
                    DB::table($multiSelectPivotTable)
                        ->where('entry_id', $entryId)
                        ->where('field_name', $key)
                        ->delete();

                    // Add new values
                    foreach ($newValues as $value) {
                        $option = DB::table($multiSelectOptionsTable)
                            ->where('field_name', $key)
                            ->where('option_value', $value)
                            ->first();

                        if (!$option) {
                            $optionId = DB::table($multiSelectOptionsTable)->insertGetId([
                                'field_name' => $key,
                                'option_value' => $value
                            ]);
                        } else {
                            $optionId = $option->id;
                        }

                        DB::table($multiSelectPivotTable)->insert([
                            'entry_id' => $entryId,
                            'option_id' => $optionId,
                            'field_name' => $key
                        ]);
                    }
                }
            }
        }

        DB::commit();
        return response()->json(['message' => 'Data updated successfully']);
    } catch (\Exception $e) {
        DB::rollBack();
        \Log::error('Error updating data: ' . $e->getMessage());
        return response()->json([
            'error' => 'Error during update',
            'message' => $e->getMessage()
        ], 500);
    }
}
    private function getOptionsFromTable($tableName, $fieldName)
{
    try {
        // On construit le nom de la colonne d'options (par convention, exemple : role_options)
        $optionsColumn = $fieldName . '_options';

        // Vérifie si la colonne des options existe bien dans la table
        $columnExists = Schema::hasColumn($tableName, $optionsColumn);

        if (!$columnExists) {
            return [];
        }

        // On récupère la première ligne de la table pour accéder aux options
        $row = DB::table($tableName)->first();

        if ($row && isset($row->$optionsColumn)) {
            $options = json_decode($row->$optionsColumn, true);
            return is_array($options) ? $options : [];
        }

        return [];
    } catch (\Exception $e) {
        \Log::error("Erreur lors de la récupération des options : " . $e->getMessage());
        return [];
    }
}

/**
 * Handle file upload for a specific form
 * 
 * @param Request $request
 * @param int $formId
 * @return \Illuminate\Http\JsonResponse
 */
public function uploadFile(Request $request, $formId)
{
    $request->validate([
        'file' => 'required|file|max:10240', // 10MB max
    ]);

    try {
        $form = Form::findOrFail($formId);
        $file = $request->file('file');
        
        // Stockage du fichier
        $originalName = $file->getClientOriginalName();
        $safeName = $this->sanitizeFilename($originalName);
        $path = $file->storeAs('public/uploads', $safeName);        
        // Retourne le chemin relatif (sans 'public/')
        $relativePath = str_replace('public/', '', $path);
        
        return response()->json([
            'success' => true,
            'filePath' => $relativePath,
            'url' => asset("storage/uploads/" . basename($relativePath))
        ]);
        
    } catch (\Exception $e) {
        return response()->json([
            'success' => false,
            'message' => 'Upload failed',
            'error' => $e->getMessage()
        ], 500);
    }
}
/**
 * Clean filename and prevent directory traversal
 */
private function sanitizeFilename($filename)
{
    // Remove path information
    $filename = basename($filename);
    
    // Replace special characters
    $filename = preg_replace('/[^a-zA-Z0-9\.\-_]/', '_', $filename);
    
    // Truncate long filenames
    if (strlen($filename) > 100) {
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        $name = substr(pathinfo($filename, PATHINFO_FILENAME), 0, 100 - (strlen($ext) + 1));
        $filename = $name . '.' . $ext;
    }
    
    return $filename;
}

/**
 * Delete an uploaded file
 */
public function deleteFile($formId, $filename)
{
    try {
        $form = Form::findOrFail($formId);
        $path = 'public/uploads/' . $filename;
        
        if (Storage::exists($path)) {
            Storage::delete($path);
            return response()->json(['success' => true]);
        }
        
        return response()->json(['success' => false, 'message' => 'File not found'], 404);
        
    } catch (\Exception $e) {
        return response()->json([
            'success' => false,
            'message' => 'Delete failed',
            'error' => $e->getMessage()
        ], 500);
    }
}
public function upload(Request $request, $formId)
{
    $request->validate([
        'file' => 'required|file|max:10240', // 10MB max
    ]);

    try {
        $file = $request->file('file');
        
        // Store in public/uploads/forms/{formId} directory
        $path = $file->store("public/uploads/forms/{$formId}");
        
        // Generate public URL
        $publicPath = str_replace('public/', 'storage/', $path);
        
        return response()->json([
            'success' => true,
            'filePath' => $publicPath,
            'url' => asset($publicPath) // Full URL
        ]);
        
    } catch (\Exception $e) {
        return response()->json([
            'success' => false,
            'message' => 'Upload failed',
            'error' => $e->getMessage()
        ], 500);
    }
}

public function getFile($formId, $filename)
{
    $path = "public/uploads/forms/{$formId}/{$filename}";
    
    if (!Storage::exists($path)) {
        abort(404);
    }
    
    // Return the file with proper headers
    return response()->file(storage_path('app/'.$path));
}
public function deleteFormData($formId, $entryId)
{
    $form = Form::findOrFail($formId);
    $tableName = strtolower(str_replace(' ', '_', $form->name));

    DB::beginTransaction();

    try {
        // 1. Récupérer les données de l'entrée avant suppression pour les fichiers
        $entryData = DB::table($tableName)
            ->where('id', $entryId)
            ->first();

        if (!$entryData) {
            return response()->json(['message' => 'Entrée non trouvée'], 404);
        }

        // 2. Analyser la structure du formulaire pour trouver les champs fichiers/images
        $formData = json_decode($form->form_data, true);
        $fileFields = collect($formData)
            ->filter(fn($field) => in_array($field['type'] ?? null, ['file', 'image']))
            ->pluck('name')
            ->toArray();

        // 3. Supprimer les fichiers associés
        foreach ($fileFields as $field) {
            if (isset($entryData->{$field}) && !empty($entryData->{$field})) {
                $filePath = $entryData->{$field};
                
                // Normaliser le chemin de stockage
                if (strpos($filePath, 'storage/') === 0) {
                    $storagePath = str_replace('storage/', 'public/', $filePath);
                } else {
                    $storagePath = 'public/uploads/forms/'.$formId.'/'.basename($filePath);
                }

                if (Storage::exists($storagePath)) {
                    Storage::delete($storagePath);
                }
            }
        }

        // 4. Supprimer les entrées multiselect associées
        if (Schema::hasTable($tableName.'_multi_value')) {
            DB::table($tableName.'_multi_value')
                ->where('entry_id', $entryId)
                ->delete();
        }

        // 5. Supprimer l'entrée principale
        $deleted = DB::table($tableName)
            ->where('id', $entryId)
            ->delete();

        DB::commit();

        return response()->json([
            'message' => 'Entrée et fichiers associés supprimés avec succès',
            'deleted_id' => $entryId
        ], 200);

    } catch (\Exception $e) {
        DB::rollBack();
        \Log::error("Erreur suppression données formulaire - Form: {$formId}, Entry: {$entryId} - " . $e->getMessage());
        
        return response()->json([
            'message' => 'Erreur lors de la suppression',
            'error' => $e->getMessage(),
            'trace' => config('app.debug') ? $e->getTraceAsString() : null
        ], 500);
    }
}

public function getAvailableTables()
    {

        $tables = DB::select('SHOW TABLES');

    //    Formatage facultatif selon ton besoin
        $formatted = array_map(function ($table) {
            return array_values((array)$table)[0];
        }, $tables);

        return response()->json($formatted);
    }
    
    
public function getFormColumns($id)
{
    $form = Form::findOrFail($id);
    $tableName = strtolower(str_replace(' ', '_', $form->name));

    if (!Schema::hasTable($tableName)) {
        return response()->json(['message' => 'Table non trouvée'], 404);
    }

    $columns = array_column(DB::select("SHOW COLUMNS FROM $tableName"), 'Field');

    return response()->json($columns);
}

// FormController.php
public function getTableOptions($table, Request $request)
{
    $request->validate([
        'key_column' => 'required|string',
        'value_column' => 'required|string',
        'where' => 'nullable|string' // Clause WHERE optionnelle
    ]);

    try {
        if (!Schema::hasTable($table)) {
            return response()->json(['error' => 'Table not found'], 404);
        }

        $keyColumn = $request->key_column;
        $valueColumn = $request->value_column;

        if (!Schema::hasColumn($table, $keyColumn) || !Schema::hasColumn($table, $valueColumn)) {
            return response()->json(['error' => 'Invalid columns'], 400);
        }

        $query = DB::table($table)
            ->select([$keyColumn, $valueColumn])
            ->distinct();

        if ($request->where) {
            $query->whereRaw($request->where);
        }

        $options = $query->get()
            ->map(function ($item) use ($keyColumn, $valueColumn) {
                return [
                    'key' => $item->$keyColumn,
                    'value' => $item->$valueColumn
                ];
            });

        return response()->json($options);
    } catch (\Exception $e) {
        return response()->json([
            'error' => 'Database error',
            'message' => $e->getMessage()
        ], 500);
    }
}



public function getTableFields($table)
{
    $columns = Schema::getColumnListing($table);
    return response()->json($columns);
}

public function getColumnValues($table, $column)
{
    // Vérifier si la table existe
    if (!Schema::hasTable($table)) {
        return response()->json(['error' => "La table '$table' n'existe pas."], 400);
    }

    // Vérifier si la colonne existe dans la table
    if (!Schema::hasColumn($table, $column)) {
        return response()->json(['error' => "La colonne '$column' n'existe pas dans la table '$table'."], 400);
    }

    // Récupérer toutes les valeurs distinctes de la colonne
    try {
        $values = DB::table($table)
                    ->select($column)
                    ->distinct()
                    ->pluck($column);

        return response()->json($values);
    } catch (\Exception $e) {
        return response()->json(['error' => 'Erreur lors de la récupération des données.', 'details' => $e->getMessage()], 500);
    }
}

public function getFieldOptions($formId, $fieldName)
{
    $form = Form::findOrFail($formId);
    $tableName = strtolower(str_replace(' ', '_', $form->name)); 
        $optionsTableName = $tableName . '_options';

    $options = DB::table($optionsTableName)
        ->where('field_name', $fieldName)
        ->select('option_key as key', 'option_value as value')
        ->get();

    return response()->json($options);
}

public function getMultiselectOptions($formId, $fieldName)
{
    $form = Form::findOrFail($formId);
    $tableName = strtolower(str_replace(' ', '_', $form->name));
    $optionsTableName = $tableName . '_multi_option';

    $options = DB::table($optionsTableName)
        ->where('field_name', $fieldName)
        ->select('id', 'option_value as value')
        ->get();

    return response()->json($options);
}

// Dans FormController.php

public function manageFormPermissions(Request $request, $formId)
{
    $form = Form::findOrFail($formId);
    $roleName = 'form_' . Str::slug($form->name, '_');

    $request->validate([
        'user_id' => 'required|string',
        'action' => 'required|in:grant,revoke'
    ]);

    try {
        $keycloak = new KeycloakController();
        
        if ($request->action === 'grant') {
            $keycloak->assignRoleToUser($request->user_id, $roleName);
            $message = 'Permission granted successfully';
        } else {
            $keycloak->revokeRoleFromUser($request->user_id, $roleName);
            $message = 'Permission revoked successfully';
        }

        return response()->json(['message' => $message]);

    } catch (\Exception $e) {
        return response()->json(['error' => $e->getMessage()], 500);
    }
}
}