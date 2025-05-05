<?php

namespace App\Http\Controllers;

use App\Models\Form;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

class FormController extends Controller
{
    public function index()
    {
        return response()->json(Form::all());
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


    try {
        $form->update([
            'name' => $request->name,
            'form_data' => json_encode($request->form_data),
            'description' => $request->description ?? null
        ]);

        if ($oldTableName !== $newTableName) {
            Schema::rename($oldTableName, $newTableName);
            Schema::rename($oldTableName.'_multiselect_options', $newTableName.'_multiselect_options');
            Schema::rename($oldTableName.'_multiselect_values', $newTableName.'_multiselect_values');
        }

        $this->updateDynamicTableStructure($newTableName, $request->form_data);

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

    private function createDynamicTable(string $tableName, array $fields)
    {
        try {
            Schema::create($tableName, function ($table) use ($fields,$tableName) {
                $table->increments('id')->unsigned();
                
                foreach ($fields as $field) {
                    if (!isset($field['name']) || !isset($field['type'])) {
                        continue;
                    }

                    $columnName = $this->sanitizeColumnName($field['name']);
                    $type = $field['type'];
                    
                    if ($type === 'multiselect') 
                       continue; // Gérer séparément
                    
                    $columnType = $this->mapFieldTypeToMySQL($type);
                    if ($columnType) {
                        $column = $table->{$columnType}($columnName)->nullable();
                        if ($columnType === 'integer') $column->unsigned();
                    }
                }
                
                $table->timestamps();
                $table->engine = 'InnoDB';
            });

            $this->createMultiSelectTables($tableName);
        

        } catch (\Exception $e) {
            \Log::error('Table creation error: '.$e->getMessage());
            throw $e;
        }
    }

    private function sanitizeColumnName(string $name): string
    {
        return Str::lower(Str::slug($name, '_'));
    }
    
    private function createMultiSelectTables(string $tableName)
    {
        Schema::create($tableName.'_multiselect_options', function ($table) {
            $table->increments('id')->unsigned();
            $table->string('field_name', 255);
            $table->string('option_value', 255);
            $table->unique(['field_name', 'option_value']);
            $table->engine = 'InnoDB';
        });

        Schema::create($tableName.'_multiselect_values', function ($table) use ($tableName) {
            $table->integer('entry_id')->unsigned();
            $table->integer('option_id')->unsigned();
            $table->string('field_name', 255);
            
            $table->foreign('entry_id')
                  ->references('id')
                  ->on($tableName)
                  ->onDelete('cascade');
                  
            $table->foreign('option_id')
                  ->references('id')
                  ->on($tableName.'_multiselect_options')
                  ->onDelete('cascade');
                  
            $table->primary(['entry_id', 'option_id', 'field_name']);
            $table->engine = 'InnoDB';
        });
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
                    $optionsTable = strtolower(str_replace(' ', '_', $form->name)).'_multiselect_options';
                    
                    if (Schema::hasTable($optionsTable)) {
                        $options = DB::table($optionsTable)
                            ->where('field_name', $field['name'])
                            ->select('option_value as value', 'option_value as label')
                            ->get()
                            ->toArray();
                        
                        $field['options'] = $options;
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
    }
    private function updateDynamicTableStructure(string $tableName, array $fields)
    {
        $existingColumns = Schema::getColumnListing($tableName);
        $columnsToKeep = ['id', 'created_at', 'updated_at']; // Colonnes système à toujours garder
    
        // Ajouter les nouvelles colonnes et mettre à jour les existantes
        foreach ($fields as $field) {
            if (!isset($field['name']) || !isset($field['type'])) {
                continue;
            }
    
            $columnName = $this->sanitizeColumnName($field['name']);
            $type = $field['type'];
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
        $hasMultiselect = array_filter($fields, fn($f) => $f['type'] === 'multiselect');
        if (!empty($hasMultiselect)) {
            $this->ensureMultiselectTablesExist($tableName);
        }
    }
    
    private function ensureMultiselectTablesExist(string $tableName)
    {
        if (!Schema::hasTable($tableName.'_multiselect_options')) {
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
        $multiSelectOptionsTable = $tableName . '_multiselect_options';
        $multiSelectValuesTable = $tableName . '_multiselect_values';
    
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
    public function getFile($filename)
{
    $path = storage_path('app/public/uploads/' . $filename);

    if (!File::exists($path)) {
        abort(404);
    }

    return response()->file($path);
}
   public function getFormData($id)
{
    $form = Form::findOrFail($id);
    $tableName = strtolower(str_replace(' ', '_', $form->name));
    
    $entries = DB::table($tableName)->get();
    
    // Pour les multiselects, joindre les valeurs
    $entries->transform(function ($entry) use ($tableName) {
        $multiselects = DB::table($tableName.'_multiselect_values')
            ->join($tableName.'_multiselect_options', 'option_id', '=', 'id')
            ->where('entry_id', $entry->id)
            ->get()
            ->groupBy('field_name');
        
        foreach ($multiselects as $field => $options) {
            $entry->{$field} = $options->pluck('option_value')->toArray();
        }
        
        return $entry;
    });
    
    return response()->json([
        'form_data' => json_decode($form->form_data),
        'entries' => $entries
    ]);
}

public function submitFormData(Request $request, $id)
{
    $form = Form::findOrFail($id);
    $tableName = $this->sanitizeTableName($form->name);
    $formData = json_decode($form->form_data, true);
    
    if (!is_array($formData)) {
        return response()->json(['message' => 'Invalid form data format'], 400);
    }

    DB::beginTransaction();

    try {
        $dataToInsert = [];
        $filePaths = [];

         foreach ($formData as $field) {
            if (!isset($field['name'], $field['type'])) continue;

            $fieldName = $field['name'];
            $fieldType = $field['type'];
            $inputValue = $request->input($fieldName);

            // Gestion des fichiers
            if ($fieldType === 'file' || $fieldType === 'image') {
                if ($request->hasFile($fieldName)) {
                    $file = $request->file($fieldName);
                    $path = $file->store('public/uploads');
                    $publicPath = str_replace('public/', 'storage/', $path);
                    $dataToInsert[$fieldName] = $publicPath;
                    $filePaths[] = $path;
                }
                continue;
            }
            // Gestion des checkbox simples (pas avec options)
            elseif ($fieldType === 'checkbox' && empty($field['options'])) {
                $dataToInsert[$fieldName] = $inputValue ? 1 : 0;
            }
            // Ignorer multiselect (sera traité après)
            elseif ($fieldType === 'multiselect') {
                continue;
            }
            // Gestion des autres champs
            else {
                $dataToInsert[$fieldName] = $inputValue;
            }
        }

        // Insertion dans la table principale
        $entryId = DB::table($tableName)->insertGetId($dataToInsert);

        // Gestion multiselect
        foreach ($formData as $field) {
            if ($field['type'] === 'multiselect') {
                $key = $field['name'];
                $values = (array)$request->input($key, []);
                
                foreach ($values as $value) {
                    $optionId = DB::table($tableName.'_multiselect_options')
                        ->where('field_name', $key)
                        ->where('option_value', $value)
                        ->value('id');
                    
                    if (!$optionId) {
                        $optionId = DB::table($tableName.'_multiselect_options')->insertGetId([
                            'field_name' => $key,
                            'option_value' => $value
                        ]);
                    }
                    
                    DB::table($tableName.'_multiselect_values')->insert([
                        'entry_id' => $entryId,
                        'option_id' => $optionId,
                        'field_name' => $key
                    ]);
                }
            }
        }

        DB::commit();

        return response()->json([
            'message' => 'Data saved successfully',
            'entry_id' => $entryId
        ], 201);
        
    } catch (\Exception $e) {
        DB::rollBack();
        
        // Supprimer les fichiers uploadés en cas d'erreur
        foreach ($filePaths as $path) {
            Storage::delete($path);
        }
        
        \Log::error('Form submission error: '.$e->getMessage());
        return response()->json([
            'message' => 'Error saving data',
            'error' => $e->getMessage()
        ], 500);
    }
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
        $multiSelectOptionsTable = $tableName . '_multiselect_options';
        $multiSelectPivotTable = $tableName . '_multiselect_values';
    
        DB::beginTransaction();
    
        try {
            $formFields = json_decode($form->form_data, true);
            $dataToUpdate = [];
    
            // 1. Mettre à jour les champs normaux
            foreach ($formFields as $field) {
                $key = $field['name'];
                $type = $field['type'];
                if ($type === 'file' || $type === 'image') {
                    if ($request->hasFile($key)) {
                        // Supprimer l'ancien fichier si existant
                        $oldPath = DB::table($tableName)
                            ->where('id', $entryId)
                            ->value($key);
                        
                        if ($oldPath) {
                            $storagePath = str_replace('storage/', 'public/', $oldPath);
                            $filesToDelete[] = $storagePath;
                        }
    
                        // Enregistrer le nouveau fichier
                        $file = $request->file($key);
                        $path = $file->store('public/uploads');
                        $publicPath = str_replace('public/', 'storage/', $path);
                        $dataToUpdate[$key] = $publicPath;
                        $newFilePaths[] = $path;
                    }
                    continue;
                }
                
                if ($type === 'multiselect') {
                    continue; // géré séparément
                }
    
                if ($request->has($key)) {
                    $dataToUpdate[$key] = $request->input($key);
                }
            }
    
            if (!empty($dataToUpdate)) {
                DB::table($tableName)->where('id', $entryId)->update($dataToUpdate);
            }
    
            // 2. Mettre à jour les multiselects
            foreach ($formFields as $field) {
                if ($field['type'] === 'multiselect') {
                    $key = $field['name'];
                    $newValues = $request->input($key, []);
    
                    // Supprimer les anciennes valeurs
                    DB::table($multiSelectPivotTable)
                        ->where('entry_id', $entryId)
                        ->where('field_name', $key)
                        ->delete();
    
                    // Ajouter les nouvelles valeurs
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
    
            DB::commit();
            return response()->json(['message' => 'Données mises à jour avec succès']);
        } catch (\Exception $e) {
            DB::rollBack();
            \Log::error('Erreur mise à jour données : ' . $e->getMessage());
            return response()->json(['error' => 'Erreur mise à jour: ' . $e->getMessage()], 500);
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

public function deleteFormData($formId, $entryId)
{
    $form = Form::findOrFail($formId);
    $tableName = strtolower(str_replace(' ', '_', $form->name));

    DB::beginTransaction();

    try {
        // Supprimer d'abord les entrées multiselect associées
        DB::table($tableName.'_multiselect_values')
            ->where('entry_id', $entryId)
            ->delete();

        // Puis supprimer l'entrée principale
        $deleted = DB::table($tableName)
            ->where('id', $entryId)
            ->delete();

        DB::commit();

        if ($deleted) {
            return response()->json(['message' => 'Entrée supprimée avec succès'], 200);
        } else {
            return response()->json(['message' => 'Entrée non trouvée'], 404);
        }
    } catch (\Exception $e) {
        DB::rollBack();
        return response()->json(['message' => 'Erreur lors de la suppression', 'error' => $e->getMessage()], 500);
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
    $optionsTableName = $tableName . '_multiselect_options';

    $options = DB::table($optionsTableName)
        ->where('field_name', $fieldName)
        ->select('id', 'option_value as value')
        ->get();

    return response()->json($options);
}

    

}