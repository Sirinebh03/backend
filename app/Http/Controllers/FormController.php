<?php

namespace App\Http\Controllers;

use App\Models\Form;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class FormController extends Controller
{
    public function index()
    {
        return response()->json(Form::all());
    }

    public function store(Request $request)
{
    $request->validate([
        'name' => 'required|string|max:255',
        'form_data' => 'required|array',
    ]);

    $tableName = strtolower(str_replace(' ', '_', $request->name));

    if (Schema::hasTable($tableName)) {
        return response()->json(['message' => 'Une table avec ce nom existe déjà'], 400);
    }

    // Stockez simplement le formulaire
    $form = Form::create([
        'name' => $request->name,
        'form_data' => json_encode($request->form_data),
    ]);

    $this->createDynamicTable($tableName, $request->form_data);

    return response()->json($form, 201);
}    private function createDynamicTable(string $tableName, array $fields)
    {
        try {
            Schema::create($tableName, function ($table) use ($fields) {
                $table->increments('id')->unsigned();
                
                foreach ($fields as $field) {
                    $columnName = strtolower(str_replace(' ', '_', $field['name']));
                    $type = $field['type'];
                    
                    if ($type === 'multiselect') continue;
                    
                    $columnType = $this->mapFieldTypeToMySQL($type);
                    if ($columnType) {
                        $column = $table->{$columnType}($columnName)->nullable();
                        if ($columnType === 'integer') $column->unsigned();
                    }
                }
                
                $table->timestamps();
                $table->engine = 'InnoDB';
            });
    
            // Création tables pour multiselect uniquement
            $this->createMultiSelectTables($tableName);
            
        } catch (\Exception $e) {
            \Log::error('Erreur création table : '.$e->getMessage());
            throw $e;
        }
    }
    
    private function createMultiSelectTables(string $tableName)
    {
        // Table des options multiselect
        Schema::create($tableName.'_multiselect_options', function ($table) {
            $table->increments('id')->unsigned();
            $table->string('field_name', 255);
            $table->string('option_value', 255);
            $table->unique(['field_name', 'option_value']);
            $table->engine = 'InnoDB';
        });
    
        // Table pivot
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

    public function getFormConfig($id)
    {
        $form = Form::findOrFail($id);
        $formData = json_decode($form->form_data, true);
        
        foreach ($formData as &$field) {
            // Pour les champs avec options statiques
            if (in_array($field['type'], ['select', 'radio', 'checkbox'])) {
                if (!empty($field['options'])) {
                    // Convertir les options au format {value, label} si nécessaire
                    $field['options'] = array_map(function($opt) {
                        return is_array($opt) ? $opt : ['value' => $opt, 'label' => $opt];
                    }, (array)$field['options']);
                }
            }
    
            // Pour les champs dynamiques
            if (!empty($field['dynamic']) && !empty($field['sourceTable'])) {
                // Options dynamiques
                $options = DB::table($field['sourceTable'])
                    ->select([
                        $field['keyColumn'].' as value',
                        $field['valueColumn'].' as label'
                    ])
                    ->get()
                    ->toArray();
                
                $field['options'] = $options;
            }
            elseif ($field['type'] === 'multiselect') {
                // Options multiselect
                $options = DB::table(strtolower(str_replace(' ', '_', $form->name)).'_multiselect_options')
                    ->where('field_name', $field['name'])
                    ->select('option_value as value', 'option_value as label')
                    ->get()
                    ->toArray();
                
                $field['options'] = $options;
            }
        }
        
        return response()->json($formData);
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
   
private function mapFieldTypeToMySQL(string $fieldType): ?string
{
    return match ($fieldType) {
        'text', 'email', 'password', 'select', 'radio' => 'string',
        'number' => 'integer',
        'date' => 'date',
        'textarea' => 'text',
        'checkbox' => 'string', // stocke la valeur directement
        'multiselect' => null, // pas de colonne, géré via tables pivot
        'boolean' => 'boolean',
        default => null,
    };
}
    
    public function show($id)
    {
        $form = Form::findOrFail($id);
        return response()->json($form);
    }

    public function update(Request $request, $id)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'form_data' => 'required|array',
        ]);

        $form = Form::findOrFail($id);
        $oldTableName = strtolower(str_replace(' ', '_', $form->name));
        $newTableName = strtolower(str_replace(' ', '_', $request->name));

        if ($oldTableName !== $newTableName) {
            DB::statement("ALTER TABLE $oldTableName RENAME TO $newTableName");
        }

        $this->updateDynamicTable($newTableName, json_decode($form->form_data, true), $request->form_data);

        $form->update([
            'name' => $request->name,
            'form_data' => json_encode($request->form_data),
        ]);

        return response()->json($form);
    }

    private function updateDynamicTable(string $tableName, array $oldFields, array $newFields)
    {
        if (!Schema::hasTable($tableName)) {
            throw new \Exception("Table {$tableName} does not exist.");
        }

        $existingColumns = array_column(DB::select("SHOW COLUMNS FROM $tableName"), 'Field');
        $newColumns = array_map(fn($field) => strtolower(str_replace(' ', '_', $field['name'])), $newFields);

        foreach ($newFields as $field) {
            $columnName = strtolower(str_replace(' ', '_', $field['name']));
            $columnType = $this->mapFieldTypeToMySQL($field['type']);

            if (!in_array($columnName, $existingColumns) && $columnType) {
                DB::statement("ALTER TABLE $tableName ADD $columnName $columnType");
            }
        }

        foreach ($existingColumns as $column) {
            if ($column !== 'id' && !in_array($column, $newColumns)) {
                DB::statement("ALTER TABLE $tableName DROP COLUMN $column");
            }
        }
    }

    public function destroy($id)
    {
        // Validation de l'ID
        if (!is_numeric($id) || $id <= 0) {
            return response()->json([
                'success' => false,
                'message' => 'ID de formulaire invalide'
            ], 400);
        }
    
        $form = Form::find($id);
        
        // Vérifier si le formulaire existe
        if (!$form) {
            return response()->json([
                'success' => false,
                'message' => 'Formulaire non trouvé'
            ], 404);
        }
    
        $tableName = strtolower(str_replace(' ', '_', $form->name));
        $multiSelectOptionsTable = $tableName.'_multiselect_options';
        $multiSelectValuesTable = $tableName.'_multiselect_values';
    
    
        try {
            // 1. Vérifier les dépendances
            $databaseName = config('database.connections.mysql.database');
            $dependencies = DB::select("
                SELECT TABLE_NAME as table_name 
                FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
                WHERE 
                    REFERENCED_TABLE_NAME = ? 
                    AND REFERENCED_TABLE_SCHEMA = ?
                    AND TABLE_NAME NOT LIKE ?
            ", [$tableName, $databaseName, $tableName.'%']);
    
            if (!empty($dependencies)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Impossible de supprimer: tables externes dépendantes',
                    'dependencies' => $dependencies
                ], 422);
            }
    
            // 2. Supprimer les tables dans le bon ordre
            if (Schema::hasTable($multiSelectValuesTable)) {
                Schema::drop($multiSelectValuesTable);
            }
    
            if (Schema::hasTable($multiSelectOptionsTable)) {
                Schema::drop($multiSelectOptionsTable);
            }
    
            if (Schema::hasTable($tableName)) {
                Schema::drop($tableName);
            }
    
            // 3. Supprimer le formulaire
            $form->delete();
    
            DB::commit();
    
            return response()->json([
                'success' => true,
                'message' => 'Suppression réussie'
            ]);
    
        } catch (\Exception $e) {
            DB::rollBack();
            \Log::error("Erreur suppression formulaire {$id}: " . $e->getMessage());
            
            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de la suppression',
                'error' => $e->getMessage()
            ], 500);
        }
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
    $tableName = strtolower(str_replace(' ', '_', $form->name));
    
    DB::beginTransaction();

    try {
        $formFields = json_decode($form->form_data, true);
        $dataToInsert = [];

        foreach ($formFields as $field) {
            $key = strtolower(str_replace(' ', '_', $field['name']));
            $value = $request->input($field['name']);
            $type = $field['type'];

              // Conversion des valeurs
              if ($type === 'checkbox') {
                // Pour les checkboxes simples (sans options)
                if (empty($field['options'])) {
                    $dataToInsert[$key] = $value ? 1 : 0;
                } 
                // Pour les checkboxes avec options (case à cocher multiple)
                else {
                    $dataToInsert[$key] = json_encode((array)$value);
                }
            }
            elseif ($type === 'multiselect') {
                continue; // Géré après
            }
            else {
                // Stockage direct pour select/radio/text/etc.
                $dataToInsert[$key] = $value;
            }
        }

        // Insertion dans la table principale
        $entryId = DB::table($tableName)->insertGetId($dataToInsert);

        // Gestion multiselect
        foreach ($formFields as $field) {
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
        return response()->json(['message' => 'Données enregistrées']);
        
    } catch (\Exception $e) {
        DB::rollBack();
        \Log::error('Erreur soumission : '.$e->getMessage());
        return response()->json(['error' => $e->getMessage()], 500);
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