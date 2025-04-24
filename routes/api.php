<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\FormController;

Route::prefix('forms')->group(function () {
    Route::delete('/{formId}/entries/{entryId}/delete', action: [FormController::class, 'deleteFormData']);
    Route::get('/table', [FormController::class, 'getAvailableTables']);
    Route::get('/tables/{table}/fields', [FormController::class, 'getTableFields']);
    Route::get('/tables/{table}/options', [FormController::class, 'getTableFieldOptions']);
    Route::get('/get-column-values/{table}/{column}', [FormController::class, 'getColumnValues']);
    Route::post('/{formId}/field-options', [FormController::class, 'saveFieldOptions']);

   

    Route::get('/', [FormController::class, 'index']);
    Route::post('/', [FormController::class, 'store']);

    Route::get('/{id}', [FormController::class, 'show']);
    Route::put('/{id}', [FormController::class, 'update']);

    Route::delete('/{id}', [FormController::class, 'destroy']);
    Route::get('/{id}/data', [FormController::class, 'getFormData']);
    Route::post('/{id}/submit', [FormController::class, 'submitFormData']);
    Route::get('/{id}/config', [FormController::class, 'getFormConfig']);
    Route::put('/{formId}/entries/{entryId}/update', [FormController::class, 'updateFormData']);
    Route::get('/options/{table}/{field}', [FormController::class, 'getFieldOptions']);
    Route::get('/{id}/columns', [FormController::class, 'getFormColumns']);

  
});

