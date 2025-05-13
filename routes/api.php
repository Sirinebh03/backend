<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\FormController;
use App\Http\Controllers\AuthController;

Route::prefix('forms')->group(function () {
    Route::get('/{id}/data', [FormController::class, 'getFormData']);
    Route::get('/{id}', [FormController::class, 'show']);
    Route::get('/table', [FormController::class, 'getAvailableTables']);
    Route::post('/{formId}/upload', [FormController::class, 'upload']);
    Route::get('/{name}', [FormController::class, 'getByName']);
    Route::get('/{formId}/files/{filename}', [FormController::class, 'getFile'])->where('filename', '.*');
    Route::put('/{id}', [FormController::class, 'update']);
    Route::get('/{id}/metadata', [FormController::class, 'getFormMetadata']);
    Route::get('/id-by-name/{name}', [FormController::class, 'getIdByName']);
    Route::post('/upload', [FormController::class, 'handleFileUpload']);
    Route::post('/{form}/upload', [FormController::class, 'uploadFile']);
    Route::get('/files/{filename}', [FormController::class, 'getFiles']);
    Route::delete('/{formId}/entries/{entryId}/delete', [FormController::class, 'deleteFormData']);
    Route::get('/tables/{table}/fields', [FormController::class, 'getTableFields']);
    Route::get('/tables/{table}/options', [FormController::class, 'getTableFieldOptions']);
    Route::get('/get-column-values/{table}/{column}', [FormController::class, 'getColumnValues']);
    Route::post('/{formId}/field-options', [FormController::class, 'saveFieldOptions']);
    Route::get('/', [FormController::class, 'index']);
    Route::post('/', [FormController::class, 'store']);
    Route::delete('/{id}', [FormController::class, 'destroy']);
    Route::post('/{id}/submit', [FormController::class, 'submitFormData']);
    Route::get('/{id}/config', [FormController::class, 'getFormConfig']);
    Route::put('/{formId}/entries/{entryId}/update', [FormController::class, 'updateFormData']);
    Route::get('/options/{table}/{field}', [FormController::class, 'getFieldOptions']);
    Route::get('/{id}/columns', [FormController::class, 'getFormColumns']);
});

// Route protégée avec le middleware auth:api pour le logout (Keycloak ou autre)
Route::middleware('auth:api')->group(function () {
    Route::post('/logout', [AuthController::class, 'logoutApi']);
});
