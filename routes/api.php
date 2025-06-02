<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\FormController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\KeycloakController;

Route::middleware(['api'] )->group(function () {
    
    // Routes publiques
    Route::prefix('forms')->group(function () {
        // Routes GET publiques
        Route::get('/', [FormController::class, 'index']);
        Route::get('/{id}', [FormController::class, 'show']);
       // Route::get('/{name}', [FormController::class, 'getByName']);
        Route::get('/id-by-name/{name}', [FormController::class, 'getIdByName']);
        Route::get('/{id}/config', [FormController::class, 'getFormConfig']);
        Route::get('/{id}/metadata', [FormController::class, 'getFormMetadata']);
        Route::get('/table', [FormController::class, 'getAvailableTables']);
        Route::get('/tables/{table}/fields', [FormController::class, 'getTableFields']);
        Route::get('/get-column-values/{table}/{column}', [FormController::class, 'getColumnValues']);
        Route::get('/options/{table}/{field}', [FormController::class, 'getFieldOptions']);
        Route::get('/users/{formId}/{userId}', [FormController::class, 'getUserFormDetails']);
        // Routes POST publiques
        Route::post('/upload', [FormController::class, 'handleFileUpload']);
        
        // Routes fichiers publiques
        Route::get('/{formId}/files/{filename}', [FormController::class, 'getFile'])->where('filename', '.*');
     Route::get('/{id}/data', [FormController::class, 'getFormData']);
    });

    // Routes Keycloak publiques
    Route::prefix('keycloak')->group(function () {
        Route::post('/users', [KeycloakController::class, 'createUser']);
        Route::get('/users/check-username', [KeycloakController::class, 'checkUsername']);
    });

    // Routes protégées par Keycloak
    Route::middleware(['keycloak'])->group(function () {
        // Routes formulaires protégées
        Route::prefix('forms')->group(function () {
            // Routes POST protégées
            Route::post('/', [FormController::class, 'store']);
            Route::post('/{formId}/upload', [FormController::class, 'upload']);
            Route::post('/{form}/upload', [FormController::class, 'uploadFile']);
            Route::post('/{formId}/field-options', [FormController::class, 'saveFieldOptions']);
            Route::post('/{id}/submit', [FormController::class, 'submitFormData']);
            Route::get('/with-permissions', [FormController::class, 'getFormsWithPermissions']);
            // Routes PUT protégées
            Route::put('/{id}', [FormController::class, 'update']);
            Route::put('/{formId}/entries/{entryId}', [FormController::class, 'updateFormData']);
            
            // Routes DELETE protégées
            Route::delete('/{id}', [FormController::class, 'destroy']);
            Route::delete('/{formId}/entries/{entryId}', [FormController::class, 'deleteFormData']);
            Route::delete('/{formId}/files/{filename}', [FormController::class, 'deleteFile']);
            
            // Routes GET protégées
            
            Route::get('/user/{formId}/entries', [FormController::class, 'getUserFormEntries']);
            Route::get('/{id}/columns', [FormController::class, 'getFormColumns']);
            Route::get('/userform/{userId}', [KeycloakController::class, 'getFormUser']);
            Route::get('/auth/has-role', [KeycloakController::class, 'hasRole']);

        });

        // Route de déconnexion protégée
        Route::post('/logout', [AuthController::class, 'logoutApi']);
    });
    Route::middleware(['api', 'keycloak'])->group(function () {
    // ... autres routes existantes
    
    Route::prefix('keycloak')->group(function () {
        // ... autres routes keycloak existantes
         Route::get('/users/{userId}', [KeycloakController::class, 'getUser']);

        // Nouvelles routes pour la gestion des rôles
        Route::get('/users', [KeycloakController::class, 'getUsers']);
        Route::get('/roles', [KeycloakController::class, 'getAvailableRoles']);
        Route::get('/users/{userId}/roles', [KeycloakController::class, 'getUserRoles']);
        Route::post('/users/{userId}/roles', [KeycloakController::class, 'assignRolesToUser']);
        Route::delete('/users/{userId}/roles', [KeycloakController::class, 'revokeRolesFromUser']);
        Route::get('/users/count', [KeycloakController::class, 'countUsers']);
    });
});
});