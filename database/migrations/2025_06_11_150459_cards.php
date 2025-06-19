<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
 public function up()
{
    Schema::create('cards', function (Blueprint $table) {
        $table->id(); 
        $table->string('label');
        $table->string('description')->nullable(); 
         $table->string('value'); 

        $table->timestamps(); // created_at et updated_at
    });
}


    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        //
    }
};
