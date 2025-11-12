<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('assign_chart_entries', function (Blueprint $table) {
            $table->id();
            $table->foreignId('assign_chart_id');
            $table->string('size'); // e.g., S, M, L
            $table->string('length')->nullable();
            $table->string('width')->nullable();
            $table->string('shoulder')->nullable();
            $table->string('sleeve')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('assign_chart_entries');
    }
};
