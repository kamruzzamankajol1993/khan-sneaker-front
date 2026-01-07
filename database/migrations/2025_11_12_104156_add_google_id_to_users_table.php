<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('google_id')->nullable()->after('id');
            $table->string('phone')->nullable()->change(); // <-- Make phone nullable
        });

        // Also make the 'customers' table phone nullable
        Schema::table('customers', function (Blueprint $table) {
             $table->string('phone')->nullable()->change();
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('google_id');
            $table->string('phone')->nullable(false)->change(); // Revert 'phone'
        });

        Schema::table('customers', function (Blueprint $table) {
            $table->string('phone')->nullable(false)->change(); // Revert 'phone'
        });
    }
};