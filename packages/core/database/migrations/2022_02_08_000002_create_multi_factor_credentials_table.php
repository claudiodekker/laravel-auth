<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateMultiFactorCredentialsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('multi_factor_credentials', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->string('type');
            $table->unsignedBigInteger('user_id')->nullable()->index();
            $table->string('name');
            $table->text('secret');
            $table->timestamp('created_at')->nullable();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('multi_factor_credentials');
    }
}
