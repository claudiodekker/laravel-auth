<?php

namespace ClaudioDekker\LaravelAuth\Tests\Unit;

use ClaudioDekker\LaravelAuth\Tests\TestCase;
use CreateMultiFactorCredentialsTable;

class DatabaseMigrationTest extends TestCase
{
    /** @test */
    public function it_can_customize_the_database_connection(): void
    {
        $this->assertSame('testbench', (new CreateMultiFactorCredentialsTable())->getConnection());

        config(['laravel-auth.database.connection' => null]);

        $this->assertNull((new CreateMultiFactorCredentialsTable())->getConnection());
    }
}
