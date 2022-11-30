<?php

namespace ClaudioDekker\LaravelAuth;

use ClaudioDekker\LaravelAuth\Database\Factories\MultiFactorCredentialFactory;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;

class MultiFactorCredential extends Model
{
    use HasFactory;

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'multi_factor_credentials';

    /**
     * The "type" of the primary key ID.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * Indicates if the IDs are auto-incrementing.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'created_at' => 'datetime',
        'secret' => 'encrypted',
        'type' => CredentialType::class,
    ];

    /**
     * The guarded attributes on the model.
     *
     * @var array
     */
    protected $guarded = [];

    /**
     * The name of the "updated at" column.
     *
     * @var string|null
     */
    public const UPDATED_AT = null;

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array
     */
    protected $hidden = [
        'secret',
    ];

    /**
     * Create a new factory instance for the model.
     *
     * @return \Illuminate\Database\Eloquent\Factories\Factory
     */
    protected static function newFactory(): Factory
    {
        return MultiFactorCredentialFactory::new();
    }

    /**
     * Get the user that the Multi-Factor Registration belongs to.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function user()
    {
        $guard = Config::get('auth.defaults.guard');
        $provider = Config::get('auth.guards.'.$guard.'.provider');
        $model = Config::get('auth.providers.'.$provider.'.model');

        return $this->belongsTo($model, 'user_id', (new $model())->getKeyName());
    }

    /**
     * Get the current connection name for the model.
     */
    public function getConnectionName(): ?string
    {
        return Config::get('laravel-auth.database.connection') ?? $this->connection;
    }
}
