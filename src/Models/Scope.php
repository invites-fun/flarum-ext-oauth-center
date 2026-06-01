<?php

/*
 * This file is part of foskym/flarum-oauth-center.
 *
 * Copyright (c) 2023 FoskyM.
 *
 * For the full copyright and license information, please view the LICENSE.md
 * file that was distributed with this source code.
 */
namespace FoskyM\OAuthCenter\Models;

use Flarum\Database\AbstractModel;

use Illuminate\Contracts\Cache\Store as Cache;

class Scope extends AbstractModel
{
    protected $table = 'oauth_scopes';
    protected $guarded = [];
    public static function boot()
    {
        parent::boot();

        static::saved(function ($scope) {
            resolve(Cache::class)->forget('foskym.oauth-center.scopes');
        });

        static::deleted(function ($scope) {
            resolve(Cache::class)->forget('foskym.oauth-center.scopes');
        });
    }

    static public function get_path_scope($path = '')
    {
        /** @var Cache $cache */
        $cache = resolve(Cache::class);
        $key = 'foskym.oauth-center.scopes';

        $scopes = $cache->get($key);
        if ($scopes === null) {
            $scopes = self::all();
            $cache->forever($key, $scopes);
        }

        return $scopes->filter(function ($scope) use ($path) {
            return \Illuminate\Support\Str::startsWith($scope->resource_path, $path) 
                || \Illuminate\Support\Str::startsWith($path, $scope->resource_path);
        });
    }
}
