<?php

namespace FoskyM\OAuthCenter\Middlewares;

use Flarum\Foundation\ErrorHandling\ExceptionHandler\IlluminateValidationExceptionHandler;
use Flarum\Foundation\ErrorHandling\JsonApiFormatter;
use Flarum\Settings\SettingsRepositoryInterface;
use Flarum\User\User;
use FoskyM\OAuthCenter\OAuth;
use FoskyM\OAuthCenter\Storage;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Flarum\Http\RequestUtil;
use FoskyM\OAuthCenter\Models\Scope;

class ResourceScopeAuthMiddleware implements MiddlewareInterface
{
    const TOKEN_PREFIX = 'Bearer ';
    protected $settings;
    public function __construct(SettingsRepositoryInterface $settings)
    {
        $this->settings = $settings;
    }
    public function process(Request $request, RequestHandlerInterface $handler): Response
    {
        if (!$request->getAttribute('originalUri')) {
            return $handler->handle($request);
        }

        $headerLine = $request->getHeaderLine('authorization');

        $parts = explode(';', $headerLine);

        if (isset($parts[0]) && Str::startsWith($parts[0], self::TOKEN_PREFIX)) {
            $token = substr($parts[0], strlen(self::TOKEN_PREFIX));
        } else {
            $token = Arr::get($request->getQueryParams(), 'access_token', '');
        }
        $path = $request->getAttribute('originalUri')->getPath();

        if ($token !== '' && $scopes = Scope::get_path_scope($path)) {
            try {
                $oauth = new OAuth($this->settings);
                $server = $oauth->server();
                $oauth_request = $oauth->request()::createFromGlobals();
                
                // Validate token ONCE
                if (!$server->verifyResourceRequest($oauth_request)) {
                    return new JsonResponse(json_decode($server->getResponse()->getResponseBody(), true) ?: [], $server->getResponse()->getStatusCode(), $server->getResponse()->getHttpHeaders());
                }

                $tokenData = $server->getAccessTokenData($oauth_request);
                $tokenScopes = explode(' ', $tokenData['scope'] ?? '');

                $has_scope = false;
                $filtered_scopes = [];
                
                foreach ($scopes as $scope) {
                    if (strtolower($request->getMethod()) === strtolower($scope->method)) {
                        if (in_array($scope->scope, $tokenScopes)) {
                            $filtered_scopes[] = $scope;
                            $has_scope = true;
                        }
                    }
                }
                
                if (!$has_scope) {
                    return new JsonResponse(['error' => 'insufficient_scope', 'error_description' => 'The request requires higher privileges than provided by the access token'], 403);
                }
                $actor = User::find($tokenData['user_id']);
                $request = RequestUtil::withActor($request, $actor);
                $request = $request->withAttribute('oauth.scopes', $filtered_scopes);
                $request = $request->withAttribute('bypassCsrfToken', true);
                $request = $request->withoutAttribute('session');

            } catch (ValidationException $exception) {

                $handler = resolve(IlluminateValidationExceptionHandler::class);

                $error = $handler->handle($exception);

                return (new JsonApiFormatter())->format($error, $request);
            }

        }

        return $handler->handle($request);
    }
}
