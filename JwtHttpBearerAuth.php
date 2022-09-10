<?php

namespace shanwker1223\jwt;

use Lcobucci\JWT\Token;
use yii\di\Instance;
use yii\filters\auth\AuthMethod;


class JwtHttpBearerAuth extends AuthMethod
{

    public Jwt|string|array $jwt = 'jwt';
    public string $realm = 'api';
    public string $schema = 'Bearer';
    public $auth;


    public function init()
    {
        parent::init();
        $this->jwt = Instance::ensure($this->jwt, Jwt::class);
    }


    public function authenticate($user, $request, $response)
    {
        $authHeader = $request->getHeaders()->get('Authorization');
        if ($authHeader !== null && preg_match('/^' . $this->schema . '\s+(.*?)$/', $authHeader, $matches)) {
            $token = $this->loadToken($matches[1]);
            if ($token === null) {
                return null;
            }

            if ($this->auth) {
                $identity = call_user_func($this->auth, $token, get_class($this));
            } else {
                $identity = $user->loginByAccessToken($token, get_class($this));
            }

            return $identity;
        }

        return null;
    }

    public function challenge($response)
    {
        $response->getHeaders()->set(
            'WWW-Authenticate',
            "{$this->schema} realm=\"{$this->realm}\", error=\"invalid_token\", error_description=\"The access token invalid or expired\""
        );
    }


    public function loadToken(string $token): ?Token
    {
        return $this->jwt->loadToken($token);
    }
}
