<?php

namespace Shortcodes\Jwt\Services\Auth;

use App\User;
use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Log;

class JwtGuard implements Guard
{
    use GuardHelpers;

    protected $request;
    protected $inputKey;

    public function __construct(UserProvider $provider, Request $request = null)
    {
        $this->request = $request;
        $this->provider = $provider;
        $this->inputKey = 'X-Authorization';
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        $token = $this->getTokenForRequest();

        if (!$token) {
            return null;
        }

        try {

            $decoded = JWT::decode($token, env("JWT_SECRET"), [env("JWT_ALGO")]);

            $user = User::find($decoded->user_id);
            $this->setUser($user);
            return $user;

        } catch (\Exception $e) {
            Log::info('Provided token is incorrect : ' . $e->getMessage());
        }

        return null;
    }

    public function getUserFromToken($token)
    {
        try {

            $decoded = JWT::decode($token, env("JWT_SECRET"), [env("JWT_ALGO")]);

            $user = User::find($decoded->user_id);
            $this->setUser($user);
            return $user;

        } catch (\Exception $e) {
            Log::info('Provided token is incorrect : ' . $e->getMessage());
        }

        return null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (empty($credentials[$this->inputKey])) {
            return false;
        }

        $token = $credentials[$this->inputKey];
        $decoded = JWT::decode($token, env("JWT_SECRET"), [env("JWT_ALGO")]);

        if ($decoded && $decoded->purpose == 'authenticate') {
            return true;
        }

        return false;
    }

    public function getTokenForRequest()
    {
        $token = $this->request->header($this->inputKey);

        if (empty($token)) {
            $token = $this->request->input($this->inputKey);
        }

        if (empty($token)) {
            $token = $this->request->bearerToken();
        }

        if (empty($token)) {
            $token = $this->request->getPassword();
        }

        return $token;
    }

    public function attempt(array $credentials = [], $rememberMe = false)
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
            return $this->geterateJwtToken($user, $rememberMe);
        }

        return false;
    }

    protected function hasValidCredentials($user, $credentials)
    {
        return !is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }

    public function generateJwtTokenForUser(Authenticatable $authenticable, $remember = false)
    {
        return $this->geterateJwtToken($authenticable,$remember);
    }

    protected function geterateJwtToken($user, $rememberMe = null)
    {
        $key = env('JWT_SECRET');

        $token = array(
            "iss" => env('APP_URL'),
            "iat" => Carbon::now()->timestamp,
            "email" => $user->email,
            "purpose" => 'authenticate',
            "user_id" => $user->id,
        );

        if ($rememberMe !== true) {
            $token['exp'] = Carbon::now()->addHour(1)->timestamp;
        }

        return JWT::encode($token, $key);
    }


}
