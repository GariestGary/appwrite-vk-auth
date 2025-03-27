<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;
use Utopia\Exception;

class Vk extends OAuth2
{
    private string $endpoint = 'https://api.vk.com/oauth/';
    private string $apiEndpoint = 'https://api.vk.com/method/';
    protected array $user = [];
    protected array $tokens = [];
    protected array $scopes = [
        "email"
    ];

    public function getName(): string
    {
        return 'vk';
    }

    public function getLoginURL(): string
    {
        $url = $this->endpoint . 'authorize?' . http_build_query([
            'client_id' => $this->appID,
            'redirect_uri' => $this->callback,
            'response_type' => 'code',
            'scope' => implode(' ', $this->getScopes()),
            'state' => json_encode($this->state),
            'v' => '5.131' // версия API
        ]);

        return $url;
    }

    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            $response = $this->request(
                'POST',
                $this->endpoint . 'access_token',
                [],
                http_build_query([
                    'client_id' => $this->appID,
                    'client_secret' => $this->appSecret,
                    'redirect_uri' => $this->callback,
                    'code' => $code
                ])
            );

            $this->tokens = json_decode($response, true);
        }

        return $this->tokens;
    }

    public function refreshTokens(string $refreshToken): array
    {
        $response = $this->request(
            'POST',
            $this->endpoint . 'access_token',
            [],
            http_build_query([
                'client_id' => $this->appID,
                'client_secret' => $this->appSecret,
                'refresh_token' => $refreshToken,
                'grant_type' => 'refresh_token'
            ])
        );

        $this->tokens = json_decode($response, true);
        return $this->tokens;
    }

    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);
        return $user['id'] ?? '';
    }

    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);
        return $user['email'] ?? '';
    }

    public function isEmailVerified(string $accessToken): bool
    {
        $user = $this->getUser($accessToken);
        return !empty($user['email']);
    }

    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);
        return $user['first_name'] . ' ' . $user['last_name'];
    }

    protected function getUser(string $accessToken): array
    {
        if (empty($this->user)) {
            $response = $this->request(
                'GET',
                $this->apiEndpoint . 'users.get?' . http_build_query([
                    'access_token' => $accessToken,
                    'fields' => 'email,first_name,last_name',
                    'v' => '5.131'
                ])
            );

            $data = json_decode($response, true);

            if (isset($data['response'][0])) {
                $this->user = $data['response'][0];
                // Email приходит отдельно в ответе на access_token
                $tokens = $this->getTokens('');
                if (isset($tokens['email'])) {
                    $this->user['email'] = $tokens['email'];
                }
            } else {
                throw new Exception('Failed to fetch user data');
            }
        }

        return $this->user;
    }
}