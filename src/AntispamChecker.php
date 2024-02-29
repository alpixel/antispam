<?php

namespace Alpixel\Antispam;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;

class AntispamChecker
{
    private $domainKey;

    public function __construct(string $domainKey)
    {
        $this->domainKey = $domainKey;
    }

    public function isSpam(string $locale, array $data, string $messageField = null): bool
    {
        //Prepare the data
        $body = [
            'locale' => $locale,
            'fields' => $data,
        ];

        if ($messageField !== null) {
            $body['message_field'] = $messageField;
        }

        $client = new Client(['timeout' => 2.0]);
        $headers = [
            'x-domain-key' => $this->domainKey,
            'Referer' => $_SERVER['HTTP_HOST'],
            'Content-Type' => 'application/json',
        ];
        $request = new Request('POST', 'https://antispam.alpixel.net/captcha/check', $headers, json_encode($body));

        try {
            $res = $client->send($request);
            $json = json_decode($res->getBody());

            return !$json->is_clean;
        } catch (\Exception $e) {
            return false;
        }

    }
}