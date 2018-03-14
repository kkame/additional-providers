<?php

class Hybrid_Providers_Payco extends Hybrid_Provider_Model_OAuth2
{
    /**
     * initialization
     */
    function initialize()
    {
        parent::initialize();

        $this->api->api_base_url = "https://apis3.krp.toastoven.net";
        $this->api->authorize_url = "https://id.payco.com/oauth2.0/authorize";
        $this->api->token_url = "https://id.payco.com/oauth2.0/token";
    }

    /**
     * begin login step
     */
    function loginBegin()
    {
        $token = $this->generate_state_token();
        Hybrid_Auth::storage()->set("payco_state_token", $token);

        $parameters = [
            "response_type" => "code",
            "client_id" => $this->api->client_id,
            "redirect_uri" => $this->api->redirect_uri,
            "state" => $token,
            "serviceProviderCode" => "FRIENDS",
        ];

        Hybrid_Auth::redirect($this->api->authorizeUrl($parameters));
    }

    /**
     * finish login step
     */
    function loginFinish()
    {
        $error = (array_key_exists('error', $_REQUEST)) ? $_REQUEST['error'] : "";
        // check for errors

        if ($error)
            throw new Exception("Authentication failed! {$this->providerId} returned an error: $error", 5);

        // try to authenicate user
        $code = (array_key_exists('code', $_REQUEST)) ? $_REQUEST['code'] : "";
        try {
            $this->authenticate($code);
        } catch (Exception $e) {
            throw new Exception("User profile request failed! {$this->providerId} returned an error: $e", 6);
        }

        // check if authenticated
        if (!$this->api->access_token)
            throw new Exception("Authentication failed! {$this->providerId} returned an invalid access token.", 5);

        // store tokens
        $this->token("access_token", $this->api->access_token);
        $this->token("refresh_token", $this->api->refresh_token);
        $this->token("expires_in", $this->api->access_token_expires_in);
        $this->token("expires_at", $this->api->access_token_expires_at);

        // set user connected locally
        $this->setUserConnected();
    }

    /**
     * set propper headers
     */
    function profile()
    {
        $url = $this->api->api_base_url . "/payco/friends/getMemberProfileByFriendsToken.json";

        $json_data = json_encode([
            'client_id' => $this->api->client_id,
            'access_token' => $this->api->access_token,
        ]);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Content-Length: '.strlen($json_data),
            'client_id:'.$this->api->client_id,
            'access_token:'.$this->api->access_token,
        ));
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POST, 1);

        $response = curl_exec($ch);

        return json_decode($response)->memberProfile;
    }

    /**
     * load the user profile
     */
    function getUserProfile()
    {
        $response = $this->profile();

        # store the user profile.
        $this->user->profile->identifier = $response->idNo;
        $this->user->profile->age = $response->ageGroup;
        $this->user->profile->displayName = $response->name;
        $this->user->profile->birthDay = $response->birthdayMMdd;
        $this->user->profile->email = $response->id;
        $this->user->profile->gender = $response->sexCode;

        return $this->user->profile;
    }

    private function authenticate($code)
    {
        $params = array(
            "grant_type" => "authorization_code",
            "client_id" => $this->api->client_id,
            "client_secret" => $this->api->client_secret,
            "code" => $code,

            // "state" =>
        );

        Hybrid_Auth::storage()->set("payco_state_token", null);

        $response = $this->request($this->api->token_url, $params, $this->api->curl_authenticate_method);
        $response = $this->parseRequestResult($response);

        if (!$response || !isset($response->access_token)) {
            throw new Exception("The Authorization Service has return: " . $response->error);
        }

        if (isset($response->access_token)) $this->api->access_token = $response->access_token;
        if (isset($response->refresh_token)) $this->api->refresh_token = $response->refresh_token;
        if (isset($response->expires_in)) $this->api->access_token_expires_in = $response->expires_in;

        // calculate when the access token expire
        if (isset($response->expires_in))
            $this->api->access_token_expires_at = time() + $response->expires_in;

        return $response;
    }

    private function request($url, $params = false, $type = "GET")
    {
        Hybrid_Logger::info("Enter OAuth2Client::request( $url )");
        Hybrid_Logger::debug("OAuth2Client::request(). dump request params: ", serialize($params));

        $this->http_info = array();
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->api->curl_time_out);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->api->curl_useragent);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->api->curl_connect_time_out);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->api->curl_ssl_verifypeer);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $this->api->curl_header);

        if ($this->api->curl_proxy) {
            curl_setopt($ch, CURLOPT_PROXY, $this->curl_proxy);
        }

        if ($type == "POST") {
            curl_setopt($ch, CURLOPT_POST, 1);
            if ($params) curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        }

        $response = curl_exec($ch);

        Hybrid_Logger::debug("OAuth2Client::request(). dump request info: ", serialize(curl_getinfo($ch)));
        Hybrid_Logger::debug("OAuth2Client::request(). dump request result: ", serialize($response));

        $this->http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->http_info = array_merge($this->http_info, curl_getinfo($ch));

        curl_close($ch);

        return $response;
    }

    private function parseRequestResult($result)
    {
        if (json_decode($result)) return json_decode($result);

        parse_str($result, $ouput);
        $result = new StdClass();

        foreach ($ouput as $k => $v)
            $result->$k = $v;

        return $result;
    }

    private function generate_state_token()
    {
        $mt = microtime();
        $rand = mt_rand();

        return md5($mt . $rand);
    }
}
