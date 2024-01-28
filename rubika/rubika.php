
<?php

include "./crypto.php";

class Rubika {
    private $auth;
    private $user_agent;
    private $private_key;
    private $phone_number;
    private $client = [
         "app_name" => "Main", 
         "app_version" => "4.4.5",
         "platform" => "Web", 
         "package" => "web.rubika.ir", 
         "lang_code" => "fa"
    ];

    public function __construct($phone_number) {
        $this->user_agent = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36";
        $this->phone_number = $phone_number;

        $response = self::send_code($this->phone_number);

        if ($response['status'] == 'OK') {
            $code_hash = $response['data']['phone_code_hash'];

            echo "code: ";
            $code = fgets(STDIN);

            $response = self::sign_in(
                $code, $this->phone_number, $code_hash
            );

            if ($response['status'] == 'OK') {
                $main_auth = Crypto::decrypt_rsa_oaep($this->private_key, $response['data']['auth']);

                $this->auth = $main_auth;
                $response['data']['auth'] = $main_auth;

                self::register_device();
            }
        echo json_encode($response);

        } else {
            echo "error: " . json_encode($response);
        }
    }

    private function request($data) {

        $url = "https://messengerg2c64.iranlms.ir/";

        $headers = array(
            "User-Agent: " . $this->user_agent,
            "content-type: application/json",
            "Origin: https://web.rubika.ir",
            "Referer: https://web.rubika.ir",
            "Host: messengerg2c64.iranlms.ir",
        );

        while (true) { 
            $_curl= curl_init($url);
    
            curl_setopt($_curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($_curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($_curl, CURLOPT_POSTFIELDS, json_encode($data));
    
            $response = curl_exec($_curl);
            $status = curl_getinfo($_curl, CURLINFO_HTTP_CODE);

            curl_close($_curl);

            if ($status == 200) {
                return json_decode($response, true);
            } else {
                continue;
            }
        }
    }

    public function send_code($phone, $pass_key = null) {
        $tmp = Crypto::random_tmp(32);
        $crypto = new Crypto($tmp);

        $data = [
            "api_version" => "6",
            "tmp_session" => $tmp,
            "data_enc" => $crypto->encrypt([
                "method" => "sendCode",
                "input" => [
                    "phone_number" => $phone,
                    "send_type" => "SMS",
                    "pass_key" => $pass_key
                    ],
                "client" => $this->client
            ])
        ];

        $response = self::request($data);

        $result = json_decode($crypto->decrypt($response['data_enc']),
            true);

        $this->auth = $tmp;

        return $result;
    }

    public function sign_in($code, $phone, $phone_code_hash) {
        $crypto = new Crypto($this->auth);
        $keys = Crypto::generate_keys();
        $public_key = $keys[0];
        $private_key = $keys[1];

        $input = $crypto->encrypt([
            "method" => "signIn",
            "input" => [
                "phone_code" => $code,
                "phone_number" => $phone,
                "public_key" => $public_key,
                "phone_code_hash" => $phone_code_hash
            ],
            "client" => $this->client
        ]);

        $data = [
            "api_version" => "6",
            "tmp_session" => $this->auth,
            "data_enc" => $input,
        ];

        $response = self::request($data);

        $result = json_decode($crypto->decrypt($response['data_enc']),
            true);

        $this->private_key = $private_key;

        return $result;
    }

    public function register_device() {
        $auth_dec = Crypto::decode_auth($this->auth);
        $crypto = new Crypto($this->auth);

        preg_match_all('/\d+/', $this->user_agent, $matches);

        $php_version = phpversion();
        $device_hash = implode('', $matches[0]);

        $input = $crypto->encrypt([
            "method" => "registerDevice",
            "input" => [
                "token_type" => "Web",
                "token" => "",
                "app_version" => "WB_1.0.0",
                "lang_code" => "fa",
                "system_version" => "php " . $php_version,
                "device_model" => "php-lib",
                "device_hash" => $device_hash,
            ],
            "client" => $this->client
        ]);

        $signature = Crypto::sign($this->private_key,  $input);

        $data = [
            "api_version" => "6",
            "auth" => $auth_dec,
            "data_enc" => $input,
            "sign" => $signature,
        ];

        $response = self::request($data);

        $result = json_decode($crypto->decrypt($response['data_enc']),
            true);

        return $result;
    }

    public function get_contacts($start_id = null) {
        $auth_dec = Crypto::decode_auth($this->auth);
        $crypto = new Crypto($this->auth);

        $input = $crypto->encrypt([
            "method" => "getContacts",
            "input" => [
                "start_id" => $start_id
            ],
            "client" => $this->client
        ]);

        $signature = Crypto::sign($this->private_key,  $input);

        $data = [
            "api_version" => "6",
            "auth" => $auth_dec,
            "data_enc" => $input,
            "sign" => $signature,
        ];

        $response = self::request($data);

        $result = json_decode($crypto->decrypt($response['data_enc']),
            true);

        return $result;
    }
}

echo "phone numbe (989000000000): ";

$phone = fgets(STDIN);

$rubika = new Rubika($phone);

$result = $rubika->get_contacts();

echo json_encode($result);

?>
