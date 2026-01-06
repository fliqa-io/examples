# Fliqa PHP code examples

Project contains PHP code examples referenced from [documentation.fliqa.io](https://documentation.fliqa.io)

> **NOTE:** The code examples provided are for illustration purposes only. **Use at own risk!**

## See following examples

- WebHook check of signature verification [webhook-utils.php](https://github.com/fliqa-io/examples/blob/main/php/webhook-utils.php)

### Usage

Include the verification in you code

```php
require_once __DIR__ . '/webhook-utils.php';
```

```php
public function webhook_listener()
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $rawData = file_get_contents('php://input');
            $data = json_decode($rawData, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new InvalidArgumentException('Missing signature.');
            }
               
            $headers = getallheaders();

            if (!isset($headers[self::X_SIGNATURE_HEADER]))
                $this->err('Missing X-Fliqa-Signature');


            $isValid = WebHookUtils::checkSignature($headers[self::X_SIGNATURE_HEADER],
                $this->webhook_secret,
                $this->webhook_secret_old,
                $this->get_webhook_url(),
                $rawData);
                
            if (!$isValid) {
                throw new InvalidArgumentException('Invalid Fliqa signature - stop processing!');
            }
    }
... 
}
```