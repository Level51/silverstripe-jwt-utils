# JWT Utils for SilverStripe
[![Build Status](https://travis-ci.org/Level51/silverstripe-jwt-utils.svg?branch=master)](https://travis-ci.org/Level51/silverstripe-jwt-utils)

Lean set of helper classes to deal with JWT in SilverStripe setups. 

## Example

```php
use Level51\JWTUtils\JWTUtils;
use Level51\JWTUtils\JWTUtilsException;

class MyTokenController extends Controller {

    private static $allowed_actions = ['token'];
    
    public function token() {
        try {
            $payload = JWTUtils::inst()->byBasicAuth($this->request);
            
            return json_encode($payload);
        } catch(JWTUtilsException $e) {
            return $this->httpError(403, $e->getMessage());
        }
    }
}
```

With correct config and credentials there will be a payload like the following:

```json
{
	"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtZW1iZXJJZCI6MSwiaXNzIjoiaHR0cDpcL1wvc2lsdmVyZ3JvdW5kLm1lXC8iLCJleHAiOjE1MTgyNzMwMjIsImlhdCI6MTUxNzY2ODIyMiwicmF0IjoxNTE3NjY4MjIyLCJqdGkiOiI0ZjIyMjViNS0wMzE5LTQ3YTMtYWNjMy1jOWJlNDk4MDc1NTIifQ.vQLLzmB7rWkwQDomAuC6Bfm-J0ITsIfFq4wL8UMAAJs",
	"member": {
		"id": 1,
		"email": "js@lvl51.de",
		"firstName": "Julian",
		"surname": "Scheuchenzuber"
	}
}
```

## Config

Make sure to include an environment variable `JWT_SECRET` and pick a random value.

```yaml
Level51\JWTUtils\JWTUtils:
  secret: '`JWT_SECRET`'          # Secret for signature. This is mandatory and there is no default value
  lifetime_in_days: 7             # Term of validity
  renew_threshold_in_minutes: 60  # Keep JWT for at least 60 minutes
```

## API

- `static inst()`: Get singleton instance
- `byBasicAuth($request, $includeMemberData: bool = true): array`: Creates a new token from Basic Auth member data
- `renew($token: string): string`: Checks if the given token is valid and needs to be renewed
- `check($token: string): bool`: Checks if token is valid and non-expired 

## Maintainer
- JZubero <js@lvl51.de>
