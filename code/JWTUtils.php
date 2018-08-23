<?php

use \Firebase\JWT\JWT as JWT;
use \Carbon\Carbon;
use \Ramsey\Uuid\Uuid;

/**
 * Utility Class for handling JWTs.
 */
class JWTUtils {

    /**
     * @var int Config: JWT lifetime
     */
    private static $lifetime_in_days = 7;

    /**
     * @var int Config: Relevant for 'rat' claim (renewed at)
     */
    private static $renew_threshold_in_minutes = 60;

    /**
     * @var JWTUtils Singleton instance holder
     */
    private static $instance = null;

    /**
     * @var array Default member fields included in the response
     */
    private static $default_member_fields = [
        'id'        => 'ID',
        'email'     => 'Email',
        'firstName' => 'FirstName',
        'surname'   => 'Surname'
    ];

    /**
     * @return JWTUtils
     * @throws JWTUtilsException
     */
    public static function inst() {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Clears the singleton instance. Helps with PHPUnit testing.
     */
    public static function tearDown() {
        self::$instance = null;
    }

    /**
     * JWTUtils constructor.
     * @throws JWTUtilsException
     */
    private function __construct() {
        if (!$this->hasValidSecret()) {
            throw new JWTUtilsException('No "secret" config found.');
        }
    }

    /**
     * Disables the magic clone method
     */
    private function __clone() { }

    /**
     * Checks for a valid "secret" config
     *
     * @return bool
     */
    private function hasValidSecret() {
        return boolval(Config::inst()->get(self::class, 'secret'));
    }

    /**
     * @return int Unix timestamp of token expiration
     */
    private function calcExpirationClaim() {
        return Carbon::now()->addDays(Config::inst()->get(self::class, 'lifetime_in_days'))->timestamp;
    }

    /**
     * Generates a fresh set of default claims.
     *
     * @return array
     */
    public function getClaims() {
        $claims = [
            'iss' => Config::inst()->get(self::class, 'iss') ?: Director::absoluteBaseURL(),
            'exp' => $this->calcExpirationClaim(),
            'iat' => time(),
            'rat' => time(),
            'jti' => Uuid::uuid4()->toString()
        ];

        return $claims;
    }

    /**
     * Get the member fields which should be appended to the response.
     *
     * Can be set through the "included_member_fields" config, self::$default_member_fields per default.
     *
     * @return array
     */
    private function getMemberFields() {
        if ($fields = Config::inst()->get(self::class, 'included_member_fields'))
            return $fields;

        return self::$default_member_fields;
    }

    /**
     * Creates a new token from Basic Auth member data
     *
     * TODO add param for custom claims
     *
     * @param bool $includeMemberData
     *
     * @return array
     * @throws JWTUtilsException
     */
    public function byBasicAuth($includeMemberData = true) {

        // Try to authenticate member with basic auth
        try {
            $member = BasicAuth::requireLogin('', null, false);
        } catch (SS_HTTPResponse_Exception $e) {
            throw new JWTUtilsException($e->getResponse()->getBody());
        }

        return $this->byMember($member, $includeMemberData);
    }

    /**
     * Creates a new token from user credentials.
     *
     * @param string $uniqueIdentifier @see Member::$unique_identifier_field (Email per default)
     * @param string $password
     * @param bool $includeMemberData
     * @param array $customClaims
     *
     * @return array
     * @throws JWTUtilsException
     */
    public function byIdentifierAndPassword($uniqueIdentifier, $password, $includeMemberData = true, $customClaims = []) {
        $member = Member::get()->find(Config::inst()->get(Member::class, 'unique_identifier_field'), $uniqueIdentifier);

        // Respond with "wrong credentials" message if the user was not found.
        if (!$member)
            throw new JWTUtilsException(_t('Member.ERRORWRONGCRED'));

        try {
            $result = $member->checkPassword($password);
        } catch (Exception $e) {
            throw new JWTUtilsException($e->getMessage());
        }

        if (!$result->valid())
            throw new JWTUtilsException($result->message());

        return $this->byMember($member, $includeMemberData, $customClaims);
    }

    /**
     * Creates a new token from a given Member object.
     *
     * @param Member $member
     * @param bool $includeMemberData
     * @param array $customClaims
     *
     * @return array
     */
    public function byMember($member, $includeMemberData = true, $customClaims = []) {
        $claims = array_merge($customClaims, $this->getClaims());

        $token = JWT::encode($claims, Config::inst()->get(self::class, 'secret'));

        $payload = [
            'token' => $token
        ];

        // Check if member data should be included
        if ($includeMemberData) {
            $memberData = [];
            foreach ($this->getMemberFields() as $key => $field) {
                $memberData[$key] = $member->$field;
            }
            $payload['member'] = $memberData;
        }

        return $payload;
    }

    /**
     * Checks if the given token is valid and needs to be renewed
     *
     * @param string $token The decoded token to renew
     *
     * @return string The renewed decoded token
     * @throws JWTUtilsException            Provided JWT was: simply invalid, invalid because the signature verification failed, since expired, as defined by the 'exp' claim
     */
    public function renew($token) {

        try {
            $jwt = (array)JWT::decode(
                $token,
                Config::inst()->get(self::class, 'secret'),
                ['HS256']);
        } catch (Exception $e) {
            throw new JWTUtilsException($e->getMessage());
        }

        // TODO: Check if script reaches this point if exp claim is in past

        // Check if token needs to be renewed
        $renewedAt = Carbon::createFromTimestamp($jwt['rat']);
        if ($renewedAt->diffInMinutes(Carbon::now()) <
            Config::inst()->get(self::class, 'renew_threshold_in_minutes')) {

            // Token was refreshed less than an hour ago, return same token
            return $token;
        }

        // Update 'exp' and 'rat' claims
        $jwt['exp'] = $this->calcExpirationClaim();
        $jwt['rat'] = time();

        // Renew and return token
        return JWT::encode(
            $jwt,
            'test');
    }

    /**
     * Checks if token is valid and non-expired
     *
     * @param string $token
     *
     * @return bool
     */
    public function check($token) {
        try {
            JWT::decode(
                $token,
                Config::inst()->get(self::class, 'secret'),
                ['HS256']);

            return true;
        } catch (Exception $e) {

            return false;
        }
    }
}
