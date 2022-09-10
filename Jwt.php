<?php

namespace shanwker1223\jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha384;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use RuntimeException;
use Yii;
use yii\base\Component;

/**
 * JSON Web Token implementation, based on this library:
 * https://github.com/lcobucci/jwt
 *
 * @author Dmitriy Demin <sizemail@gmail.com>
 * @since 1.0.0-a
 */
class Jwt extends Component
{
    public ?Signer $signingAlgorithm = null;
    public Key $signingKey;
    public ?Key $verificationKey = null;
    public ?Encoder $encoder = null;
    public ?Decoder $decoder = null;

    protected bool $isAsymmetric = false;
    protected ?Configuration $configuration = null;
    protected const _SUPPORTED_ALGORITHMS = [
        'HS256' => Sha256::class,
        'HS384' => Sha384::class,
        'HS512' => Sha512::class,
        'ES256' => Signer\Ecdsa\Sha256::class,
        'ES384' => Signer\Ecdsa\Sha384::class,
        'ES512' => Signer\Ecdsa\Sha512::class,
        'RS256' => Signer\Rsa\Sha256::class,
        'RS384' => Signer\Rsa\Sha384::class,
        'RS512' => Signer\Rsa\Sha512::class,
    ];

    public function __construct(array $config = [])
    {
        parent::__construct($config);

        if ($this->verificationKey !== null) {
            $this->isAsymmetric = true;
        }
    }


    public function getBuilder(Encoder $encoder = null): Builder
    {
        return $this->getConfig()->builder();
    }

    protected function getConfig(): Configuration
    {
        if ($this->configuration === null) {
            $this->configuration = $this->createConfiguration();

        }
        return $this->configuration;
    }

    protected function createConfiguration(): Configuration
    {
        if ($this->isAsymmetric()) {
            return Configuration::forAsymmetricSigner(
                $this->getSigningAlgorithm(),
                $this->getSigningKey(),
                $this->getVerificationKey(),
                $this->getEncoder(),
                $this->getDecoder()
            );
        }
        return Configuration::forSymmetricSigner(
            $this->getSigningAlgorithm(),
            $this->getSigningKey(),
            $this->getEncoder(),
            $this->getDecoder()
        );
    }

    public function getParser(): Parser
    {
        return $this->getConfig()->parser();
    }

    public function loadToken(string $token, bool $validate = true, bool $verify = true): ?Token
    {
        try {
            $token = $this->getParser()->parse($token);
        } catch (RuntimeException|\InvalidArgumentException $e) {
            Yii::warning('Invalid JWT provided: ' . $e->getMessage(), 'jwt');
            return null;
        }

        if ($validate && !$this->validateToken($token)) {
            return null;
        }

        return $token;
    }

    public function validateToken(Token $token): bool
    {
        return $this->getConfig()->validator()->validate($token);
    }

    /**
     * @return Signer
     */
    public function getSigningAlgorithm(): Signer
    {
        return $this->signingAlgorithm ?? new Sha256();
    }

    /**
     * @return Key
     */
    public function getSigningKey(): Key
    {
        return $this->signingKey;
    }

    /**
     * @return Key|null
     */
    public function getVerificationKey(): ?Key
    {
        return $this->verificationKey;
    }

    /**
     * @return Encoder|null
     */
    public function getEncoder(): ?Encoder
    {
        return $this->encoder;
    }

    /**
     * @return Decoder|null
     */
    public function getDecoder(): ?Decoder
    {
        return $this->decoder;
    }

    /**
     * @return bool
     */
    public function isAsymmetric(): bool
    {
        return $this->isAsymmetric;
    }
}
