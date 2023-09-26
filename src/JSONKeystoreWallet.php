<?php

/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

namespace M8B\EtherBinder\Wallet;

use kornrunner\Keccak;
use M8B\EtherBinder\Crypto\Key;
use M8B\EtherBinder\Exceptions\EthBinderArgumentException;
use M8B\EtherBinder\Exceptions\EthBinderLogicException;
use M8B\EtherBinder\Exceptions\EthBinderRuntimeException;
use M8B\EtherBinder\Exceptions\NotSupportedException;

/**
 * JSONKeystoreWallet is encrypted json keystore wallet handler, it supports scrypt kdf wallets, and should be compatible
 * with most common implementations like MyEtherWallet and such. It can be used to wrap existing key, or generate new one
 *
 * @author DubbaThony
 */
class JSONKeystoreWallet extends AbstractWallet
{
	protected string $uuid;

	protected function __construct(){}

	/**
	 * Opens wallet from keystore. Accepts raw json string or json_decode()'d string. Throws EthBinderArgumentException
	 * if password does not match. If KDF is not scrypt, throws NotSupportedException.
	 *
	 * @throws NotSupportedException
	 * @throws EthBinderLogicException
	 * @throws EthBinderArgumentException
	 */
	public static function loadFromKeystore(array|string $keystore, #[\SensitiveParameter] string $password): static
	{
		try {
			if(is_string($keystore))
				$keystore = json_decode($keystore, true, 512, JSON_THROW_ON_ERROR);
		} catch(\JsonException $e) {
			throw new EthBinderArgumentException($e->getMessage(), $e->getCode(), $e);
		}

		$_this = new static();
		$_this->uuid = $keystore["uuid"] ?? "none";

		$crypto = $keystore["crypto"];
		list("ciphertext" => $cipherText, "cipher" => $cipher, "kdf" => $kdf, "mac" => $mac) = $crypto;
		if(strtolower($kdf) !== "scrypt")
			throw new NotSupportedException("not supported kdf: only scrypt is supported, but got ".$kdf);

		list("n" => $n, "r" => $r, "p" => $p, "dklen" => $dk, "salt" => $salt) = $crypto["kdfparams"];
		$kdfOutput = hex2bin(scrypt(
			$password,
			hex2bin(str_starts_with($salt, "0x") ? substr($salt, 2) : $salt),
			$n, $r, $p, $dk));

		try {
			if(bin2hex(Keccak::hash(substr($kdfOutput, 16, 16) . hex2bin($cipherText), 256, true)) !== $mac) {
				throw new EthBinderArgumentException("password was invalid");
			}
		} catch(\Exception $e) {
			throw new EthBinderLogicException($e->getMessage(), $e->getCode(), $e);
		}

		$iv        = $crypto["cipherparams"]["iv"];
		$_this->key = Key::fromBin(openssl_decrypt(
			hex2bin($cipherText),
			strtoupper($cipher),
			$kdfOutput,
			OPENSSL_RAW_DATA,
			hex2bin($iv),
		));

		$want = strtolower($keystore["address"] ?? null);
		$want = str_starts_with($want??"0x", "0x") ? $want : "0x".$want;
		$got  = strtolower($_this->key->toAddress()->toHex());
		if($want !== null && $want !== $got)
			throw new EthBinderArgumentException("failed to open wallet: invalid password or damaged keystore");
		return $_this;
	}

	/**
	 * Generates new private key and wraps it with JSON Keystore
	 *
	 * @throws EthBinderRuntimeException
	 */
	public static function generate(): static
	{
		try {
			$_this       = new static();
			$_this->key  = Key::fromBin(random_bytes(32));
			$_this->uuid = static::generateUUID();
		} catch(\Exception $e) {
			throw new EthBinderRuntimeException("failed to generate random bytes: ".$e->getMessage(), $e->getCode(), $e);
		}
		return $_this;
	}

	/**
	 * Encrypts key with given password and outputs json string
	 *
	 * @throws EthBinderRuntimeException
	 * @throws EthBinderLogicException
	 */
	public function export(
		#[\SensitiveParameter] string $password,
		bool $prettyPrint = false,
		int $scryptCost = 131072,
		string $algo = "aes-128-ctr"
	): string {
		$saltBin = openssl_random_pseudo_bytes(16);
		$kdfOutput = hex2bin(scrypt(
			$password,
			$saltBin,
			$scryptCost, 8, 1, 32));
		$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($algo));
		$cipher = openssl_encrypt($this->key->toBin(), $algo, $kdfOutput, OPENSSL_RAW_DATA, $iv);
		$mac = Keccak::hash(substr($kdfOutput, 16, 16).$cipher, 256, true);

		$output = [
			"version" => 3,
			"id"      => $this->uuid == "none" ? self::generateUUID() : $this->uuid,
			"address" => strtolower($this->key->toAddress()->toHex(false)),
			"crypto"  => [
				"ciphertext"   => bin2hex($cipher),
				"cipherparams" => ["iv" => bin2hex($iv)],
				"cipher"       => $algo,
				"kdf"          => "scrypt",
				"kdfparams" => [
					"dklen"  => 32,
					"salt"   => bin2hex($saltBin),
					"n"      => $scryptCost,
					"r"      => 8,
					"p"      => 1
				],
				"mac" => bin2hex($mac)
			]
		];

		return json_encode($output, $prettyPrint ? JSON_PRETTY_PRINT : 0);
	}

	/**
	 * @throws EthBinderRuntimeException
	 */
	protected static function generateUUID(): string
	{
		try {
			$data = random_bytes(16);
		} catch(\Exception $e) {
			throw new EthBinderRuntimeException("failed to generate random bytes: ".$e->getMessage(), $e->getCode(), $e);
		}
		$data[6] = chr(ord($data[6]) & 0x0f | 0x40);
		$data[8] = chr(ord($data[8]) & 0x3f | 0x80);

		return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
	}

	/**
	 * Instantiates wallet object from private key object (useful if you for example want to encrypt the key)
	 *
	 * @param Key $key
	 * @return static
	 * @throws EthBinderRuntimeException
	 */
	public static function wrap(#[\SensitiveParameter] Key $key): static
	{
		$_this       = new static();
		$_this->key  = $key;
		$_this->uuid = self::generateUUID();
		return $_this;
	}
}
