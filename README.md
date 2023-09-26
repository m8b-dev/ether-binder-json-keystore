# JSON Keystore Wallet for Ether Binder

This is separated from [Ether Binder](https://github.com/m8b-dev/ethbinder) library addon, due to extension dependency.

This library requires PECL extension `scrypt`. To install extension:

```shell
pecl install scrypt
```

Installing:

```shell
composer require m8b/ethbnd-keystore
```

## Usage

To read the existing json keystore, get the json and password, and drop it to `loadFromKeystore` function

```php
$keystore = file_get_contents("path/to/key.json");
$wallet   = \M8B\EtherBinder\Wallet\JSONKeystoreWallet::loadFromKeystore($keystore, "password"); 
```

To encrypt existing key

```php
$key = \M8B\EtherBinder\Crypto\Key::fromHex("0x....");
$wallet = \M8B\EtherBinder\Wallet\JSONKeystoreWallet::wrap($key);
file_put_contents($wallet->export("password"));
```

To generate new key and immediately wrap it with json keystore

```php
$wallet = \M8B\EtherBinder\Wallet\JSONKeystoreWallet::generate();
```

# License
Mozilla public license 2.0
