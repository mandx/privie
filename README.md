# 🔐 Privie 🔐

An experimental (and opinionated) CLI utility to manage secrets as part of code, managed with your source control system. This utility is heavily inspired by [`ejson`](https://github.com/Shopify/ejson), and so, it strives to keep all of its benefits, which are:

> * Secrets can be safely stored in a git repo.
> * Changes to secrets are auditable on a line-by-line basis with git blame.
> * Anyone with git commit access has access to write new secrets.
> * Decryption access can easily be locked down to production servers only.
> * Secrets change synchronously with application source (as opposed to secrets provisioned by Configuration Management).

There are also a couple more (opinionated) improvements:

* Keyrings are a single JSON file, instead of files named with random hashes. Now there's a single file with an explicit name to be added to `.gitignore`.
* Full support for `stdin`/`stdout`, plus explicit CLI flags to specify the input and output files.
* Handy subcommand to add and encrypt secrets to an existing secrets file; less hand editing files.
* Public keys are embedded in the encrypted secrets themselves, instead of a single public key shared for all the secrets in the document. This allows for two things:
 * JSON documents can now have an arbitrary structure, now there's no requirement for them to be an object. We could have a JSON document containing an array of strings, the individual strings inside the array can be encrypted too.
 * We can construct an encrypted secrets file in which each secret can have independent public keys, so, when decoding, only the keys in the keyring with a corresponding secret key will be decrypted; the rest of the secrets (those that couldn't be decrypted) will be left as-is in the output.

## Caveats
Unfortunately Privie can not (yet) be recommended for production environments, mainly because:
* I'm not cryptography expert! (Help is welcomed)
* The [cryptographic libraries used](https://github.com/RustCrypto) provide a good API, however they haven't been (yet) properly audited.

## Usage

### Keyrings

A keyring is a JSON document with a mapping of public keys and (optionally) their corresponding secret keys. We only need a public key to encrypt a secret, but we do need its corresponding secret key to decrypt that encrypted secret.

A keyring can be generated like this:
```
$ privie generate-keyring > my-keyring.json
# or
$ privie generate-keyring --output=my-keyring.json
```
By default generated keyrings are dumped to `stdout`, so we can use shell redirections (`>`) or the explicit `--output` parameter.

Now we have a keyring file that looks like this:
```
cat my-keyring.json
{"17EV2Rohy...Th0tJF36qfAw=":"hy9ZzHBn...8dpiqdIBxck8="}
```

Keyrings contain the secret keys required for decryption, so it's very important we keep these safe. *DO NOT commit these to any code repository!*.

### Encrypting

Assuming we have a file called `my-secrets.json` with this content:

```json
{
   "mongodb": "mongodb://m-user:m-pass@some-server.mlab.com:23022/someDb",
   "redis": "redis://r-user:r-pass@some-server.cloud.redislab.com:12345/1"
}
```

We can encrypt it using the keyring from the previous example:

```
$ privie encrypt --keyring=my-keyring.json --input=my-secrets.json --output=my-encrypted-secrets.json
```

<details>
<summary>We can also use `stdin` and/or `stdout` instead of `--input` and/or `--ouput`</summary>

For example, this command is equivalent to the previous one:

```
$ privie encrypt --keyring=my-keyring.json < my-secrets.json > my-encrypted-secrets.json
```

</details>

Now we have a `my-encrypted-secrets.json` file that looks something like this:

```
$ cat my-encrypted-secrets.json
{
  "mongodb": "17EV2Rohy...Th0tJF36qfAw=:qeGq09vNaBoDda8RWnmnT2zxF/B5jIeEtQ894Uy4...g9zBE2BPa08DVzt1sjHJxe",
  "redis": "17EV2Rohy...Th0tJF36qfAw=:cDbrdgVu446IA475Hq8HTDJb7FMKGXtlG8YAgGCbr1...7Cq0FXl+O41kKRSfEix3f70pJDK1K"
}
```

Now our secrets are encrypted and can be committed to our repository:

```
$ git add my-encrypted-secrets.json
$ git commit -m 'Add encrypted secrets file'
```

### Decrypting

```
$ privie decrypt --keyring=my-keyring.json --input=my-encrypted-secrets.json --output=my-decrypted-secrets.json
```

Similar to when decrypting; we use the `decrypt` subcommand instead of `encrypt` and reverse the `--input` and `--output` params. Now we have a `my-decrypted-secrets.json` file which is "equivalent" to the initial `my-secrets.json` file we had at the beginning. (They won't be exactly equal, since most formatting will be lost every time a JSON document is read and written).

### Sharing the keyring

This is where is up to the team to decide where to keep this file, and also, how to make it available in CI. For example, its possible to paste the content of the keyring as a Github secret, and write it to a file just before invoking `privie`:

```yaml
      - name: Decrypt the secrets file
        env:
          KEYRING_CONTENTS: ${{ secrets.KEYRING_CONTENTS }}
          EJSON_PRIVATE_KEY: ${{ secrets.EJSON_PRIVATE_KEY }}
        run: |
          echo $KEYRING_CONTENTS > my-keyring.json
          privie decrypt --keyring=my-keyring.json --input=my-encrypted-secrets.json --output=my-decrypted-secrets.json
```
