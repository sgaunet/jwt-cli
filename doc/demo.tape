# jwt-cli demo — regenerate with: task demo
#
# Every command below is self-contained: no key files, no fixtures from tests/.
# That matters because *pem, *.key and *.pub are gitignored, so a fresh clone
# has no key material and any tape depending on it would render a broken demo.

Output doc/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type "export PATH=$PWD:$PATH" Enter
Type "export PS1='$ '" Enter
Type "clear" Enter
Show

Type "# jwt-cli — encode and decode JWT and PASETO tokens" Enter
Sleep 1s

Type "# 1. Sign a JWT with HS256" Enter
Sleep 500ms
Type "SECRET='this-is-a-valid-32-byte-secret!!'" Enter
Sleep 300ms
Type `TOKEN=$(jwt-cli encode hs256 --payload '{"email":"demo@example.com"}' --secret "$SECRET")` Enter
Sleep 500ms
Type "echo $TOKEN" Enter
Sleep 2s

Type "# 2. Decode it back — the signature is verified first" Enter
Sleep 500ms
Type `jwt-cli decode hs256 --token "$TOKEN" --secret "$SECRET"` Enter
Sleep 2s

Type "# 3. A wrong secret is rejected" Enter
Sleep 500ms
Type `jwt-cli decode hs256 --token "$TOKEN" --secret "this-is-a-DIFFERENT-32-byte-key!!"` Enter
Sleep 2500ms

Type "# 4. PASETO v4 too — here with --json output" Enter
Sleep 500ms
Type "KEY=$(openssl rand -hex 32)" Enter
Sleep 300ms
Type `PTOKEN=$(jwt-cli paseto encode local --key "$KEY" --payload '{"email":"demo@example.com"}')` Enter
Sleep 500ms
Type `jwt-cli paseto decode local --json --key "$KEY" --token "$PTOKEN"` Enter
Sleep 3s
