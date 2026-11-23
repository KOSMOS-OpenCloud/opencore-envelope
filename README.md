# opencore-envelope

Umschlagformat des OpenCore-Keystores: ein Geheimnis (z. B. der Inhaltsschlüssel eines Keystore-Eintrags) wird für
genau einen Empfängerschlüssel verschlossen, gebunden an dessen Key-ID und an einen Kontext (z. B. die Eintrags-ID).

- Suite v1: HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
- Key-ID: RFC-7638-JWK-Thumbprint (SHA-256, base64url) des X25519-Schlüssels
- HPKE-Info: drei Teile (Zweck, Key-ID, Kontext), je mit 4 Byte Länge (big endian) davor
- Einträge: AES-256-GCM mit dem Inhaltsschlüssel, Associated Data = Info(`opencore/keystore/v1/entry`, "", Eintrags-ID)

Genutzt von opencloud (`pkg/keystore`, Schlüsselspeicher des IdP), opendock (Keystore der dApps) und Diensten, die
für sie Verschlossenes öffnen (z. B. der Mail-Connector openfetchmail). Andere Sprachen prüfen gegen
`testdata/vectors.json`.

Ursprung: unverändert aus opencloud `pkg/keystore/envelope.go` (KOSMOS, 2026-11-17) herausgelöst; Umschläge von vorher
öffnen weiter. Lizenz: Apache-2.0.
