/**
 * OWASP Mobile Application Security (MASVS + MASTG)
 * Checklist completo para testes de segurança em aplicativos Android e iOS
 * Baseado no OWASP MASVS v2.0 e MASTG (Mobile Application Security Testing Guide)
 */

export const mobileSecurityChecklist = {
  id: "owasp-mobile",
  name: "Mobile Security (MASVS)",
  description: "OWASP Mobile Application Security Verification Standard (MASVS) - Testes para Android e iOS cobrindo armazenamento, criptografia, autenticação, rede, plataforma e resiliência.",
  sections: [
    {
      id: "masvs-storage",
      title: "MASVS-STORAGE: Armazenamento Seguro",
      summary: "Proteção de dados sensíveis em armazenamento local (SharedPreferences, Keychain, SQLite, arquivos).",
      items: [
        {
          id: "storage-1",
          title: "Verificar armazenamento de dados sensíveis em plain text",
          description: "Validar se credenciais, tokens, PII não estão salvos em SharedPreferences/UserDefaults sem criptografia.",
          guide: {
            overview: "Apps frequentemente salvam tokens, senhas, dados pessoais em armazenamento local sem criptografia, permitindo acesso via backup, device rooted, ou forensics.",
            impact: "Vazamento de credenciais, tokens de sessão, dados pessoais (CPF, cartão) em caso de device perdido/rooted.",
            detection: [
              "Android: Extrair /data/data/[package]/shared_prefs/*.xml",
              "iOS: Extrair UserDefaults via backup iTunes/iCloud",
              "Procurar por: password, token, api_key, credit_card, ssn",
              "Verificar SQLite databases sem criptografia: strings database.db"
            ],
            tools: [
              "ADB (Android Debug Bridge)",
              "objection",
              "Frida",
              "iExplorer (iOS)",
              "SQLite Browser",
              "apktool (decompilar APK)"
            ],
            commands: [
              "# Android - Extrair SharedPreferences",
              "adb shell",
              "su  # Requer root",
              "cd /data/data/com.example.app/shared_prefs",
              "cat *.xml | grep -i 'password\\|token\\|api_key'",
              "",
              "# Android - Dump de SQLite",
              "adb pull /data/data/com.example.app/databases/app.db",
              "sqlite3 app.db",
              "sqlite> .tables",
              "sqlite> SELECT * FROM users;",
              "",
              "# iOS - Backup e análise",
              "idevicebackup2 backup --full ./backup",
              "cd backup",
              "grep -r 'password\\|token' .",
              "",
              "# Frida - Runtime analysis",
              "frida -U -f com.example.app -l dump-storage.js"
            ],
            steps: [
              "1. Fazer backup do app (Android: adb backup, iOS: iTunes)",
              "2. Android: Extrair APK e descompilar com apktool",
              "3. Navegar para /data/data/[package]/ (requer root/emulador)",
              "4. Ler shared_prefs/*.xml procurando dados sensíveis",
              "5. Extrair databases/*.db e fazer query com SQLite",
              "6. iOS: Extrair bundle com iExplorer e analisar UserDefaults",
              "7. Usar objection para dump automático de storage",
              "8. Verificar se app usa Android Keystore / iOS Keychain adequadamente"
            ],
            mitigation: [
              "Android: Usar EncryptedSharedPreferences (Jetpack Security)",
              "Android: Armazenar chaves no Android Keystore (hardware-backed)",
              "iOS: Usar Keychain Services com kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
              "Criptografar databases SQLite: SQLCipher",
              "Nunca salvar credenciais em plain text",
              "Implementar certificate pinning para proteger tokens em trânsito",
              "Habilitar FileProvider para compartilhamento seguro de arquivos"
            ],
            evidence: [
              "Screenshot de shared_prefs.xml com <string name=\"api_token\">ABC123</string>",
              "Dump de SQLite mostrando password em plain text",
              "Código fonte: SharedPreferences.Editor.putString(\"password\", pwd)",
              "objection output listando secrets em storage"
            ],
            references: [
              "https://mas.owasp.org/MASVS/05-MASVS-STORAGE/",
              "https://mas.owasp.org/MASTG/",
              "https://developer.android.com/topic/security/data",
              "https://developer.apple.com/documentation/security/keychain_services"
            ]
          }
        },
        {
          id: "storage-2",
          title: "Validar exclusão segura de dados sensíveis",
          description: "Verificar se dados sensíveis são apagados ao logout/desinstalação (não apenas marcados como deleted).",
          guide: {
            overview: "Apps podem 'deletar' dados apenas marcando flag, mantendo dados recuperáveis via forensics.",
            impact: "Recuperação de dados sensíveis após logout/desinstalação via carving de disco.",
            detection: [
              "Criar conta, fazer login, gerar dados sensíveis",
              "Fazer logout ou desinstalar app",
              "Usar forensics tools para recuperar dados deletados"
            ],
            tools: ["Autopsy", "FTK Imager", "strings", "binwalk"],
            commands: [
              "# Fazer dump completo do storage",
              "adb pull /data/data/com.example.app/ ./before-logout",
              "",
              "# Fazer logout no app",
              "",
              "# Dump novamente",
              "adb pull /data/data/com.example.app/ ./after-logout",
              "",
              "# Comparar",
              "diff -r before-logout/ after-logout/",
              "",
              "# Procurar strings em espaço 'livre'",
              "strings -a /dev/block/mmcblk0 | grep 'sensitive_data'"
            ],
            steps: [
              "1. Instalar app e criar dados sensíveis (mensagens, documentos)",
              "2. Fazer backup completo do storage",
              "3. Executar logout/clear data/desinstalar",
              "4. Fazer novo backup e comparar arquivos",
              "5. Usar strings/binwalk para procurar dados em espaço não alocado",
              "6. Verificar se SQLite faz VACUUM após DELETE",
              "7. Testar recuperação com ferramentas forenses"
            ],
            mitigation: [
              "Sobrescrever dados antes de deletar (write zeros)",
              "SQLite: PRAGMA secure_delete = ON;",
              "Usar shred em arquivos críticos antes de unlink()",
              "Implementar wipe ao logout: deletar databases, shared_prefs, cache",
              "iOS: Usar Data Protection API com remoção de chave de criptografia",
              "Android: Forçar garbage collection após clear de dados sensíveis"
            ],
            evidence: [
              "diff mostrando arquivos inalterados após logout",
              "strings output com tokens recuperados após DELETE",
              "SQLite: .dump mostrando registros 'deletados' ainda presentes",
              "Autopsy screenshot com dados recuperados"
            ],
            references: [
              "https://mas.owasp.org/MASVS/05-MASVS-STORAGE/",
              "https://sqlite.org/pragma.html#pragma_secure_delete"
            ]
          }
        }
      ]
    },
    {
      id: "masvs-crypto",
      title: "MASVS-CRYPTO: Criptografia",
      summary: "Uso correto de criptografia (algoritmos modernos, chaves seguras, não usar crypto fraca).",
      items: [
        {
          id: "crypto-1",
          title: "Identificar uso de algoritmos criptográficos fracos",
          description: "Detectar uso de MD5, SHA1, DES, RC4, ECB mode em código ou bibliotecas.",
          guide: {
            overview: "Apps mobile frequentemente usam algoritmos quebrados (MD5, DES) ou modos inseguros (ECB).",
            impact: "Quebra de criptografia, rainbow table attacks, exposição de dados, man-in-the-middle.",
            detection: [
              "Descompilar APK/IPA e fazer grep por: MD5, SHA1, DES, RC4, ECB",
              "Usar MobSF (Mobile Security Framework) para análise estática",
              "Interceptar tráfego e verificar TLS version/ciphers"
            ],
            tools: ["apktool", "jadx", "MobSF", "grep", "Hopper (iOS disassembler)"],
            commands: [
              "# Descompilar APK",
              "apktool d app.apk",
              "",
              "# Procurar por crypto fraca",
              "grep -r 'MD5\\|SHA1\\|DES\\|RC4\\|ECB' app/smali/",
              "grep -r 'MessageDigest.getInstance(\"MD5\")' app/",
              "",
              "# Análise automatizada",
              "python3 mobsf.py -f app.apk",
              "",
              "# iOS - Strings no binário",
              "strings app.ipa/Payload/App.app/App | grep -i 'md5\\|des\\|rc4'"
            ],
            steps: [
              "1. Descompilar app (apktool para Android, class-dump para iOS)",
              "2. Fazer grep recursivo por algoritmos fracos",
              "3. Analisar imports: javax.crypto.Cipher, CommonCrypto",
              "4. Procurar por: getInstance(\"MD5\"), AES/ECB/NoPadding",
              "5. Usar MobSF para scan automatizado",
              "6. Testar conexões: SSLScan para verificar TLS ciphers",
              "7. Interceptar com Burp/mitmproxy e verificar handshake TLS"
            ],
            mitigation: [
              "Usar apenas algoritmos modernos: AES-256-GCM, ChaCha20-Poly1305",
              "Hash: SHA-256/SHA-3 (não MD5/SHA1)",
              "TLS 1.2+ com perfect forward secrecy (ECDHE ciphers)",
              "Android: usar Cipher.getInstance(\"AES/GCM/NoPadding\")",
              "iOS: usar CryptoKit (Swift), não CommonCrypto deprecated APIs",
              "Nunca implementar crypto própria, usar bibliotecas validadas",
              "Configurar minimum TLS version: Android - networkSecurityConfig.xml"
            ],
            evidence: [
              "Código: MessageDigest.getInstance(\"MD5\")",
              "Gradle dependency: compile 'org.bouncycastle:bcprov:old-version'",
              "SSLScan output mostrando TLS 1.0 habilitado",
              "MobSF report: 'Insecure algorithm MD5 detected'"
            ],
            references: [
              "https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/",
              "https://developer.android.com/privacy-and-security/cryptography",
              "https://developer.apple.com/documentation/cryptokit",
              "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
            ]
          }
        },
        {
          id: "crypto-2",
          title: "Validar geração e armazenamento seguro de chaves criptográficas",
          description: "Verificar se chaves são geradas com entropia adequada e armazenadas em hardware (Keystore/Keychain).",
          guide: {
            overview: "Apps podem gerar chaves com Random() inseguro ou hardcoded, ou armazenar em código/assets.",
            impact: "Chaves previsíveis/hardcoded permitem decriptação de dados de todos os usuários.",
            detection: [
              "Descompilar e procurar por: SecretKey, byte[] key = {",
              "Procurar chaves em assets/, strings.xml, BuildConfig",
              "Verificar uso de SecureRandom vs Random()",
              "Testar se Android Keystore / iOS Keychain são usados"
            ],
            tools: ["apktool", "jadx", "Frida", "objection"],
            commands: [
              "# Procurar chaves hardcoded",
              "grep -r 'byte\\[\\] key = ' app/smali/",
              "grep -r 'API_KEY\\|SECRET_KEY' app/res/",
              "",
              "# Android - Verificar uso de Keystore",
              "grep -r 'KeyStore.getInstance(\"AndroidKeyStore\")' app/",
              "",
              "# Frida - Hook key generation",
              "frida -U -f com.example.app -l hook-keygen.js",
              "",
              "# iOS - Procurar em Info.plist",
              "plutil -p Info.plist | grep -i 'key\\|secret'"
            ],
            steps: [
              "1. Descompilar app e procurar por: 'key', 'secret', 'iv'",
              "2. Verificar assets/, res/raw/ para arquivos de config com chaves",
              "3. Analisar código de key generation: usa SecureRandom?",
              "4. Verificar se chaves são armazenadas em Keystore/Keychain",
              "5. Testar com Frida: hook KeyGenerator e verificar entropy",
              "6. Procurar hardcoded keys: String key = \"abc123...\"",
              "7. Verificar se mesma chave é usada para todos usuários (red flag)"
            ],
            mitigation: [
              "Gerar chaves com SecureRandom / CryptoKit.SymmetricKey",
              "Android: Armazenar em AndroidKeyStore (hardware-backed se disponível)",
              "iOS: Armazenar no Keychain com kSecAttrAccessibleAfterFirstUnlock",
              "Nunca hardcodar chaves no código",
              "Usar key derivation: PBKDF2, Argon2 a partir de password do usuário",
              "Implementar key rotation policy",
              "Usar chaves únicas por usuário/sessão (não global)"
            ],
            evidence: [
              "Código: byte[] key = {0x01, 0x02, 0x03, ...} (hardcoded)",
              "strings.xml: <string name=\"encryption_key\">abc123</string>",
              "Ausência de KeyStore.getInstance() no código",
              "Frida output: Random() usado em vez de SecureRandom()"
            ],
            references: [
              "https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/",
              "https://developer.android.com/training/articles/keystore",
              "https://source.android.com/docs/security/features/keystore"
            ]
          }
        }
      ]
    },
    {
      id: "masvs-auth",
      title: "MASVS-AUTH: Autenticação e Gestão de Sessão",
      summary: "Validação de mecanismos de login, sessão, biometria e autenticação de múltiplos fatores.",
      items: [
        {
          id: "auth-1",
          title: "Testar implementação de autenticação biométrica (bypass)",
          description: "Verificar se autenticação biométrica pode ser bypassada via hook/patch.",
          guide: {
            overview: "Apps podem implementar biometria de forma insegura, validando apenas no client-side.",
            impact: "Bypass de autenticação biométrica usando Frida/Xposed para sempre retornar 'success'.",
            detection: [
              "Usar Frida para hook BiometricPrompt.AuthenticationCallback",
              "Forçar retorno de onAuthenticationSucceeded()",
              "Verificar se app faz validação server-side após biometria"
            ],
            tools: ["Frida", "objection", "Xposed Framework", "Magisk"],
            commands: [
              "# Frida - Bypass biometria Android",
              "frida -U -f com.example.app -l biometric-bypass.js",
              "",
              "# biometric-bypass.js",
              "Java.perform(function() {",
              "  var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');",
              "  BiometricPrompt.onAuthenticationSucceeded.implementation = function(result) {",
              "    console.log('[+] Biometric bypassed!');",
              "    this.onAuthenticationSucceeded(result);",
              "  };",
              "});",
              "",
              "# objection - Bypass automático",
              "objection -g com.example.app explore",
              "android hooking watch class androidx.biometric.BiometricPrompt"
            ],
            steps: [
              "1. Instalar app em device rooted/jailbroken",
              "2. Interceptar chamada de BiometricPrompt (Android) / LAContext (iOS)",
              "3. Usar Frida para hook callback de autenticação",
              "4. Forçar retorno de sucesso mesmo sem biometria válida",
              "5. Verificar se app valida token biométrico no servidor",
              "6. Testar se é possível acessar funcionalidades após bypass",
              "7. Analisar se CryptoObject é usado (validação server-side de assinatura)"
            ],
            mitigation: [
              "Android: Usar BiometricPrompt com CryptoObject (server valida assinatura)",
              "iOS: Usar LAContext com kSecAccessControlBiometryCurrentSet",
              "Nunca confiar apenas em callback client-side",
              "Após biometria OK, gerar token assinado e validar no servidor",
              "Implementar anti-tampering para detectar Frida/Xposed",
              "Usar SafetyNet/Play Integrity API para validar device integrity"
            ],
            evidence: [
              "Frida script hookando onAuthenticationSucceeded",
              "Screenshot de acesso sem biometria válida",
              "Código mostrando validação apenas client-side",
              "Video demonstrando bypass completo"
            ],
            references: [
              "https://mas.owasp.org/MASVS/07-MASVS-AUTH/",
              "https://developer.android.com/training/sign-in/biometric-auth",
              "https://developer.apple.com/documentation/localauthentication"
            ]
          }
        },
        {
          id: "auth-2",
          title: "Validar gestão de sessão (timeout, revogação de tokens)",
          description: "Verificar se tokens expiram, são revogados ao logout, e não são reutilizáveis.",
          guide: {
            overview: "Apps mobile podem usar tokens sem expiração ou que continuam válidos após logout.",
            impact: "Sessões perpétuas, reutilização de tokens roubados, ausência de logout efetivo.",
            detection: [
              "Fazer login, capturar token, fazer logout",
              "Testar se token ainda funciona após logout",
              "Verificar campo 'exp' em JWT",
              "Testar reutilização de refresh tokens"
            ],
            tools: ["Burp Suite", "mitmproxy", "Charles Proxy", "jwt.io"],
            commands: [
              "# Interceptar token",
              "mitmproxy --mode transparent",
              "",
              "# Decodificar JWT",
              "echo 'eyJhbGc...' | base64 -d | jq",
              "",
              "# Testar após logout",
              "curl -H 'Authorization: Bearer OLD_TOKEN' https://api.example.com/api/user",
              "",
              "# Verificar expiração",
              "# JWT exp claim: se ausente ou > 24h = red flag"
            ],
            steps: [
              "1. Configurar proxy SSL (Burp/Charles) e interceptar tráfego",
              "2. Fazer login e capturar access_token e refresh_token",
              "3. Verificar JWT claims: exp (deve existir e ser < 1h)",
              "4. Fazer logout no app",
              "5. Tentar reusar access_token: deve retornar 401",
              "6. Tentar refresh com refresh_token antigo: deve falhar",
              "7. Verificar se há blacklist de tokens no servidor"
            ],
            mitigation: [
              "Implementar expiração curta: access_token = 15min, refresh_token = 7 dias",
              "Invalidar tokens no logout (blacklist ou token versioning)",
              "Usar rotating refresh tokens (cada refresh gera novo token)",
              "Armazenar tokens de forma segura (Keychain/Keystore)",
              "Implementar device binding (token válido apenas no device de origem)",
              "Monitorar uso anômalo de tokens (IP changes, concurrent sessions)"
            ],
            evidence: [
              "JWT decodificado sem campo 'exp'",
              "Token funcionando após logout: curl retorna 200 OK",
              "Código sem implementação de token revocation",
              "Refresh token reutilizável indefinidamente"
            ],
            references: [
              "https://mas.owasp.org/MASVS/07-MASVS-AUTH/",
              "https://datatracker.ietf.org/doc/html/rfc6749#section-10.3",
              "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
            ]
          }
        }
      ]
    },
    {
      id: "masvs-network",
      title: "MASVS-NETWORK: Comunicação de Rede",
      summary: "TLS adequado, certificate pinning, proteção contra MitM.",
      items: [
        {
          id: "network-1",
          title: "Validar implementação de Certificate Pinning",
          description: "Testar se app rejeita certificados não pinados, impedindo MitM.",
          guide: {
            overview: "Apps sem certificate pinning aceitam qualquer certificado válido (incluindo de proxies MitM).",
            impact: "Man-in-the-Middle, interceptação de tráfego HTTPS, roubo de credenciais/tokens.",
            detection: [
              "Instalar certificado de proxy (Burp/Charles) no device",
              "Configurar proxy e abrir app",
              "Se tráfego for interceptado sem erro: sem pinning",
              "Testar bypass com Frida/objection"
            ],
            tools: ["Burp Suite", "Frida", "objection", "SSL Kill Switch 2 (iOS)"],
            commands: [
              "# Android - Instalar cert do Burp",
              "adb push burp-cert.cer /sdcard/",
              "# Configurar proxy: Settings > Wi-Fi > Modify > Proxy",
              "",
              "# Testar bypass com objection",
              "objection -g com.example.app explore",
              "android sslpinning disable",
              "",
              "# Frida - Universal SSL Pinning bypass",
              "frida -U -f com.example.app -l frida-multiple-unpinning.js --no-pause",
              "",
              "# iOS - SSL Kill Switch",
              "# Instalar via Cydia e ativar toggle"
            ],
            steps: [
              "1. Instalar certificado CA do proxy no device (Settings > Security)",
              "2. Configurar Wi-Fi proxy apontando para Burp/Charles",
              "3. Abrir app e tentar fazer requests",
              "4. Se tráfego aparece no proxy: pinning ausente ou fraco",
              "5. Se app falha/crash: pinning presente",
              "6. Testar bypass com Frida scripts conhecidos",
              "7. Analisar logs de erro: SSLPeerUnverifiedException?"
            ],
            mitigation: [
              "Android: Implementar network_security_config.xml com <pin-set>",
              "Android: Usar OkHttp CertificatePinner",
              "iOS: Implementar URLSession delegate didReceiveChallenge",
              "Pinar múltiplos certificados (backup pins)",
              "Usar public key pinning (não leaf certificate)",
              "Implementar pinning também para APIs de terceiros críticas",
              "Considerar usar Android App Bundle com Dynamic Feature Modules para atualizar pins"
            ],
            evidence: [
              "Screenshot do Burp interceptando tráfego HTTPS do app",
              "network_security_config.xml ausente ou sem <pin-set>",
              "objection output: 'SSL Pinning disabled'",
              "Código sem implementação de certificate validation"
            ],
            references: [
              "https://mas.owasp.org/MASVS/08-MASVS-NETWORK/",
              "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning",
              "https://developer.android.com/training/articles/security-config",
              "https://github.com/datatheorem/TrustKit"
            ]
          }
        },
        {
          id: "network-2",
          title: "Verificar se app aceita tráfego HTTP (cleartext)",
          description: "Validar se app permite comunicação HTTP não criptografada.",
          guide: {
            overview: "Apps podem permitir HTTP para alguns endpoints, expondo dados em trânsito.",
            impact: "Sniffing de credenciais, tokens, PII em redes abertas (Wi-Fi público).",
            detection: [
              "Analisar network_security_config.xml: cleartextTrafficPermitted?",
              "Interceptar tráfego com Wireshark em rede local",
              "Procurar requests HTTP (não HTTPS) no log do proxy"
            ],
            tools: ["Wireshark", "tcpdump", "apktool", "Android Network Inspector"],
            commands: [
              "# Android - Verificar config",
              "apktool d app.apk",
              "cat app/res/xml/network_security_config.xml",
              "# Procurar: <base-config cleartextTrafficPermitted=\"true\">",
              "",
              "# Sniffing de rede",
              "tcpdump -i wlan0 -A 'tcp port 80' | grep -i 'authorization\\|password'",
              "",
              "# Wireshark filter",
              "http && ip.src == [device_ip]"
            ],
            steps: [
              "1. Descompilar APK e verificar AndroidManifest.xml",
              "2. Procurar: android:usesCleartextTraffic=\"true\"",
              "3. Analisar network_security_config.xml",
              "4. Conectar device e PC na mesma rede Wi-Fi",
              "5. Capturar tráfego com tcpdump/Wireshark",
              "6. Usar app e procurar por pacotes HTTP (porta 80)",
              "7. Verificar se dados sensíveis trafegam em cleartext"
            ],
            mitigation: [
              "Android 9+: Cleartext desabilitado por padrão (enforced)",
              "Forçar HTTPS para TODOS os endpoints",
              "network_security_config.xml: <base-config cleartextTrafficPermitted=\"false\">",
              "iOS: App Transport Security (ATS) enabled por padrão",
              "Remover exceções de ATS em Info.plist",
              "Rejeitar qualquer conexão não HTTPS no código"
            ],
            evidence: [
              "AndroidManifest.xml: android:usesCleartextTraffic=\"true\"",
              "Wireshark capture mostrando HTTP POST com credenciais",
              "tcpdump output com Authorization header em cleartext",
              "network_security_config.xml com cleartextTrafficPermitted=true"
            ],
            references: [
              "https://mas.owasp.org/MASVS/08-MASVS-NETWORK/",
              "https://developer.android.com/training/articles/security-config#CleartextTrafficPermitted",
              "https://developer.apple.com/documentation/security/preventing_insecure_network_connections"
            ]
          }
        }
      ]
    },
    {
      id: "masvs-platform",
      title: "MASVS-PLATFORM: Interação com Plataforma",
      summary: "Uso seguro de componentes do OS (WebView, intents, deep links, IPC).",
      items: [
        {
          id: "platform-1",
          title: "Testar vulnerabilidades em WebView (XSS, JavaScript Interface)",
          description: "Verificar se WebView permite JavaScript, carrega URLs externas, e expõe interfaces inseguras.",
          guide: {
            overview: "WebViews mal configuradas permitem XSS, roubo de dados locais via JavaScript, acesso a funções nativas.",
            impact: "XSS, acesso a localStorage/cookies, chamadas a métodos Java via @JavascriptInterface.",
            detection: [
              "Descompilar e procurar: setJavaScriptEnabled(true)",
              "Procurar @JavascriptInterface em código Java/Kotlin",
              "Testar se WebView carrega URLs controladas pelo usuário",
              "Injetar JavaScript: javascript:alert(document.cookie)"
            ],
            tools: ["apktool", "jadx", "Burp Suite", "adb"],
            commands: [
              "# Procurar configuração de WebView",
              "grep -r 'setJavaScriptEnabled' app/smali/",
              "grep -r 'JavascriptInterface' app/",
              "",
              "# Testar deep link com payload XSS",
              "adb shell am start -a android.intent.action.VIEW -d 'myapp://web?url=javascript:alert(1)'",
              "",
              "# Hook WebView com Frida",
              "frida -U -f com.example.app -l webview-hook.js"
            ],
            steps: [
              "1. Descompilar APK e procurar WebView usage",
              "2. Verificar: setJavaScriptEnabled(true)?",
              "3. Procurar @JavascriptInterface methods expostos",
              "4. Testar se WebView aceita URLs externas (deep links)",
              "5. Injetar payload XSS: <script>alert(1)</script>",
              "6. Testar chamada de interface: javascript:AndroidBridge.sensitiveMethod()",
              "7. Verificar se setAllowFileAccess(true) permite file:///"
            ],
            mitigation: [
              "Desabilitar JavaScript se não necessário: setJavaScriptEnabled(false)",
              "Validar URLs antes de loadUrl(): whitelist de domínios",
              "Remover @JavascriptInterface ou validar origem do JavaScript",
              "Usar setSafeBrowsingEnabled(true)",
              "setAllowFileAccessFromFileURLs(false)",
              "Implementar Content Security Policy em HTML carregado",
              "Usar AndroidX WebView SafeBrowsing"
            ],
            evidence: [
              "Código: webView.getSettings().setJavaScriptEnabled(true)",
              "@JavascriptInterface method: deleteAllData() sem validação",
              "Deep link com XSS payload funcionando",
              "Screenshot de alert(1) executado em WebView"
            ],
            references: [
              "https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/",
              "https://developer.android.com/develop/ui/views/layout/webapps/webview",
              "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md"
            ]
          }
        },
        {
          id: "platform-2",
          title: "Validar segurança de Deep Links e Intents",
          description: "Testar se app valida origem de intents/deep links, evitando intent spoofing.",
          guide: {
            overview: "Apps podem processar deep links maliciosos ou intents sem validar origem, levando a ações não autorizadas.",
            impact: "Intent spoofing, phishing via deep link, execução de ações críticas sem confirmação.",
            detection: [
              "Descompilar e procurar <intent-filter> no AndroidManifest.xml",
              "Testar deep links com payloads maliciosos",
              "Verificar se activities exportadas validam caller"
            ],
            tools: ["adb", "Drozer", "apktool"],
            commands: [
              "# Listar intent-filters",
              "apktool d app.apk",
              "cat app/AndroidManifest.xml | grep -A5 intent-filter",
              "",
              "# Testar deep link",
              "adb shell am start -a android.intent.action.VIEW -d 'myapp://payment?amount=0.01&to=attacker'",
              "",
              "# Drozer - Enumerar attack surface",
              "run app.package.attacksurface com.example.app",
              "run app.activity.info -a com.example.app",
              "",
              "# Testar intent injection",
              "adb shell am start -n com.example.app/.PaymentActivity --es 'user_id' 'victim123'"
            ],
            steps: [
              "1. Extrair AndroidManifest.xml e listar <intent-filter>",
              "2. Identificar activities/services/receivers exportados",
              "3. Para cada deep link, testar: myapp://action?param=malicious",
              "4. Verificar se app valida parâmetros antes de processar",
              "5. Testar intent injection: enviar extras maliciosos",
              "6. Usar Drozer para fuzzing de intents",
              "7. Verificar se ações críticas (payment, delete) exigem confirmação"
            ],
            mitigation: [
              "Validar todos parâmetros de deep links (whitelist)",
              "Usar App Links (Android) com verificação de domínio",
              "Marcar components como android:exported=\"false\" quando possível",
              "Validar caller de intents: getCallingActivity()",
              "Implementar confirmação para ações críticas via deep link",
              "Usar pending intents com FLAG_IMMUTABLE",
              "Sanitizar extras de intents antes de usar"
            ],
            evidence: [
              "AndroidManifest.xml: activity exported=true sem validação",
              "Deep link executando payment sem confirmação",
              "Intent injection: adb command alterando user_id",
              "Drozer output listando 15 exported components"
            ],
            references: [
              "https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/",
              "https://developer.android.com/training/app-links/verify-android-applinks",
              "https://github.com/mwrlabs/drozer"
            ]
          }
        }
      ]
    },
    {
      id: "masvs-resilience",
      title: "MASVS-RESILIENCE: Resiliência contra Engenharia Reversa",
      summary: "Detecção de root/jailbreak, anti-debugging, ofuscação de código, runtime integrity.",
      items: [
        {
          id: "resilience-1",
          title: "Testar detecção de root/jailbreak",
          description: "Verificar se app detecta e bloqueia execução em devices rooted/jailbroken.",
          guide: {
            overview: "Apps críticos (banking, DRM) devem detectar root/jailbreak para evitar tampering e data extraction.",
            impact: "Bypass de detecção permite Frida, Xposed, dump de memória, hooks em devices comprometidos.",
            detection: [
              "Instalar app em device rooted/jailbroken",
              "Verificar se app bloqueia execução ou mostra aviso",
              "Testar bypass com Magisk Hide, Liberty Lite",
              "Usar Frida para hook funções de detecção"
            ],
            tools: ["Magisk", "Magisk Hide", "Liberty Lite (iOS)", "Frida", "RootBeer"],
            commands: [
              "# Android - Verificar root",
              "adb shell su -c 'id'  # Se retornar uid=0: rooted",
              "",
              "# Magisk Hide (ocultar root do app)",
              "magisk --hide com.example.app",
              "",
              "# Frida - Hook root detection",
              "frida -U -f com.example.app -l root-bypass.js",
              "",
              "# root-bypass.js",
              "Java.perform(function() {",
              "  var RootDetection = Java.use('com.example.app.RootDetection');",
              "  RootDetection.isRooted.implementation = function() {",
              "    return false;",
              "  };",
              "});"
            ],
            steps: [
              "1. Instalar app em device rooted (Magisk) ou jailbroken",
              "2. Abrir app e verificar comportamento",
              "3. Se app funciona normalmente: sem detecção",
              "4. Se app bloqueia: identificar método de detecção",
              "5. Descompilar e procurar: RootBeer, su binary checks, Magisk detection",
              "6. Testar bypass com Magisk Hide ou Frida hooks",
              "7. Verificar se detecção pode ser contornada facilmente"
            ],
            mitigation: [
              "Implementar múltiplas camadas de detecção (não confiar em 1 método)",
              "Android: Verificar su binary, Magisk, Xposed, build tags",
              "iOS: Verificar Cydia, jailbreak files (/Applications/Cydia.app)",
              "Usar SafetyNet Attestation API (Android)",
              "iOS: DeviceCheck API",
              "Implementar server-side validation de attestation",
              "Ofuscar código de detecção (evitar hooks simples)",
              "Considerar UX: avisar usuário em vez de bloquear completamente"
            ],
            evidence: [
              "App funcionando em device rooted sem avisos",
              "Código de root detection bypassado com Frida",
              "Magisk Hide ocultando root com sucesso",
              "Ausência de SafetyNet checks no código"
            ],
            references: [
              "https://mas.owasp.org/MASVS/10-MASVS-RESILIENCE/",
              "https://github.com/scottyab/rootbeer",
              "https://developer.android.com/training/safetynet/attestation",
              "https://github.com/topjohnwu/Magisk"
            ]
          }
        },
        {
          id: "resilience-2",
          title: "Validar ofuscação de código e anti-debugging",
          description: "Verificar se código é ofuscado (ProGuard/R8) e se há proteções anti-debugging.",
          guide: {
            overview: "Apps sem ofuscação são facilmente reversíveis, expondo lógica de negócio e segredos.",
            impact: "Engenharia reversa facilitada, descoberta de vulnerabilidades, extração de algoritmos proprietários.",
            detection: [
              "Descompilar APK/IPA e verificar nomes de classes/métodos",
              "Se nomes legíveis (MainActivity, getUserData): sem ofuscação",
              "Testar attach de debugger: Android Studio, lldb",
              "Procurar anti-debugging checks no código"
            ],
            tools: ["jadx", "apktool", "Hopper", "IDA Pro", "Android Studio Debugger"],
            commands: [
              "# Descompilar e verificar ofuscação",
              "jadx app.apk -d output/",
              "ls output/sources/com/example/app/",
              "# Se ver: a.java, b.java, c.java = ofuscado",
              "# Se ver: MainActivity.java, UserService.java = SEM ofuscação",
              "",
              "# Tentar attach debugger",
              "adb shell am set-debug-app -w com.example.app",
              "# Se app crash/deteta: anti-debugging presente",
              "",
              "# Procurar anti-debugging",
              "grep -r 'Debug.isDebuggerConnected' output/"
            ],
            steps: [
              "1. Descompilar APK com jadx",
              "2. Navegar em sources/ e verificar nomes de classes",
              "3. Verificar build.gradle: proguardFiles presente?",
              "4. Tentar attach debugger via Android Studio",
              "5. Procurar calls: Debug.isDebuggerConnected(), ptrace()",
              "6. iOS: Verificar se símbolos foram stripped (lldb)",
              "7. Avaliar eficácia: fácil reverter lógica ou não?"
            ],
            mitigation: [
              "Android: Habilitar ProGuard/R8 com regras agressivas",
              "build.gradle: minifyEnabled true, shrinkResources true",
              "Usar ofuscação nativa: LLVM-Obfuscator para código C/C++",
              "Implementar anti-debugging: Debug.isDebuggerConnected()",
              "Android: detectar /proc/self/status TracerPid",
              "iOS: sysctl checks, ptrace(PT_DENY_ATTACH)",
              "Considerar DexGuard (comercial) para proteção adicional",
              "Ofuscar strings sensíveis (não deixar hardcoded)"
            ],
            evidence: [
              "jadx output com nomes legíveis: UserLoginActivity.java",
              "build.gradle: minifyEnabled false",
              "Debugger attach sem resistência",
              "Strings sensíveis em plain text: 'SECRET_API_KEY'"
            ],
            references: [
              "https://mas.owasp.org/MASVS/10-MASVS-RESILIENCE/",
              "https://developer.android.com/build/shrink-code",
              "https://www.guardsquare.com/dexguard",
              "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md"
            ]
          }
        }
      ]
    }
  ]
};
