https://docs.microsoft.com/en-us/dotnet/standard/security/secure-coding-guidelines
- Do not use .NET Remoting. Why?
- Microsoft's guidance is now to always use the "encrypt-then-sign" paradigm. That is, first encrypt data using a symmetric key, then compute a _MAC_ or asymmetric signature over the ciphertext (encrypted data). When decrypting data, perform the reverse. First, confirm the _MAC_ or signature of the ciphertext, then decrypt it.
- These vulnerabilities allow an attacker to decrypt data encrypted by symmetric block algorithms, such as **AES** and **3DES**, using no more than **4096** attempts per block of data.
- First and foremost, Microsoft recommends that any data that has confidentiality needs be transmitted over **Transport Layer Security (TLS)**, the successor to **Secure Sockets Layer (SSL)**.
- There's no one-size-fits-all correct answer to cryptography and this generalization isn't as good as directed advice from a professional cryptographer.

# OWASP TOP10 (Open Web Application Security Project)

## 1. Injection
- Integrity is not verifiable
- Intent may be malicious
- Data may include: SQL injection, Cross site Scripting and Binaries containing malware
- Start handling from database till web tier
  - Principle of least permission inside database
  - Whitelisting: Type conversion (avoid strings), Use a regular expression, List of known good values
  - ORMs implement parameterization automatically
  - Stored Procedure should use sp_executesql
- Havji

## 2. Cross-Site Scripting (XSS)
- Can allow cookies stealing
- MySpace case
- Use proven libraries to prevent: `AntiXssEncoder.HtmlEncode`, `JavaScriptEncode (AntiXss+Nuget)`
- MVC automatically encodes all output by default (implicit): if needed `@Html.Raw`
- RequestValidation: `Request.Unvalidated`, `AllowHtml`. Last line of defense.
- Do not rely only on the browser
- Expect attackers to use obfuscated URLs: How to handle?

## 3. Broken Authentication and Session Management
- Never have session IDs in a URL (any sensitive data at all): Cookies
- HTTP is a stateless protocol
- Timeout too long into ASP.NET applications
- Use of ASP.NET membership provider
- Sliding: It renews after a request

## 4. Insecure Direct Object References
- Fiddler Web Debugger
- Natural Key is risky: Prefer `Guid` even though they don't perform as well on the database end
- Temporary map / User specific / Indirect reference
- It always boils back down to insufficient authorization

## 5. Cross-Site Request Forgery (CSRF) [Impact Moderate]
- Add randomness via a CSRF token: Using a hidden field an also in a cookie (only defense)
  - `Html.BeginForm()` > `Html.AntiForgeryToken()` + `[ValidateAntiForgeryToken]`
- CORS
- Never rely on the browser: Write secure code with anti-forgery tokens

## 6. Security Misconfiguration
- inurl:elmah.axd "error log for"
- Protect/Encrypt sensitive data
- Use/Set Release configurations
- Keep frameworks up to date

## 7. Insecure Cryptographic Storage
- Hashcat
- Usually about password storage: Plain text, Encrypted, Hashed
- Hashing (one-way process) != Encryption (reversible)
- Rainbow tables
- Salt: Sequence of random bytes added to a password
- BCrypt.Net / Zetetic.Security
- Symmetric and Asymmetric (public key)
- Hashing: There's no key management as it's not reversible
- DPAPI: `ProtectedData.Protect` | `ProtectedData.Unprotect`
  - Don't have to worry about key management
- ROT13 isn't cryptography: only character substitution
- Base64 isn't cryptography: only encoding to get the byte arrays into ASCII characters
- Cryptographic storage is the last line of defense

## 8. Failure to Restrict URL Access
- Users accessing pages they shouldn't
- Use Authorize attributes on the resources you want to protect: Roles
- Be role-centric
- Don't forget to protect APIs and non-ASP.NET resources

## 9. Insufficient Transport Layer Protection
- MiTM (Man in the middle attack): Can either observe or manipulate insecure traffic
- WireShark + Edit This Cookie
- HTTPS: Confidentiality and Integrity
- Cookies have to be secure
- The browser prefix urls without scheme with the current one
- HSTS header: disallow any HTTP requests (restrictions)
- SSL comes with a performance cost

## 10. Unvalidated Redirects and Forwards
- Most used to send SPAM
- Whitelist of redirects
