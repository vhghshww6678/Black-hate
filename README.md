# Web Application Functionality Security Test Cases and Vulnerability #
Description

Web Application Functionality Security Testing specifically focuses on ensuring that the application's functionalities are not vulnerable to security threats. While some overlap exists with general security testing, the emphasis here is on the functionality aspects. I personally prefer to start with the Black-Box and Grey-Box testing approach where I try to enumerate banner information, some basic or I can say network-level findings that can be found using any automated tool as well as manually such as.

1.Registration Functionality:

1.Username enumeration via verbose failure messages
2.No confirmed password functionality
3.No mobile number verification process
4.No email verification process/No account verification process
5.Weak Security Question/Answer
6.No multi-factor authentication enables option
7.No term and condition checkbox during registration
8.Nonunique usernames/Predictable usernames
9.Lack of User Input Validation (Max Length not Implemented)
10.SQL Injection
11.HTML Injection
12.Stored XSS

1.Input Validation
Register using special characters in the username, email, or password fields to check for SQL injection vulnerabilities.
Input overly long strings into the fields to check for buffer overflow.
Input HTML or JavaScript snippets to test for cross-site scripting (XSS) vulnerabilities.

2.Account Enumeration
Observe system's response to registering with an already registered email or username. It shouldn't indicate clearly whether an email or username is registered (to prevent user enumeration).

3.Rate Limiting/Brute Force
Try to register multiple times in quick succession to ensure rate limiting is in place.
Automated registration attempts to ensure CAPTCHA or similar anti-bot mechanisms are in place.

4.Password Policy
Attempt to register with weak passwords (like "password", "123456", etc.) to check password strength policies.
Check if there's a mechanism that ensures password complexity (mix of uppercase, lowercase, numbers, special characters).

5.Data Transmission Security

Ensure that the registration page is using HTTPS, ensuring data is encrypted during transmission.
Intercept the registration request using a proxy tool (like Burp Suite or OWASP ZAP) and verify if the data (especially the password) is sent in clear text.

6.Data Storage Security
If possible, check how the password is stored in the database. It should be hashed (and ideally salted).

7.Error Handling
Ensure that detailed system errors (like stack traces) are not shown to the user. They should see generic error messages instead.

8.CAPTCHA
Ensure a CAPTCHA is in place and can't be bypassed easily.
Check if the CAPTCHA expires after a certain time or after a few unsuccessful attempts.

9.Account Verification
Ensure that a user must verify their email address (or other contact method) before the registration is complete.
Check if the verification link/token expires after a certain time.

10.Session Management
Once registered and if the user is logged in immediately, ensure they receive a unique session ID and that this ID isn't easily guessable.

11.Multi-factor Authentication (MFA)
If MFA is an option, ensure that it's working correctly and can't be bypassed.

12.Logging and Monitoring
Check if multiple registration failures are being logged.
Ensure that critical actions (like changing email/password) during or post-registration are logged.

13.Redirects and Forwards
Check for unvalidated redirects and forwards after registration. Attackers might exploit this to redirect users to malicious sites.

14.Third-party Integrations
If registration can be done using third-party identities (like "Login with Google" or "Login with Facebook"), ensure that these integrations are secure and tokens aren't exposed.

15.Unused Features/Endpoints
Make sure there aren't any unused registration endpoints or features that can be exploited.

16.Denial of Service
Try flooding the registration form with requests to see if it can be used for DoS attacks.

17.Social Engineering
Assess any security questions or backup methods used for account recovery to ensure they aren’t easily guessable or discoverable through social engineering.

Resource

https://medium.com/@app.sec1900/test-cases-for-security-assessment-testing-925b9a018d22 
https://aalphaindia.medium.com/registration-login-test-cases-for-ecommerce-website-2022-aalpha-1f02dadd6579  https://accelatest.com/how-to-write-test-cases-for-registration-page/  
https://medium.com/@prabhathudda/web-application-security-testing-checklist-7708f7306755
https://medium.com/@loginradius/how-to-write-test-cases-for-registration-and-login-page-42c32af7ec46
https://sm4rty.medium.com/hunting-for-bugs-in-sign-up-register-feature-2021-c47035481212


2.Login Page:

1.No Captcha Implemented
2.Username/Email enumeration via verbose failure messages
3.Mobile enumeration via verbose failure messages
4.Brute Force Possible/No account lockout policy
5.Remember me Functionality
6.No MFA
7.No, Forget Password Functionality
8.No Virtual Keyboard Supported
9.Password is not case sensitive while login
10.Response Mauplation
11.SQL Injection
12.Authentication Bypass
13.Session Managment
14.Account Locking and Unlocking
15.Session Timeout
16.Testing with Different User Roles User, Admin

1.Input Validation:
Inject special characters or SQL statements into the username and password fields to check for SQL injection vulnerabilities.
Attempt to input HTML or JavaScript snippets to test for cross-site scripting (XSS) vulnerabilities.
Enter overly long strings into the fields to test for buffer overflow.

2.Account Enumeration:
Observe system's response to entering non-existent usernames or wrong passwords. It shouldn't indicate whether a particular user exists or not.

3.Brute Force Attacks:
Attempt to login multiple times with different password combinations to ensure there are measures to prevent brute force attacks, like account lockouts or CAPTCHAs.

4.Session Management:
Once logged in, ensure the application assigns a unique session ID. Test if manually changing the session ID allows access to another user's session.
Ensure the session expires after a period of inactivity.

5.Password Policy Enforcement:
Attempt multiple incorrect passwords and observe system behavior (e.g., does it lock out after 'n' attempts?).

6.Data Transmission Security:
Ensure the login page is secured with HTTPS, indicating data is encrypted during transmission.
Intercept the login request using tools like Burp Suite or OWASP ZAP and verify if the data (especially passwords) is sent in clear text.

7.Error Handling:
Ensure that no detailed system errors (e.g., database errors) are shown to the user.

8.Redirects and Forwards:
Test for unvalidated redirects and forwards after login to prevent attackers from redirecting users to malicious sites.

9.Two-factor or Multi-factor Authentication:
If provided, ensure the MFA process works correctly and can't be bypassed.
Test the MFA recovery process.

10.Remember Me Functionality:
If a "Remember Me" option is provided, test its functionality and ensure it doesn't compromise security.

11.Account Recovery:
Test the account/password recovery process. Ensure that security questions (if used) aren't trivial.
Ensure that reset tokens sent via email or other methods expire after a certain period or after being used.

12.Logging and Monitoring:
Ensure login failures are logged with relevant details (e.g., IP address, timestamp).
Multiple failed login attempts from the same IP in a short period should raise alerts.

13.Test for Auto-fill Browsers Feature:
Ensure that sensitive fields like passwords are not easily auto-filled without user confirmation.

14.Check for Session Fixation:
Log into the application and note down the session cookie. Log out and then use the same cookie to access the application. The application should not allow access.

15.Logout Functionality:
After logging out, ensure that the user's session is terminated and cannot be reused.

16.Third-party Integrations:
If login can be done using third-party services (like "Login with Google" or "Login with Facebook"), ensure these integrations are secure.
T
17.esting for Default Credentials:
Check if the application has any default usernames and passwords set up (e.g., admin/admin) and ensure they are changed or disabled in production environments.

18.Check for Denial of Service (DoS):
Attempt to flood the login form with numerous requests in a short period and observe the application's behavior.

Resource
https://medium.com/@app.sec1900/test-cases-for-security-assessment-testing-925b9a018d22 
https://agilitest.medium.com/a-checklist-for-login-page-testing-agilitest-blog-54bdd3855478
https://medium.com/@amaralisa321/how-to-write-test-cases-for-registration-page-b826d418bc1a

3.Password Reset Functionality:
Testing the password reset functionality is crucial because it's often a target for attackers aiming to gain unauthorized access to user accounts. Here's a comprehensive list of security test cases tailored for the password reset functionality.

1.No password change functionality post login
2.No password history enforcement
3.Insufficient password complexity
4.Password Policy accepts any Special Characters
5.Unverified Password Change/No old password required for new password
6.Password change link reused/ does not expire
7.Old password link does not expire on new link generation
8.Password change token is tied with email id/username
9.Reset Password Email flooding
10.No minimum time interval between password changes
11.Wrong Redirection post password change
12.No logout button enabled on Dashboard
13.No Email on sensitive action
14.brute-forcing the reset token
15.Account Tackover
16.Testing with Different User Roles User, Admin
17.Cross-Site Request Forgery(CSRF)

1.Token Generation and Expiry:
Ensure the reset token/link is unique and random, and can't be easily guessed or brute-forced.
Check if the token expires after a certain period.
Ensure the token is invalidated after use.

2.Token Transmission Security:
Ensure that the reset token/link is transmitted securely (e.g., via HTTPS if sent through a link in an email).

3.Brute Force Attacks:
Try brute-forcing the reset token to see if there's any rate limiting or lockout mechanisms in place.

4.Input Validation on Reset Form:
Test for SQL injection, XSS, and buffer overflow vulnerabilities on the password reset input fields.

5.Account Enumeration:
Observe the application's response when requesting a password reset for both existing and non-existing accounts. The response shouldn't reveal whether an email is associated with an account in the system.

6.Session Management after Password Reset:
After a successful password reset, ensure that all active sessions for the user are terminated, requiring re-login with the new password.

7.Email Notification:
When a password reset request is made, the account owner should receive an email notification, even if the request was not initiated by them. This acts as an alert for potential unauthorized reset attempts.

8.Password Policy Enforcement:
Ensure the new password adheres to the application's password policy in terms of length, complexity, etc.

9.Direct Access to Reset Page:
Try accessing the password reset page directly without a valid token to ensure it's not accessible.

10.Resending Password Reset Link:
Request password reset multiple times. Check if the application invalidates the older links/tokens when a new one is generated.

11.Use of Captcha:
Ensure CAPTCHA or similar anti-bot mechanisms are in place to prevent automated attacks on the password reset page.

12.Logging and Monitoring:
Ensure that password reset attempts, both successful and unsuccessful, are logged with relevant details like IP address, timestamp, and user-agent.

13.Error Handling:
Observe the error messages displayed for invalid tokens, expired tokens, etc. The messages shouldn't reveal too much about the system's internal workings or database details.

14.Two-factor or Multi-factor Authentication:
If the user has MFA enabled, ensure the password reset process incorporates MFA verification.

15.Testing with Different User Roles:
If the application has different user roles (e.g., user, admin), test the reset functionality for each role to ensure there are no discrepancies in the process or potential vulnerabilities specific to a role.

16.Backend Verification:
Check how the reset tokens are stored in the backend. They should be stored securely (hashed) or not stored at all.

17.Cross-Site Request Forgery (CSRF):
Ensure the password reset functionality is protected against CSRF attacks.

18.Password History Check:
After resetting, the application should not allow the use of the last 'n' passwords used by the user.

4.Authentication Bypass Functionality security test cases:

Authentication bypass vulnerabilities can be catastrophic for an application, allowing attackers to gain unauthorized access to sensitive functionalities. Testing for these vulnerabilities is paramount for application security. Here are some security test cases tailored for authentication bypass functionality.

1.Forced Browsing
2.Parameter Modification
3.using response manipulation
4.using response replay attack
5.using OTP bypass/MFA bypass
6.leveraging OTP misconfiguration
7.Using session ID prediction
8.SQL Injection
9.Session Token Manipulation
10.Privilage Escalation
11.Discover Hidden Directories or Endpoints
12.Default Usernames and Passwords
13.Unauthorized HTTP Methods Allowed on Restricted Endpoints
14.Cookie Manuplation
15.Race Conditions

1.Direct URL Access:
Attempt to access restricted pages directly by typing or pasting their URLs.

2.Session Token Manipulation:
Intercept the authentication request and modify the session token or other authentication headers.
Reuse old session tokens to see if they provide access.

3.Parameter Modification:
Change user role parameters, user IDs, or other identifiers in the URL, cookies, or hidden input fields.

4.Password Field Manipulation:
Try bypassing the login prompt by inputting SQL injection payloads or special characters.

5.Forceful Browsing:
Use tools like Dirbuster or OWASP ZAP to discover hidden directories or endpoints and try accessing them.

6.Default Credentials:
Check for default usernames and passwords (e.g., admin/admin or guest/guest).

7.Token Predictability:
Check if tokens (like session IDs) are easily guessable or follow a pattern.

8.HTTP Methods:
Check if unauthorized HTTP methods (like PUT, DELETE) are allowed on restricted endpoints.

9.Browser Extensions:
Use browser extensions that may facilitate authentication bypass (like manipulating cookies).

10.Remember Me Functionality:
If the application has a "Remember Me" option, check if manipulating this functionality can lead to an authentication bypass.

11.3rd Party Authentication Services:
If the application uses third-party services for authentication (e.g., OAuth with Google or Facebook), test if you can bypass these services or spoof their tokens/responses.

12.Race Conditions:
Try to exploit potential race conditions where you send multiple requests simultaneously to bypass authentication checks.

13.JSON Web Tokens (JWT):
If JWT is used, try to:
Alter the payload.
Exploit weak signatures.
Use common vulnerabilities, like the "none" algorithm.

14.Error Messages:
Check if error messages reveal information that could assist in bypassing authentication.

16.Account Lockout Mechanism:
Attempt to bypass account lockout mechanisms by changing IP addresses, clearing cookies, or using a different user-agent.

17.Password Reset and Recovery Functionality:
Check if there's a flaw in the password reset mechanism that can be exploited to bypass authentication.

18.Two-factor or Multi-factor Authentication Bypass:
Try to bypass MFA by intercepting requests, manipulating responses, or exploiting fallback mechanisms.

19.CORS Misconfigurations:
Check for Cross-Origin Resource Sharing misconfigurations that might allow unauthorized domains to bypass authentication mechanisms.

20.Request Header Manipulation:
Modify headers like "X-Forwarded-For" to trick the application into thinking the request is coming from a trusted source.

21.Browser's Private/Incognito Mode:
Test the application in a private or incognito window to see if there's a different behavior that can be exploited.

5.Session Management:

Weak token generation/predictable token
Session fixation
Multiple Concurrent Sessions Allowed
No session invalidation after logout/SessionID can be used post logout
Session timeout not implemented
Improper Session Management on Password Change
Back Button Enabled

6.Authorization Flaw:

1.Authentication bypass via invalidation of credentials (Parameter modification)
2.Insecure access (without token/OTP/MFA)
3.Directory traversal
4.File inclusion
5.Privilege escalation
6.Insecure direct object reference (IDOR)
7.Forced browsing
8.Business logic flaw
9.Business constraint bypass
10.Business flow bypasses
11.Business control bypass
12.Sensitive data exposure
13.PCI data in clear text
14.Sensitive data submission in clear text
15.Password without hashing and salting
16.Clear text password in response
17.Clear text password stored in cookies
18.Sensitive data traveled via GET method
19.Cleat text storage of sensitive information in Database
20.Information disclosure
21.Internal IP disclosure

7.File Uploads security test cases:
When an application allows file uploads, it's critical to test this functionality rigorously because it can be exploited in numerous ways. Here are security test cases tailored for file upload functionalities.

1.Test that acceptable file types are whitelisted
2.Test that file size limits, upload frequency and total file counts are defined and are enforced
3.Test that file contents match the defined file type
4.Test that all file uploads have Anti-Virus scanning in-place.
5.Test that unsafe filenames are sanitised
6.Test that uploaded files are not directly accessible within the web root
7.Test that uploaded files are not served on the same hostname/port
8.Test that files and other media are integrated with the authentication and authorisation schemas
9.XSS
10.SSRF
11.Remot Code Execution(RCE)
12.Test the file size limits
13.Content-Type Manipulation
14.Metadata 

1.Unrestricted File Types
Attempt to upload file types not explicitly allowed (e.g., .exe, .php, .js, .bat).

2.Malicious File Content
Upload files that contain malicious content like malware or scripts intended to be executed on the server or client-side.

3.File Size Limitations
Test the file size limits by uploading files that exceed the specified limit.

4.File Name Manipulations
Try to upload files with names containing special characters, very long names, or names resembling system or reserved files.

5.Double Extensions
Upload files with double extensions to bypass certain checks, e.g., image.php.jpg.

6.Content-Type Manipulation
Intercept the upload request and modify the Content-Type header to a type different from the actual file.

7.File Overwrite
Attempt to overwrite existing files by uploading a file with the same name.

8.Path Traversal
Test for path traversal vulnerabilities by using filenames like ../../../etc/passwd.

9.Server-Side Execution
Upload files that can be executed server-side (e.g., PHP, ASP, JSP) and then try accessing these files via their URLs to see if they get executed.

12.Client-Side Attacks
Upload files containing malicious JavaScript or HTML to test for stored cross-site scripting (XSS) vulnerabilities.

11.Metadata Payloads
Embed malicious payloads within the metadata of files (e.g., a malicious macro in a Word document) and upload them.

12.Image Uploads with Embedded Code
For image uploads, embed code or malicious payloads within images to see if they can be executed.

13.File Upload via API
If the application provides API endpoints for file uploads, try to bypass restrictions using the API directly.

14.File Integrity and Transformation
Check if uploaded files are transformed in any way (e.g., images being resized) and whether this process can be exploited.

15.File Storage Location
Determine where files are stored after upload (e.g., on the server, cloud storage) and if there are different security considerations or vulnerabilities based on this location.

16.Duplicate File Uploads
Check how the system handles duplicate file uploads. Does it overwrite the old file, rename the new one, or block the upload?

17.HTTP Headers and File Uploads
Manipulate HTTP headers during the file upload process to see if they can be used to bypass restrictions or mislead the application.

18.Flash or Silverlight Uploaders
If the application uses Flash or Silverlight-based uploaders, test these components specifically for vulnerabilities.

19.Third-party Libraries or Plugins
If third-party plugins or libraries are used for file upload functionality, check if they have known vulnerabilities or if they can be exploited.

20.Error Messages
Observe error messages during failed upload attempts. They shouldn't reveal sensitive system information.

21.Logging and Monitoring
Ensure that all file uploads, successful or not, are appropriately logged.

22.Access Controls
Ensure that unauthorized users can't view or download uploaded files.

Injection:

SQL injection
Error based
Union-based
Boolean based
Time-based
Out-of-band
Second-order
Cross-site scripting (XSS)
Reflected
Stored
DOM
Blind
HTML injection
CSS injection
Link injection
Iframe injection
CSV/Formula injection
XML injection
XPath injection
LDAP injection
NoSQL Injection
Command injection
Server-side template injection
Host header injection

Other Vulnerabilities:

Cross-site request forgery
Server-side request forgery
File upload
XML external entity (XXE)
Insecure deserialization
HTTP Request smuggling/Desynchronization attack
HTTP Response splitting/CRLF injection
HTTP Parameter pollution
HTTP Verb tempering
Open redirection
Clickjacking
Misconfigured CORS
Misconfigured referer header
Data replay attack
Race condition
Web cache poisoning
Web cache deception
Cryptographic Failures:
Unencrypted HTTP communication
Self-signed Certificate
SSL/TLSv1.0
SSL/TLS supports weak ciphers
SSL weak hashing algorithm
TLS fallback is not supported
Other Security Misconfigurations:
OTP Flooding
HTTP basic authentication/HTML form-based authentication
No email/activity alert on sensitive action (account registration/change password)
Weak/default/predictable username
Weak/default/predictable password
HTTP security header missing
Cookie not marked Secure/HttpOnly
Cacheable HTTP response
Web vendor/version disclosure
Email spoofing
Vulnerable components/Outdated framework
Track/Trace/Delete method enabled
No privacy policy implemented
Robots.txt file exposure
Robots.txt file misconfigured
Admin module exposed publicly
No separate table for admin and normal user accounts
No super admin for multiple admin accounts
Database running with root privileges
Backup file found on the server
Hidden/Sensitive/Default files found
Upload module on public page
Server time misconfigured
Insufficient logging and monitoring
Server-side Vulnerabilities are as below:
SQLi
Authentication
Business logic Vulnerabilities
Access Control
Server-side Request Forgery
XXE Injection
Directory Traversal
Command Injection
Information Disclosure
Client-side Vulnerabilities are as below:
XSS
CSRF
CORS
Clickjacking
DOM Based Vulnerabilities
Web Sockets
URL-based vulnerabilities:
SQL Injection
Error based
Union based
Time-based
XSS
Reflected
DOM
XXE
File Inclusion
LFI
RFI
Directory Traversal
IDOR
Privilege Escalation
Horizontal
Vertical
OS Command Injection
SSRF
Parameter pollution
Response Splitting/CRLF
Form-based vulnerability
SQL Injection
XSS
Reflection
Stored
DOM
Blind
Other Injection
HTML
CSS
iFrame
Formula
Command
SSTI
XXE
CSRF
File Upload
Clickjacking
Header based vulnerability
Host header injection
Request Smuggling
Misconfigured CORS
Verb Tampering
Misconfigured referer header
Web cache Poisoning
Web cache deception
Data replay attack
Missing Security Header
Cookie Issues
Web Vendor/version disclosure
Cacheable response

Missing Security Header:

1.Missing HTTP Security Header (using Burp)
2.Cacheable HTTP Responses (using Burp)
3.Web vendor/version disclosure (using Burp)
4.Track/Trace/Delete method enabled (using Burp)
5.Vulnerable components/Outdated framework (using RetireJS, Wappalyser)
6.Cookie not marked Secure/HttpOnly (using Burp)
7.SSL/TLSv1.0 (using TestSSL)
8.SSL/TLS supports weak ciphers (using TestSSL)
9.SSL weak hashing algorithm (using TestSSL)
10.Form/Field autocomplete ON (using Browser)
11.Hardcoded Sensitive information (using Browser)
12.Data replay attack (using Burp)
13.Misconfigured CORS (using Burp)
14.Host Header Injection (using Burp)
15.HTTP Verb Tampering (using Burp)
16.Open Redirection (using Burp)
17.Sensitive Data in Clear Text (using Burp)
18.Unencrypted Communication (using Browser)
19.Web application accessible via IP (using Browser)

Resoureces

https://github.com/devanshbatham/Awesome-Bugbounty-Writeups
https://github.com/Voorivex/pentest-guide
https://github.com/daffainfo/AllAboutBugBounty
https://github.com/bittentech/Bug-Bounty-Beginner-Roadmap
https://github.com/sehno/Bug-bounty/blob/master/bugbounty_checklist.md
https://github.com/Pat13nt0/Pentesting-Resources
https://github.com/NafisiAslH/KnowledgeSharing/tree/main/CyberSecurity/Web/BountyStory
https://github.com/0xmaximus/Galaxy-Bugbounty-Checklist
https://github.com/Z4nzu/hackingtool
