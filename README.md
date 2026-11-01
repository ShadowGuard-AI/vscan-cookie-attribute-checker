# vscan-cookie-attribute-checker
Checks cookies for security-related attributes like HttpOnly, Secure, and SameSite. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-cookie-attribute-checker`

## Usage
`./vscan-cookie-attribute-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-o`: No description provided

## Notes
Attributes are read per cookie from the response Set-Cookie headers: Secure and HttpOnly are reported as present or absent, and SameSite is reported with its value or as absent. Cookie values are never printed or saved. Reports carry the cookie name and its attributes only, with a fixed masked marker in the value slot.

## License
Copyright (c) ShadowStrikeHQ
