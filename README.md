TwoStepsAuthenticator
=====================

.net implementation of the TOTP: Time-Based One-Time Password Algorithm and HOTP: HMAC-Based One-Time Password Algorithm<br/>
RFC 6238 http://tools.ietf.org/html/rfc6238<br>
RFC 4226 http://tools.ietf.org/html/rfc4226

Compatible with Microsoft Authenticator for Windows Phone, and Google Authenticator for Android and iPhone.

You can use this library as well for a client application (if you want to create your own authenticator) or for a server application (add two-step authentication on your asp.net website)

![Build status](https://glacasa.visualstudio.com/DefaultCollection/_apis/public/build/definitions/ab4c93fc-5d51-44a7-b9e5-fcd42fbb9bc3/7/badge)

# TOTP

## Client usage

For a client application, you need to save the secret key for your user. <br/>
Then, you only have to call the method GetCode(string) :

```c#
var secret = user.secretAuthToken;
var authenticator = new TwoStepsAuthenticator.TimeAuthenticator();
var code = authenticator.GetCode(secret);
```

## Server usage

On a server application, you will have to generate a secret key, and share it with the user, who will have to enter it in his own authenticator app.

```c#
var key = TwoStepsAuthenticator.Authenticator.GenerateKey();
```

When the user will login, he will have to give you the code generated by his authenticator.<br/>
You can check if the code is correct with the method CheckCode(string secret, string code).<br/>
If the code is incorrect, don't log him.

```c#
var secret = user.secretAuthToken;
var code = Request.Form["code"];
var authenticator = new TwoStepsAuthenticator.TimeAuthenticator();
bool isok = authenticator.CheckCode(secret, code);
```

### Used codes manager

Every code should only be used once. To prevent repeated use of a code a IUsedCodesManager interface is provided.<br>

A default implementation is provided : used codes are kept in memory for 5 minutes (long enough for codes to become invalid)

You can define how the used codes are stored, for example if you want to handle persistence (database storage), or if you have multiple webservers.<br/>
You have to implement the 2 methods of the IUsedCodesManager :

```c#
void AddCode(ulong challenge, string code, object user);
bool IsCodeUsed(ulong challenge, string code, object user);
```

The user class must implement correctly the GetHashCode and Equals methods, because they are used to check if a specific user has used each code.

When you create a new Authenticator, add the instance of your IUsedCodesManager as the first param

```c#
var usedCodeManager = new CustomUsedCodeManager();
var authenticator = new TwoStepsAuthenticator.TimeAuthenticator(usedCodeManager);
```

And when you check if the code is ok, you need to add the user object to the CheckCode method

```c#
bool isok = authenticator.CheckCode(secret, code, user);
```
