# JWTService
A Velocity Service Which Will Handle JWTs

## Workings
when user logins, they are given an access and refresh token which contains their user id and scopes. Whenever user tries to perform any action, their access token is validated in order to verify that it is the user themself trying to perform the action. Only this JWTService has the key which can validate user's access token. The access token is short lived hence expires after some time. When the access token expired, user has to give their refresh token to obtain new access and refresh token. Important tasks such as changing password can only be done using fresh tokens. When user wants to do these tasks, they have to relogin and obtain a fresh token which is extremely short lived. also this token cant be refreshed and whenever user wants to obtain this token, they need to login. When tasks such as changing password are done, they require the fresh token.

## Functions
- FreshToken -- Creates a fresh token based on user identity
- AccessAndRefreshToken -- Creates an access and refresh token based on user identity and scopes
- RefreshToken -- Creates new access and refresh token based on old refresh token
- ValidateToken -- Validates any type of token

## Claims Struct
```go
type Claims struct {
	UserIdentity  string   `json:"UserIdentity"`
	IsFresh       bool     `json:"IsFresh"`
	IsRefresh     bool     `json:"IsRefresh"`
	Scopes        []string `json:"Scopes"`
	CreationUTC   int64    `json:"CreationUTC"`
	ExpirationUTC int64    `json:"ExpirationUTC"`
	jwt.StandardClaims
}
```