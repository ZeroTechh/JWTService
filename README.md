# JWTService
A Velocity Service Which Will Handle JWTs

## Goals For v1.0.0
- Ability to create access, refresh and fresh token based on user identity and scopes
- Ability to create new access and refresh token based on a refresh token
- Ability to validate all types of token
- (fresh access tokens are very short lived non refreshable tokens used for important functions such as changing passwords)