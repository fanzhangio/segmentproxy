package auth

// JWTToken represents for LW Access Token
type JWTToken struct {
	TokenID    string   `json:"jti"`
	Subject    string   `json:"sub"`
	Audience   []string `json:"aud"`
	Groups     []string `json:"groups"`
	Issuer     string   `json:"iss"`
	IssuedAt   int64    `json:"iat"`
	ExpiresAt  int64    `json:"exp"`
	Scope      string   `json:"scope"`
	TokenType  string   `json:"token_type"`
	TokenClass string   `json:"token_class"`
	Tenant     string   `json:"tenant"`
}

// JWTRefreshToken represents for LW Refresh Token
type JWTRefreshToken struct {
	TokenID    string `json:"jti"`
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	Issuer     string `json:"iss"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
	Scope      string `json:"scope"`
	TokenType  string `json:"token_type"`
	TokenClass string `json:"token_class"`
	Tenant     string `json:"tenant"`
}
