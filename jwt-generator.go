package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// claimsList - type for collecting many flags in -claims
type claimsList []string

func (c *claimsList) String() string {
	return strings.Join(*c, ", ")
}

func (c *claimsList) Set(value string) error {
	// Support multiple claims in one flag: -claim key1=val1,key2=val2
	// Split by comma and add each claim separately
	parts := strings.Split(value, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			*c = append(*c, trimmed)
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		generateCommand(os.Args[2:])
	case "decode":
		decodeCommand(os.Args[2:])
	case "verify":
		verifyCommand(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("JWT Token Generator - Generate, decode, and verify JWT tokens")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  jwt-gen <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  generate    Generate a new JWT token")
	fmt.Println("  decode      Decode and display JWT token claims")
	fmt.Println("  verify      Verify JWT token signature")
	fmt.Println("  help        Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  jwt-gen generate -claim source=app,user_id=123")
	fmt.Println("  jwt-gen decode <token>")
	fmt.Println("  jwt-gen decode -file <file>")
	fmt.Println("  jwt-gen verify <token> -pubkey public_key.pem")
}

func generateCommand(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	var claims claimsList
	keyPath := fs.String("key", "private_key.pem", "Path to private key file")
	expiration := fs.Int("exp", 2592000, "Token expiration time in seconds")
	fs.Var(&claims, "claim", "Claim in format key=value (can be specified multiple times)")
	fs.Parse(args)

	if len(claims) == 0 {
		log.Fatal("Error: at least one -claim parameter is required")
	}

	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		log.Fatalf("Error loading private key: %v", err)
	}

	claimsMap := jwt.MapClaims{
		"exp": time.Now().Add(time.Duration(*expiration) * time.Second).Unix(),
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
	}

	for _, claim := range claims {
		parts := strings.SplitN(claim, "=", 2)
		if len(parts) != 2 {
			log.Fatalf("Invalid claim format: %s (expected key=value)", claim)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			log.Fatalf("Empty key in claim: %s", claim)
		}
		claimsMap[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsMap)

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("Error signing token: %v", err)
	}

	fmt.Println(tokenString)
}

func decodeCommand(args []string) {
	fs := flag.NewFlagSet("decode", flag.ExitOnError)
	tokenPath := fs.String("file", "", "Path to token file (if not provided, token is read from stdin)")
	fs.Parse(args)

	var tokenString string

	if *tokenPath != "" {
		var err error
		tokenString, err = loadTokenFromFile(*tokenPath)
		if err != nil {
			log.Fatalf("Error loading token from file: %v", err)
		}
	} else {
		if fs.NArg() < 1 {
			log.Fatal("Error: token is required\nUsage: jwt-gen decode <token> or jwt-gen decode -file <file>")
		}
		tokenString = fs.Arg(0)
	}

	// Parse token without verification
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		log.Fatalf("Error parsing token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Fatal("Error: failed to parse claims")
	}

	printClaims(claims)
}

func verifyCommand(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubKeyPath := fs.String("pubkey", "public_key.pem", "Path to public key file")
	fs.Parse(args)

	if fs.NArg() < 1 {
		log.Fatal("Error: token is required\nUsage: jwt-gen verify <token> -pubkey public_key.pem")
	}

	tokenString := fs.Arg(0)

	// Load public key
	publicKey, err := loadPublicKey(*pubKeyPath)
	if err != nil {
		log.Fatalf("Error loading public key: %v", err)
	}

	// Parse and verify token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		log.Fatalf("Error verifying token: %v", err)
	}

	if !token.Valid {
		log.Fatal("Token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Fatal("Error: failed to parse claims")
	}

	fmt.Println("✓ Token signature is valid")
	fmt.Println()
	printClaims(claims)
}

func printClaims(claims jwt.MapClaims) {
	fmt.Println("Token Claims:")
	fmt.Println("=============")

	displayClaims := make(map[string]interface{})
	for key, value := range claims {
		switch key {
		case "exp", "iat", "nbf":
			if timestamp, ok := value.(float64); ok {
				t := time.Unix(int64(timestamp), 0)
				displayClaims[key] = fmt.Sprintf("%d (%s)", int64(timestamp), t.Format(time.RFC3339))
			} else {
				displayClaims[key] = value
			}
		default:
			displayClaims[key] = value
		}
	}

	jsonBytes, err := json.MarshalIndent(displayClaims, "", "  ")
	if err != nil {
		log.Fatalf("Error formatting claims: %v", err)
	}

	fmt.Println(string(jsonBytes))
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	// Reading key from file
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Decoding PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parsing private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Trying PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA private key")
		}
	}

	return privateKey, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	// Reading key from file
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Decoding PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parsing public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA public key")
	}

	return publicKey, nil
}

func loadTokenFromFile(path string) (string, error) {
	tokenData, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read token from file: %w", err)
	}
	return strings.TrimSpace(string(tokenData)), nil
}
