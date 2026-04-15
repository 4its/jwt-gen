package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	testPrivateKey  *rsa.PrivateKey
	testPrivKeyFile string
	testPubKeyFile  string
)

func TestMain(m *testing.M) {
	var err error
	testPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	privFile, err := os.CreateTemp("", "jwt_test_priv_*.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(privFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(testPrivateKey),
	})
	privFile.Close()
	testPrivKeyFile = privFile.Name()

	pubBytes, err := x509.MarshalPKIXPublicKey(&testPrivateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	pubFile, err := os.CreateTemp("", "jwt_test_pub_*.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	pubFile.Close()
	testPubKeyFile = pubFile.Name()

	code := m.Run()

	os.Remove(testPrivKeyFile)
	os.Remove(testPubKeyFile)
	os.Exit(code)
}

func makeToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(testPrivateKey)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	return s
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "jwt_test_*.txt")
	if err != nil {
		t.Fatalf("writeTempFile: %v", err)
	}
	f.WriteString(content)
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestClaimsListSet(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "single claim",
			input: []string{"key=value"},
			want:  []string{"key=value"},
		},
		{
			name:  "comma-separated claims",
			input: []string{"k1=v1,k2=v2"},
			want:  []string{"k1=v1", "k2=v2"},
		},
		{
			name:  "spaces trimmed",
			input: []string{" k1=v1 , k2=v2 "},
			want:  []string{"k1=v1", "k2=v2"},
		},
		{
			name:  "empty parts skipped",
			input: []string{"k1=v1,,k2=v2"},
			want:  []string{"k1=v1", "k2=v2"},
		},
		{
			name:  "multiple Set calls accumulate",
			input: []string{"k1=v1", "k2=v2"},
			want:  []string{"k1=v1", "k2=v2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c claimsList
			for _, input := range tt.input {
				if err := c.Set(input); err != nil {
					t.Fatalf("Set(%q) error: %v", input, err)
				}
			}
			if len(c) != len(tt.want) {
				t.Fatalf("got %v, want %v", []string(c), tt.want)
			}
			for i, got := range c {
				if got != tt.want[i] {
					t.Errorf("c[%d] = %q, want %q", i, got, tt.want[i])
				}
			}
		})
	}
}

func TestLoadTokenFromFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{
			name:    "plain token",
			content: "abc.def.ghi",
			want:    "abc.def.ghi",
		},
		{
			name:    "trailing newline trimmed",
			content: "abc.def.ghi\n",
			want:    "abc.def.ghi",
		},
		{
			name:    "surrounding whitespace trimmed",
			content: "  abc.def.ghi  \n",
			want:    "abc.def.ghi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, tt.content)
			got, err := loadTokenFromFile(path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("non-existent file", func(t *testing.T) {
		_, err := loadTokenFromFile("/no/such/file.txt")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestLoadPrivateKey(t *testing.T) {
	t.Run("valid PKCS1", func(t *testing.T) {
		key, err := loadPrivateKey(testPrivKeyFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key == nil {
			t.Fatal("expected key, got nil")
		}
	})

	t.Run("valid PKCS8", func(t *testing.T) {
		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(testPrivateKey)
		if err != nil {
			t.Fatalf("marshal PKCS8: %v", err)
		}
		f, err := os.CreateTemp("", "jwt_test_pkcs8_*.pem")
		if err != nil {
			t.Fatal(err)
		}
		pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
		f.Close()
		t.Cleanup(func() { os.Remove(f.Name()) })

		key, err := loadPrivateKey(f.Name())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key == nil {
			t.Fatal("expected key, got nil")
		}
	})

	errorTests := []struct {
		name    string
		path    string
		content string
	}{
		{
			name: "non-existent file",
			path: "/no/such/key.pem",
		},
		{
			name:    "invalid PEM",
			content: "not a pem block",
		},
		{
			name:    "invalid key bytes",
			content: "-----BEGIN RSA PRIVATE KEY-----\naW52YWxpZA==\n-----END RSA PRIVATE KEY-----\n",
		},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if path == "" {
				path = writeTempFile(t, tt.content)
			}
			_, err := loadPrivateKey(path)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}

	t.Run("non-RSA key (ECDSA)", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.CreateTemp("", "jwt_test_ecdsa_priv_*.pem")
		if err != nil {
			t.Fatal(err)
		}
		pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
		f.Close()
		t.Cleanup(func() { os.Remove(f.Name()) })

		_, err = loadPrivateKey(f.Name())
		if err == nil {
			t.Error("expected error for non-RSA key, got nil")
		}
	})
}

func TestLoadPublicKey(t *testing.T) {
	t.Run("valid public key", func(t *testing.T) {
		key, err := loadPublicKey(testPubKeyFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key == nil {
			t.Fatal("expected key, got nil")
		}
	})

	errorTests := []struct {
		name    string
		path    string
		content string
	}{
		{
			name: "non-existent file",
			path: "/no/such/key.pem",
		},
		{
			name:    "invalid PEM",
			content: "not a pem block",
		},
		{
			name:    "invalid key bytes",
			content: "-----BEGIN PUBLIC KEY-----\naW52YWxpZA==\n-----END PUBLIC KEY-----\n",
		},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if path == "" {
				path = writeTempFile(t, tt.content)
			}
			_, err := loadPublicKey(path)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}

	t.Run("non-RSA key (ECDSA)", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.CreateTemp("", "jwt_test_ecdsa_pub_*.pem")
		if err != nil {
			t.Fatal(err)
		}
		pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		f.Close()
		t.Cleanup(func() { os.Remove(f.Name()) })

		_, err = loadPublicKey(f.Name())
		if err == nil {
			t.Error("expected error for non-RSA key, got nil")
		}
	})
}

func TestGenerateCommand(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "no claims",
			args:    []string{"-key", testPrivKeyFile},
			wantErr: true,
		},
		{
			name:    "valid single claim",
			args:    []string{"-key", testPrivKeyFile, "-claim", "user=alice"},
			wantErr: false,
		},
		{
			name:    "valid multiple claims via comma",
			args:    []string{"-key", testPrivKeyFile, "-claim", "user=alice,role=admin"},
			wantErr: false,
		},
		{
			name:    "invalid key path",
			args:    []string{"-key", "/no/such/key.pem", "-claim", "user=alice"},
			wantErr: true,
		},
		{
			name:    "invalid claim format (no =)",
			args:    []string{"-key", testPrivKeyFile, "-claim", "invalid"},
			wantErr: true,
		},
		{
			name:    "empty key in claim",
			args:    []string{"-key", testPrivKeyFile, "-claim", "=value"},
			wantErr: true,
		},
		{
			name:    "unknown flag",
			args:    []string{"-unknown"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := generateCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeCommand(t *testing.T) {
	validToken := makeToken(t, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenFile := writeTempFile(t, validToken)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid token as arg",
			args:    []string{validToken},
			wantErr: false,
		},
		{
			name:    "valid token from file",
			args:    []string{"-file", tokenFile},
			wantErr: false,
		},
		{
			name:    "no token",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "invalid token",
			args:    []string{"not.a.token"},
			wantErr: true,
		},
		{
			name:    "non-existent file",
			args:    []string{"-file", "/no/such/file.txt"},
			wantErr: true,
		},
		{
			name:    "unknown flag",
			args:    []string{"-unknown"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := decodeCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyCommand(t *testing.T) {
	validToken := makeToken(t, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	expiredToken := makeToken(t, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid token",
			args:    []string{"-pubkey", testPubKeyFile, validToken},
			wantErr: false,
		},
		{
			name:    "expired token",
			args:    []string{"-pubkey", testPubKeyFile, expiredToken},
			wantErr: true,
		},
		{
			name:    "no token provided",
			args:    []string{"-pubkey", testPubKeyFile},
			wantErr: true,
		},
		{
			name:    "invalid token",
			args:    []string{"-pubkey", testPubKeyFile, "not.a.token"},
			wantErr: true,
		},
		{
			name:    "invalid pubkey path",
			args:    []string{"-pubkey", "/no/such/key.pem", validToken},
			wantErr: true,
		},
		{
			name:    "unknown flag",
			args:    []string{"-unknown"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyCommand(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
