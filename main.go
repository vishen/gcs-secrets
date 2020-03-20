package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/iterator"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google"

	"cloud.google.com/go/storage"
)

var (
	kmsProjectID = flag.String("kms-project-id", "", "KMS project id")
	kmsRegion    = flag.String("kms-region", "global", "KMS region")
	kmsKeyRing   = flag.String("kms-keyring", "", "KMS KeyRing")
	kmsKey       = flag.String("kms-key", "", "KMS Key")

	gcsBucket = flag.String("gcs-bucket", "", "GCS Bucket to store or retrieve secret from")
	gcsPrefix = flag.String("gcs-prefix", "", "Prefix to use when creating or reading a secret")

	httpAuthToken = flag.String("http-auth-token", "", "HTTP Auth Token")
	httpAddr      = flag.String("http-addr", "", "HTTP server address to listen on")

	googleClientID     = flag.String("google-client-id", "", "Google Client ID")
	googleClientSecret = flag.String("google-client-secret", "", "Google Client Secret")
	googleRedirectHost = flag.String("google-redirect-host", "", "Google Redirect Host")

	gmailToAuthenticate = flag.String("gmail-to-authenticate", "", "Gmail To Authenticate")

	storageClient *storage.Client
	kmsClient     *cloudkms.KeyManagementClient

	validationError = "missing or empty required field %s"

	defaultTimeout = time.Second * 15
)

func getFromEnv(val *string, envName string) string {
	if *val == "" {
		*val = os.Getenv(envName)
	}
	return *val
}

func validateFlags() error {
	switch "" {
	case getFromEnv(kmsProjectID, "GCS_SECRETS_KMS_PROJECT_ID"):
		return fmt.Errorf(validationError, "-kms-project-id")
	case getFromEnv(kmsRegion, "GCS_SECRETS_KMS_REGION"):
		return fmt.Errorf(validationError, "-kms-region")
	case getFromEnv(kmsKeyRing, "GCS_SECRETS_KMS_KEYRING"):
		return fmt.Errorf(validationError, "-kms-key-ring")
	case getFromEnv(kmsKey, "GCS_SECRETS_KMS_KEY"):
		return fmt.Errorf(validationError, "-kms-key")
	case getFromEnv(gcsBucket, "GCS_SECRETS_GCS_BUCKET"):
		return fmt.Errorf(validationError, "-gcs-bucket")
	case getFromEnv(gcsPrefix, "GCS_SECRETS_GCS_PREFIX"):
		return fmt.Errorf(validationError, "-gcs-prefix")
	case getFromEnv(httpAuthToken, "GCS_SECRETS_HTTP_AUTH_TOKEN"):
		return nil
	case getFromEnv(httpAddr, "GCS_SECRETS_HTTP_SERVER_ADDRESS"):
		return nil
	case getFromEnv(googleClientID, "GCS_SECRETS_GOOGLE_CLIENT_ID"):
		return nil
	case getFromEnv(googleClientSecret, "GCS_SECRETS_GOOGLE_CLIENT_SECRET"):
		return nil
	case getFromEnv(googleRedirectHost, "GCS_SECRETS_GOOGLE_REDIRECT_HOST"):
		return nil
	case getFromEnv(gmailToAuthenticate, "GCS_SECRETS_GMAIL_TO_AUTHENTICATE"):
		return nil
	}
	return nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("requires at least 1 agrument")
	}

	cmd := args[0]
	switch cmd {
	case "get", "create", "list", "http":
		// Expected commands
	default:
		log.Fatalf("unexpected command %s", cmd)
	}

	if err := validateFlags(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if err := initialiseClients(ctx); err != nil {
		log.Fatal(err)
	}

	switch cmd {
	case "get":
		if len(args) != 2 {
			log.Fatal("get requires <key>=<secret>")
		}
		secret, err := getAndDecrypt(ctx, args[1])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Decrypted secret is: %s\n", secret)
	case "create":
		if len(args) != 2 {
			log.Fatal("create requires <key>=<secret>")
		}
		keyAndSecret := strings.Split(args[1], "=")
		if len(keyAndSecret) != 2 {
			log.Fatalf("expected <key>=<secret>")
		}
		key := keyAndSecret[0]
		secret := keyAndSecret[1]
		if err := encryptAndWrite(ctx, key, []byte(secret)); err != nil {
			log.Fatal(err)
		}
	case "list":
		secrets, err := listSecrets(ctx)
		if err != nil {
			log.Fatal(err)
		}
		for _, s := range secrets {
			fmt.Printf("%s (%s)\n", s.Name, s.Modified)
		}
	case "http":
		if err := startHTTPServer(*httpAddr, *googleClientID, *googleClientSecret, *googleRedirectHost); err != nil {
			log.Fatal(err)
		}
	}
}

func initialiseClients(ctx context.Context) error {
	var err error
	kmsClient, err = cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return fmt.Errorf("unable to create new kms client: %v", err)
	}

	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("unable to create storage client: %v", err)
	}
	return nil
}

func encryptAndWrite(ctx context.Context, key string, secret []byte) error {
	encrypted, err := encrypt(ctx, []byte(secret))
	if err != nil {
		return fmt.Errorf("unable to encrypt secret: %v", err)
	}

	if err := writeSecret(ctx, key, encrypted); err != nil {
		return fmt.Errorf("unable to write secret: %v", err)
	}
	return nil
}

func getAndDecrypt(ctx context.Context, key string) (string, error) {
	secret, err := getSecret(ctx, key)
	if err != nil {
		return "", fmt.Errorf("unable to get secret: %v", err)
	}
	m, err := decrypt(ctx, secret)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt secret: %v", err)
	}
	return string(m), nil
}

func getSecret(ctx context.Context, key string) ([]byte, error) {
	objName := filepath.Join(*gcsPrefix, key)
	obj := storageClient.Bucket(*gcsBucket).Object(objName)

	rc, err := obj.NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	secret, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func writeSecret(ctx context.Context, key string, secret []byte) error {
	objName := filepath.Join(*gcsPrefix, key)
	obj := storageClient.Bucket(*gcsBucket).Object(objName)

	wc := obj.NewWriter(ctx)
	if _, err := wc.Write(secret); err != nil {
		return err
	}
	wc.Close()

	// Update the object attributes with some metadata to indicate
	// that the object is managed by this application.
	_, err := obj.Update(ctx, storage.ObjectAttrsToUpdate{
		Metadata: map[string]string{
			"gcs-secrets": "true",
		},
	})
	if err != nil {
		return err
	}

	fmt.Printf("Wrote secret in %s at %s\n", *gcsBucket, obj.ObjectName())
	return nil
}

type Secret struct {
	Name     string
	Value    string
	Modified time.Time
}

func deleteSecret(ctx context.Context, key string) error {
	objName := filepath.Join(*gcsPrefix, key)
	return storageClient.Bucket(*gcsBucket).Object(objName).Delete(ctx)
}

func listSecrets(ctx context.Context) ([]Secret, error) {
	it := storageClient.Bucket(*gcsBucket).Objects(ctx, &storage.Query{
		Prefix: *gcsPrefix,
	})
	secrets := []Secret{}
	for {
		objAttrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		if val, _ := objAttrs.Metadata["gcs-secrets"]; val != "true" {
			continue
		}
		secrets = append(secrets, Secret{Name: strings.TrimPrefix(objAttrs.Name, *gcsPrefix+"/"), Modified: objAttrs.Updated})
	}
	if len(secrets) == 0 {
		return nil, errors.New("No keys found")
	}
	return secrets, nil
}

func fmtKMSKey() string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		*kmsProjectID,
		*kmsRegion,
		*kmsKeyRing,
		*kmsKey,
	)
}

func encrypt(ctx context.Context, message []byte) ([]byte, error) {
	req := &kmspb.EncryptRequest{
		Name:      fmtKMSKey(),
		Plaintext: message,
	}
	resp, err := kmsClient.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.GetCiphertext(), nil
}

func decrypt(ctx context.Context, secret []byte) ([]byte, error) {
	req := &kmspb.DecryptRequest{
		Name:       fmtKMSKey(),
		Ciphertext: secret,
	}
	resp, err := kmsClient.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.GetPlaintext(), nil
}

type PageData struct {
	Errors                 []error
	Secrets                []Secret
	SelectedSecret         Secret
	PreviousSecretName     string
	PreviousSecretSecret   string
	PreviousSecretGenerate string
}

func NewPageData() *PageData {
	pd := &PageData{Secrets: []Secret{}, Errors: []error{}}
	return pd
}

func indexPage(w http.ResponseWriter, r *http.Request, data *PageData) {
	tmpl := template.Must(template.ParseFiles("index.html"))
	if data == nil {
		data = NewPageData()
	}
	secrets, err := listSecrets(context.Background())
	if err != nil {
		data.Errors = append(data.Errors, err)
	} else {
		data.Secrets = secrets
	}
	tmpl.Execute(w, data)
}

func getSecretPage(w http.ResponseWriter, r *http.Request, secretKey string, data *PageData) {
	if data == nil {
		data = NewPageData()
	}
	tmpl := template.Must(template.ParseFiles("secret.html"))
	secret, err := getAndDecrypt(context.Background(), secretKey)
	if err != nil {
		data.Errors = append(data.Errors, err)
	} else {
		data.SelectedSecret = Secret{Name: secretKey, Value: secret}
	}
	tmpl.Execute(w, data)
}

func createSecretPage(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	secret := r.FormValue("secret")
	page := r.URL.Query().Get("page")
	data := NewPageData()
	if secret == "" || name == "" {
		data.Errors = append(data.Errors, errors.New("'name' or 'secret' were empty"))
	} else if err := encryptAndWrite(context.Background(), name, []byte(secret)); err != nil {
		data.Errors = append(data.Errors, err)
	} else {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	if page == "secret" && len(data.Errors) > 0 {
		getSecretPage(w, r, name, data)
	} else {
		data.PreviousSecretName = name
		data.PreviousSecretSecret = secret
		indexPage(w, r, data)
	}
}

func deleteSecretPage(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	page := r.URL.Query().Get("page")
	data := NewPageData()
	if name == "" {
		data.Errors = append(data.Errors, errors.New("'name' was empty"))
	} else if err := deleteSecret(context.Background(), name); err != nil {
		data.Errors = append(data.Errors, err)
	} else {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	if page == "secret" && len(data.Errors) > 0 {
		getSecretPage(w, r, name, data)
	} else {
		indexPage(w, r, data)
	}
}

var oauth2Config *oauth2.Config

func startHTTPServer(addr, googleClientID, googleClientSecret, redirectHost string) error {
	if addr == "" {
		return errors.New("http-addr needs to be set")
	} else if googleClientID == "" {
		return errors.New("google-client-id needs to be set")
	} else if googleClientSecret == "" {
		return errors.New("google-client-secret needs to be set")
	} else if redirectHost == "" {
		return errors.New("google-redirect-host needs to be set")
	} else if *gmailToAuthenticate == "" {
		return errors.New("gmail-to-authenticate needs to be set")
	}
	strings.TrimRight(redirectHost, "/")
	oauth2Config = &oauth2.Config{
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		RedirectURL:  redirectHost + "/google/callback",
		Endpoint:     googleOAuth2.Endpoint,
		Scopes:       []string{"email"},
	}
	http.HandleFunc("/google/login", loginHandler)
	http.HandleFunc("/google/callback", callbackHandler)
	http.HandleFunc("/css/skeleton.css", staticFileHandler("./css/skeleton.css"))
	http.HandleFunc("/css/normalize.css", staticFileHandler("./css/normalize.css"))
	http.HandleFunc("/images/favicon.png", staticFileHandler("./images/favicon.png"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", "Basic")
		_, auth, _ := r.BasicAuth()
		if auth != *httpAuthToken {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized.\n"))
			return
		}
		if !isAuthenticated(w, r) {
			// TODO: Stop redirection loop for failed logins!
			// TODO: Stop redirection loop for failed logins!
			// TODO: Stop redirection loop for failed logins!
			http.Redirect(w, r, "/google/login", http.StatusTemporaryRedirect)
			return
		}
		if keys := r.URL.Query()["key"]; len(keys) == 1 {
			getSecretPage(w, r, keys[0], nil)
		} else if r.URL.Path == "/create" && r.Method == "POST" {
			createSecretPage(w, r)
		} else if r.URL.Path == "/delete" && r.Method == "GET" {
			deleteSecretPage(w, r)
		} else {
			indexPage(w, r, nil)
		}
	})

	// Nuke all sessions every x minutes so we don't
	// leak memory. We don't really care if this causes
	// someone to login again since the timeout is
	// already really low on tokens.
	go func() {
		ticker := time.NewTicker(time.Minute * 10)
		for _ = range ticker.C {
			sessions = map[string]Token{}
		}
	}()

	log.Printf("Started http server listening on %s\n", addr)
	return http.ListenAndServe(addr, nil)
}

type Token struct {
	Created time.Time
	Valid   bool
}

var sessions = map[string]Token{}

func isAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	val := r.URL.Query().Get("oauthtoken")
	if val == "" {
		v, err := r.Cookie("googleoauth")
		if err != nil {
			fmt.Println(err)
			return false
		}
		val = v.Value
	} else {
		expire := time.Now().Add(5 * time.Minute)
		cookie := http.Cookie{
			Name:    "googleoauth",
			Value:   val,
			Expires: expire,
		}
		http.SetCookie(w, &cookie)
	}
	if v, ok := sessions[val]; ok && v.Valid {
		if time.Now().Before(v.Created.Add(5 * time.Minute)) {
			return true
		}
	}
	return false
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	val, _ := r.Cookie("googleoauth")
	if r.FormValue("state") != val.Value {
		w.WriteHeader(401)
		w.Write([]byte("Unauthorized.\n"))
		return
	}

	token, err := oauth2Config.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	oauthAPI := "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	resp, err := http.Get(oauthAPI + token.AccessToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userInfo := struct {
		Email      string `json:"email"`
		IsVerified bool   `json:"verified_email"`
	}{}
	if err := json.Unmarshal(contents, &userInfo); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if userInfo.Email == *gmailToAuthenticate && userInfo.IsVerified {
		sessions[val.Value] = Token{
			Created: time.Now(),
			Valid:   true,
		}
		http.Redirect(w, r, "/?oauthtoken="+val.Value, http.StatusTemporaryRedirect)
		return
	}
	http.Redirect(w, r, "/?auth-failed=true", http.StatusTemporaryRedirect)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	val := RandStringRunes(32)
	expire := time.Now().Add(5 * time.Minute)
	cookie := http.Cookie{
		Name:    "googleoauth",
		Value:   val,
		Expires: expire,
	}
	http.SetCookie(w, &cookie)
	u := oauth2Config.AuthCodeURL(val)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890$")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func staticFileHandler(filename string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filename)
	}
}
