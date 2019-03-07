package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/iterator"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	"cloud.google.com/go/storage"
)

var (
	kmsProjectID = flag.String("kms-project-id", "", "KMS project id")
	kmsRegion    = flag.String("kms-region", "global", "KMS region")
	kmsKeyRing   = flag.String("kms-keyring", "", "KMS KeyRing")
	kmsKey       = flag.String("kms-key", "", "KMS Key")

	gcsBucket = flag.String("gcs-bucket", "", "GCS Bucket to store or retrieve secret from")
	gcsPrefix = flag.String("gcs-prefix", "", "Prefix to use when creating or reading a secret")

	storageClient *storage.Client
	kmsClient     *cloudkms.KeyManagementClient

	validationError = "missing or empty required field %s"
)

func validateFlags() error {
	switch "" {
	case *kmsProjectID:
		return fmt.Errorf(validationError, "-kms-project-id")
	case *kmsRegion:
		return fmt.Errorf(validationError, "-kms-region")
	case *kmsKeyRing:
		return fmt.Errorf(validationError, "-kms-key-ring")
	case *kmsKey:
		return fmt.Errorf(validationError, "-kms-key")
	case *gcsBucket:
		return fmt.Errorf(validationError, "-gcs-bucket")
	case *gcsPrefix:
		return fmt.Errorf(validationError, "-gcs-prefix")
	}
	return nil
}
func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("requires at least 1 agrument")
	}

	cmd := args[0]
	switch cmd {
	case "get", "create", "list":
		// Expected commands
	default:
		log.Fatalf("unexpected command %s", cmd)
	}

	if err := validateFlags(); err != nil {
		log.Fatal(err)
	}

	if err := initialiseClients(); err != nil {
		log.Fatal(err)
	}

	// TODO: Add timeout
	ctx := context.Background()
	switch cmd {
	case "get":
		if len(args) != 2 {
			log.Fatal("get requires <key>=<secret>")
		}
		if err := getAndDecrypt(ctx, args[1]); err != nil {
			log.Fatal(err)
		}
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
		if err := listSecrets(ctx); err != nil {
			log.Fatal(err)
		}
	}
}

func initialiseClients() error {
	// TODO: Add timeout
	ctx := context.Background()

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

func getAndDecrypt(ctx context.Context, key string) error {
	secret, err := getSecret(ctx, key)
	if err != nil {
		return fmt.Errorf("unable to get secret: %v", err)
	}
	m, err := decrypt(ctx, secret)
	if err != nil {
		return fmt.Errorf("unable to decrypt secret: %v", err)
	}
	fmt.Printf("Decrypted secret is: %s\n", m)
	return nil
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

func listSecrets(ctx context.Context) error {
	it := storageClient.Bucket(*gcsBucket).Objects(ctx, &storage.Query{
		Prefix: *gcsPrefix,
	})
	found := 0
	for {
		objAttrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		if val, _ := objAttrs.Metadata["gcs-secrets"]; val != "true" {
			continue
		}
		fmt.Printf("%s (%s)\n", objAttrs.Name, objAttrs.Updated)
		found += 1
	}
	if found == 0 {
		fmt.Println("No keys found")
	}
	return nil
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
