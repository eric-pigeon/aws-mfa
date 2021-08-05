package ststokencredentials

import (
	"encoding/json"
	"fmt"
	"time"

	"errors"
	"io/fs"
	"testing"

	"github.com/spf13/afero"
	
	"github.com/google/go-cmp/cmp"

	"github.com/aws/aws-sdk-go/aws"

	// "github.com/aws/aws-sdk-go/aws/awserr"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

type mockedStsApi struct {
	stsiface.STSAPI
	getSessionTokenResp struct {
		err error
		resp sts.GetSessionTokenOutput
	}
}

func (m mockedStsApi) GetSessionToken(in *sts.GetSessionTokenInput) (*sts.GetSessionTokenOutput, error) {
	// Only need to return mocked response output
	resp := m.getSessionTokenResp
	return &resp.resp, resp.err
}

func TestRetrieveCredentialsFromfile(t *testing.T) {
	appFs := afero.NewMemMapFs()
	appIo := afero.Afero{Fs: appFs}

	provider := &StsTokenCredentials{
		fs: appFs,
		io: appIo,
	}

	_, err := provider.retrieveCredentialsFromFile()
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("expected retrieveCredentialsFromFile to return error fs.ErrNotExist")
	}

	// TODO: afero doesn't support file permissions with MemMapFs
	// err = appIo.WriteFile(credentials_file_name, []byte(""), 0000)
	// if err != nil {
	// 	t.Fatalf("failed to write file: %s", err)
	// }

	// _, err = provider.retrieveCredentialsFromFile()
	// if err == nil || !errors.Is(err, fs.ErrPermission) {
	// 	t.Fatal("expected retrieveCredentialsFromFile to return error fs.ErrPermission")
	// }

	expiry := time.Now().Add(60 * time.Minute)
	credentials := &sts.Credentials{
		AccessKeyId: aws.String("00000000000000000000"),
		Expiration: &expiry,
		SecretAccessKey: aws.String("0000000000000000000000000000000000000000"),
		SessionToken: aws.String("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
	}
	file, err := json.MarshalIndent(credentials, "", " ")
	if err != nil {
		t.Fatalf("failed to marshal json: %s", err)
	}
	err = appIo.WriteFile(credentials_file_name, []byte(file), 0600)
	if err != nil {
		t.Fatalf("afero failed to write file: %s", err)
	}

	fileCreds, err := provider.retrieveCredentialsFromFile()
	if !cmp.Equal(fileCreds, credentials) {
		t.Errorf("expected %+v, actual %+v", credentials, fileCreds)
	}
}

func TestRetrieveCredentialsFromAws(t *testing.T) {
	client := mockedStsApi{}
	provider := &StsTokenCredentials{
		client: client,
		serialNumber: aws.String("arn:aws:iam::000000000000:mfa/fakeuser"),
		tokenCode: aws.String("000000"),
	}

	credentials, err := provider.retriveCredentialsFromAws()
	if err != nil {
		t.Fatalf("retrieveCredentialsFromAws return err: %s", err)
	}
	expiry := time.Now().Add(60 * time.Minute)
	client.getSessionTokenResp.resp = sts.GetSessionTokenOutput{
		Credentials: &sts.Credentials{
			AccessKeyId: aws.String("00000000000000000000"),
			Expiration: &expiry,
			SecretAccessKey: aws.String("0000000000000000000000000000000000000000"),
			SessionToken: aws.String("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		},
	}
	// TODO: finish test
	fmt.Print(credentials)
	// ststokencredentials_test.go:55: retrieveCredentialsFromAws return err: AccessDenied: MultiFactorAuthentication failed, unable to validate MFA code.  Please verify your MFA serial number is valid and associated with this user.
	// ststokencredentials_test.go:55: retrieveCredentialsFromAws return err: AccessDenied: MultiFactorAuthentication failed with invalid MFA one time pass code.
	// {
  // if aerr, ok := err.(awserr.Error); ok {
	// 	fmt.Printf("%+v", aerr)
	// }
}
