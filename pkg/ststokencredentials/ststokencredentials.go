package ststokencredentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/afero"

	homedir "github.com/mitchellh/go-homedir"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

const (
	aws_dir = ".aws"
	arn_file_name = "mfa_device"
	credentials_file_name = "mfa_credentials"
	ProviderName = "SessionTokenProvider"
)

func StdinTokenProvider() (string, error) {
	var v string
	fmt.Fprintf(os.Stderr, "MFA token code: ")
	_, err := fmt.Scanln(&v)

	return v, err
}

type StsTokenCredentials struct {
	credentials.Expiry

	fs afero.Fs
	io afero.Afero
	client stsiface.STSAPI

	awsConfigDir string

	// Expiry duration of the STS credentials. Defaults to 15 minutes if not set.
	duration time.Duration

	serialNumber *string
	tokenCode *string
	tokenProvider func() (string, error)

	// ExpiryWindow will allow the credentials to trigger refreshing prior to
	// the credentials actually expiring. This is beneficial so race conditions
	// with expiring credentials do not cause request to fail unexpectedly
	// due to ExpiredTokenException exceptions.
	//
	// So a ExpiryWindow of 10s would cause calls to IsExpired() to return true
	// 10 seconds before the credentials are actually expired.
	//
	// If ExpiryWindow is 0 or less it will be ignored.
	expiryWindow time.Duration
}

func New(p client.ConfigProvider, serialNumber string, tokenProvider func() (string, error)) *StsTokenCredentials {
	fs := afero.NewOsFs()
	hDir, _ := homedir.Dir()
	configDir := filepath.Join(hDir, ".aws")
	return &StsTokenCredentials{
		fs: fs,
		io: afero.Afero{Fs: fs},
		client: sts.New(p),
		awsConfigDir: configDir,
		duration: time.Duration(60) * time.Minute,
		serialNumber: aws.String(serialNumber),
		tokenProvider: tokenProvider,
	}
}

func (s *StsTokenCredentials) Retrieve() (credentials.Value, error) {
	creds, err := s.retrieveCredentialsFromFile()
	// set exipration if there were credentials in file
	if err == nil {
		s.SetExpiration(*creds.Expiration, s.expiryWindow)
	} else {
		// TODO: debug log if error
	}

	if err == nil && !s.IsExpired() {
		return credentials.Value{
			AccessKeyID:     *creds.AccessKeyId,
			SecretAccessKey: *creds.SecretAccessKey,
			SessionToken:    *creds.SessionToken,
			ProviderName:    ProviderName,
		}, nil
	}

	creds, err = s.retriveCredentialsFromAws()
	if err != nil {
		return credentials.Value{ProviderName: ProviderName}, err
	}
	s.SetExpiration(*creds.Expiration, s.expiryWindow)
	err = s.writeCredentialsTofile(creds)
	if err != nil {
		// TODO debug log
	}

	return credentials.Value{
		AccessKeyID:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
		ProviderName:    ProviderName,
	}, nil
}

func (s *StsTokenCredentials) retrieveCredentialsFromFile() (*sts.Credentials, error) {
	credentialsFilePath := filepath.Join(s.awsConfigDir, credentials_file_name)

	fileBytes, err := s.io.ReadFile(credentialsFilePath)
	if err != nil {
		return nil, err
	}

	var creds sts.Credentials
	err = json.Unmarshal(fileBytes, &creds)
	if err != nil {
		return nil, err
	}

	return &creds, nil
}

func (s *StsTokenCredentials) retriveCredentialsFromAws() (*sts.Credentials, error) {
	getTokenInput := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(s.duration / time.Second)),
	}

	if s.serialNumber != nil {
		if s.tokenCode != nil {
			getTokenInput.SerialNumber = s.serialNumber
			getTokenInput.TokenCode = s.tokenCode
		} else if s.tokenProvider != nil {
			getTokenInput.SerialNumber = s.serialNumber
			code, err := s.tokenProvider()
			if err != nil {
				return nil, err
			}
			getTokenInput.TokenCode = aws.String(code)
		} else {
			return nil, errors.New("get session token with MFA enabled, but neither tokenCode nor tokenProvider are set")
		}
	}

	getTokenOutput, err := s.client.GetSessionToken(getTokenInput)
	if err != nil {
		return nil, err
	}

	return getTokenOutput.Credentials, nil
}

func (s *StsTokenCredentials) writeCredentialsTofile(credentials *sts.Credentials) error {
	bytes, err := json.MarshalIndent(credentials, "", " ")
	if err != nil {
		return err
	}
	credentialsFilePath := filepath.Join(s.awsConfigDir, credentials_file_name)
	err = s.io.WriteFile(credentialsFilePath, bytes, 0600)
	if err != nil {
		return err
	}
	return nil
}
