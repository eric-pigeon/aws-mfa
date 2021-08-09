package mfaarn;

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/spf13/afero"

	homedir "github.com/mitchellh/go-homedir"

	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

const (
	aws_dir = ".aws"
	arn_file_name = "mfa_device"
	env_key = "AWS_MFA_ARN"
)

type MFAArn struct {
	fs afero.Fs
	io afero.Afero
	client iamiface.IAMAPI

	awsConfigDir string

}

func New(p client.ConfigProvider) *MFAArn {
	fs := afero.NewOsFs()
	hDir, _ := homedir.Dir()
	configDir := filepath.Join(hDir, ".aws")
	return &MFAArn{
		fs: fs,
		io: afero.Afero{Fs: fs},
		awsConfigDir: configDir,
		client: iam.New(p),
	}
}

func (m *MFAArn) Arn() (*string, error) {
	envArn, ok := os.LookupEnv(env_key)
	if ok {
		return &envArn, nil
	}

	arn, err := m.arnFromFile()
	if err == nil {
		return arn, nil
	} else {
		// TODO: debug log if error
	}

	if arn != nil {
		return arn, nil
	}

	arn, err = m.arnFromAws()
	if err != nil {
		return nil, err
	}

	return arn, nil
}

func (m *MFAArn) arnFromFile() (*string, error) {
	deviceFilePath := filepath.Join(m.awsConfigDir, arn_file_name)

	fileBytes, err := m.io.ReadFile(deviceFilePath)
	if err != nil {
		return nil, err
	}

	arn := string(fileBytes)
	return &arn, nil
}

func (m *MFAArn) arnFromAws() (*string, error) {
	listMfaInput := &iam.ListMFADevicesInput{}
	mfaOutput, err := m.client.ListMFADevices(listMfaInput)
	if err != nil {
		return nil, err
	}

	devices := mfaOutput.MFADevices
	if len(devices) == 0 {
		return nil, errors.New("No MFA devices were found for your account")
	}
	arn := devices[0].SerialNumber

	return arn, nil
}
