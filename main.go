package main

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/eric-pigeon/aws-mfa/pkg/mfaarn"
	"github.com/eric-pigeon/aws-mfa/pkg/ststokencredentials"
)

func main() {

	sess := session.Must(session.NewSession())

	nameMe := mfaarn.New(sess)
	arn, err := nameMe.Arn()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	credentialprovider := ststokencredentials.New(sess, arn, ststokencredentials.StdinTokenProvider)
	credentials, err := credentialprovider.Retrieve()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Print(arn)

	args := os.Args[1:]

	if len(args) == 0 {
    fmt.Printf("export AWS_SECRET_ACCESS_KEY='%s'", credentials.SecretAccessKey)
    fmt.Printf("export AWS_ACCESS_KEY_ID='%s'", credentials.AccessKeyID)
    fmt.Printf("export AWS_SESSION_TOKEN='%s'", credentials.SessionToken)
    fmt.Printf("export AWS_SECURITY_TOKEN='%s'", credentials.SessionToken)
	} else {
	}
}
