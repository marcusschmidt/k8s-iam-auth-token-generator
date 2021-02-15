package k8s_iam_auth_token_generator

import (
	"encoding/base64"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"log"
)

type GeneratorConfig struct {
	Region          string `envconfig:"REGION"`
	AccessKeyId     string `envconfig:"ACCESS_KEY_ID"`
	SecretAccessKey string `envconfig:"SECRET_ACCESS_KEY"`
	RoleToAssume    string `envconfig:"ROLE_TO_ASSUME"`
	ClusterId       string `envconfig:"CLUSTER_ID"`
}

func GetToken(config *GeneratorConfig) string {
	stsClient := getSTSClient(config)

	presignedURLString := getPresignedRequest(config, stsClient)

	token := createToken(presignedURLString)

	return token
}

func createToken(presignedURLString string) string {
	return "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(presignedURLString))
}

func getPresignedRequest(config *GeneratorConfig, stsClient *sts.STS) string {
	request, _ := stsClient.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
	request.HTTPRequest.Header.Add("x-k8s-aws-id", config.ClusterId)

	// is valid for 15 minutes regardless of this parameters value after it has been
	// signed, but we set this unused parameter to 60 for legacy reasons
	presignedURLString, err := request.Presign(60)
	if err != nil {
		log.Fatal("Error presigning request")
	}

	return presignedURLString
}

func getSTSClient(config *GeneratorConfig) *sts.STS {
	userSession, err := session.NewSession(&aws.Config{
		Region: aws.String(config.Region),
		Credentials: credentials.NewStaticCredentials(
			config.AccessKeyId,
			config.SecretAccessKey,
			"",
		),
	})
	if err != nil {
		log.Fatal("Error creating user session")
	}

	creds := stscreds.NewCredentials(userSession, config.RoleToAssume)

	return sts.New(userSession, &aws.Config{Credentials: creds})
}
