package txcsign

import (
	"testing"
	"fmt"
)

func Test_X(t *testing.T) {
	secretId := "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******"
	secretKey := "Gu5t9xGARNpq86cd98joQYCN3*******"

	signedHeaders := map[string]string{
		"Host": "cvm.tencentcloudapi.com",
		"Content-Type": "application/json; charset=utf-8",
	}

	headers := MakeTxCloudSignV30Headers(secretId, secretKey, "POST", "cvm", "DescribeInstances", "ap-guangzhou", "2017-03-12", "/", signedHeaders, []byte(`{"Limit": 1, "Filters": [{"Values": ["\u672a\u547d\u540d"], "Name": "instance-name"}]}`))

	fmt.Printf("headers: %v\n", headers)
}
