// 腾讯云签名
// 参考文档: https://cloud.tencent.com/document/api/400/41661

package txcsign

import (
	"crypto/sha256"
	"crypto/hmac"
	"hash"
	"strings"
	"time"
	"io"
	"fmt"
	"sort"
	"net/url"
)

const (
	tc3_request = "tc3_request"
	sign_algo   = "TC3-HMAC-SHA256"
	newLine     = "\n"
	date_layout = "2006-01-02"
)

func MakeTxCloudSignV30Headers(secretId, secretKey, httpMethod, service, action, region, version string, URI string, signedHeaders map[string]string, body []byte) (headers map[string]string) {
	signature, timestamp, utc0Date, sortedKeys := TxCloudSignV30(secretId, secretKey, httpMethod, service, action, region, URI, signedHeaders, body)
	headers = map[string]string{
		"Authorization": fmt.Sprintf("%s Credential=%s/%s/%s/%s,SignedHeaders=%s,Signature=%s",
			sign_algo,
			secretId, utc0Date, service, tc3_request,
			sortedKeys,
			signature,
		),
		"X-TC-Version": version,
		"X-TC-Timestamp": timestamp,
	}
	if len(region) > 0 {
		headers["X-TC-Region"] = region
	}

	for k, v := range signedHeaders {
		headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return
}

func TxCloudSignV30(secretId, secretKey, httpMethod, service, action, region string, URI string, signedHeaders map[string]string, body []byte) (signature string, timestamp, utc0Date, sortedKeys string) {
	httpMethod = strings.ToUpper(httpMethod)
	signedHeaders["X-TC-Action"] = action

	var canonicalHeaders string
	sortedKeys, canonicalHeaders = makeCanonicalHeaders(signedHeaders)

	now := time.Now().UTC()
	timestamp = fmt.Sprintf("%d", now.Unix())
	// timestamp = "1551113065"
	utc0Date = now.Format(date_layout)
	// utc0Date = "2019-02-25"

	signature = makeChainedHash(
		// HMAC_SHA256(SecretSigning, StringToSign): SecretSigning为派生密钥
		hmac.New(sha256.New,
			// 计算派生签名密钥: 
			//    SecretDate = HMAC_SHA256("TC3" + SecretKey, Date)
			//    SecretService = HMAC_SHA256(SecretDate, Service)
			//    SecretSigning = HMAC_SHA256(SecretService, "tc3_request")
			makeChainedHmacSha256Key([]byte(fmt.Sprintf("TC3%s", secretKey)), utc0Date, service, tc3_request),
		),
		// 合成 StringToSign = Algorithm + \n + RequestTimestamp + \n + CredentialScope + \n + HashedCanonicalRequest
		//      实际实现无需字符串拼接
		makeChainedData(
			sign_algo, // Algorithm: 签名算法，目前固定为 TC3-HMAC-SHA256
			timestamp, // RequestTimestamp: 请求头部的公共参数 X-TC-Timestamp 取值，取当前时间 UNIX 时间戳，精确到秒
			fmt.Sprintf("%s/%s/%s", utc0Date, service, tc3_request), // CredentialScope: Date/service/tc3_request，包含日期、所请求的服务和终止字符串（tc3_request）。
			                                                         // Date 为 UTC 标准时间的日期，取值需要和公共参数 X-TC-Timestamp 换算的 UTC 标准时间日期一致；
			                                                         // service 为产品名，必须与调用的产品域名一致
			// HashedCanonicalRequest: 前述步骤拼接所得规范请求串的哈希值，计算伪代码为 Lowercase(HexEncode(Hash.SHA256(CanonicalRequest)))
			makeChainedHash(
				sha256.New(),
				// 合成: CanonicalRequest = HTTPRequestMethod + '\n' + CanonicalURI + '\n' + CanonicalQueryString + '\n' + CanonicalHeaders + '\n' + SignedHeaders + '\n' + HashedRequestPayload
				//       实际计算无需拼接
				makeChainedData(
					httpMethod,   // HTTPRequestMethod
					"/",          // CanonicalURI: URI 参数，API 3.0 固定为正斜杠（/）
					func()string{ // CanonicalQueryString
						if httpMethod == "POST" {
							return "" // 对于 POST 请求，固定为空字符串""
						}
						// 对于 GET 请求，则为 URL 中问号（?）后面的字符串内容URLEncode，字符集 UTF-8
						if pos := strings.IndexByte(URI, '?'); pos >= 0 {
							return url.QueryEscape(URI[pos+1:])
						}
						return ""
					}(),
					canonicalHeaders,  // CanonicalHeaders
					sortedKeys,        // SignedHeaders
					func() string {    // HashedRequestPayload: Lowercase(HexEncode(Hash.SHA256(RequestPayload)))
						h := sha256.New()
						if len(body) > 0 {
							h.Write(body)
						}
						return fmt.Sprintf("%x", h.Sum(nil))
					}(),
				),
			),
		),
	)
	return
}

func makeChainedData(s ...string) (it <-chan string) {
	dataChain := make(chan string)
	go func() {
		first := true
		for _, ss := range s {
			if first { first = false } else { dataChain <- newLine }
			dataChain <- ss
		}
		close(dataChain)
	}()
	return dataChain
}

func makeChainedHash(h hash.Hash, in <-chan string) string {
	for s := range in {
		io.WriteString(h, s)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func makeChainedHmacSha256Key(key []byte, s ...string) (resKey []byte) {
	resKey = key
	for _, ss := range s {
		h := hmac.New(sha256.New, resKey)
		io.WriteString(h, ss)
		resKey = h.Sum(nil)
	}
	return
}

func makeCanonicalHeaders(signedHeaders map[string]string) (sortedKeys string, canonicalHeaders string) {
	//  头部 key 和 value 统一转成小写，并去掉首尾空格，按照 key:value\n 格式拼接；
	//  多个头部，按照头部 key（小写）的 ASCII 升序进行拼接。
	keys := make([]string, len(signedHeaders))
	headers := make(map[string]string)

	i := 0
	for key, val := range signedHeaders {
		lk := strings.ToLower(strings.TrimSpace(key))
		lv := strings.ToLower(strings.TrimSpace(val))
		keys[i] = lk
		headers[lk] = lv
		i += 1
	}
	sort.Strings(keys)
	res := make([]string, len(keys))
	for i, key := range keys {
		res[i] = fmt.Sprintf("%s:%v\n", key, headers[key])
	}
	canonicalHeaders = strings.Join(res, "")

	// 头部 key 统一转成小写；
	// 多个头部 key（小写）按照 ASCII 升序进行拼接，并且以分号（;）分隔。
	sortedKeys = strings.Join(keys, ";")
	return
}
