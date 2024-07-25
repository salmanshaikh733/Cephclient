using System;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CephRadosGateway
{
    public class RadosGatewayClient
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseAddress;
        private readonly string _accessKey;
        private readonly string _secretKey;
        private readonly string _userToken;

        public RadosGatewayClient(string baseAddress, string accessKey, string secretKey, string userToken)
        {
            _baseAddress = baseAddress;
            _accessKey = accessKey;
            _secretKey = secretKey;
            _userToken = userToken;

            _httpClient = new HttpClient
            {
                BaseAddress = new Uri(_baseAddress)
            };
        }

        public async Task<string> GetBucketListAsync()
        {
            var requestUri = "/?format=json";
            var request = CreateRequest(HttpMethod.Get, requestUri);
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> GetObjectAsync(string bucketName, string objectName)
        {
            var requestUri = $"/{bucketName}/{objectName}";
            var request = CreateRequest(HttpMethod.Get, requestUri);
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> PutObjectAsync(string bucketName, string objectName, Stream contentStream, string contentType = "application/octet-stream")
        {
            var requestUri = $"/{bucketName}/{objectName}";
            var content = new StreamContent(contentStream);
            content.Headers.ContentType = new MediaTypeHeaderValue(contentType);

            var request = CreateRequest(HttpMethod.Put, requestUri, content);
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        public async Task DeleteObjectAsync(string bucketName, string objectName)
        {
            var requestUri = $"/{bucketName}/{objectName}";
            var request = CreateRequest(HttpMethod.Delete, requestUri);
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
        }

        public async Task CreateBucketAsync(string bucketName)
        {
            var requestUri = $"/{bucketName}";
            var request = CreateRequest(HttpMethod.Put, requestUri);
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
        }

        public async Task DeleteBucketAsync(string bucketName)
        {
            var requestUri = $"/{bucketName}";
            var request = CreateRequest(HttpMethod.Delete, requestUri);
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
        }

        private HttpRequestMessage CreateRequest(HttpMethod method, string requestUri, HttpContent content = null)
        {
            var request = new HttpRequestMessage(method, requestUri)
            {
                Content = content
            };

            var dateTime = DateTime.UtcNow;
            var iso8601Date = dateTime.ToString("yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture);
            var contentHash = GetContentHash(content);

            request.Headers.Add("x-amz-date", iso8601Date);
            request.Headers.Add("x-amz-content-sha256", contentHash);
            request.Headers.Add("x-amz-security-token", _userToken);
            request.Headers.Add("Authorization", GenerateAuthorizationHeader(method, requestUri, iso8601Date, contentHash));

            return request;
        }

        private string GenerateAuthorizationHeader(HttpMethod method, string requestUri, string iso8601Date, string contentHash)
        {
            var canonicalRequest = CreateCanonicalRequest(method, requestUri, iso8601Date, contentHash);
            var stringToSign = CreateStringToSign(iso8601Date, canonicalRequest);
            var signature = SignatureHelper.CalculateSignature(stringToSign, _secretKey, DateTime.UtcNow.ToString("yyyyMMdd"));

            return $"AWS4-HMAC-SHA256 Credential={_accessKey}/{DateTime.UtcNow.ToString("yyyyMMdd")}/s3/aws4_request, SignedHeaders=host;x-amz-date;x-amz-content-sha256;x-amz-security-token, Signature={signature}";
        }

        private string CreateCanonicalRequest(HttpMethod method, string requestUri, string iso8601Date, string contentHash)
        {
            var canonicalRequest = new StringBuilder()
                .AppendLine(method.Method)
                .AppendLine(requestUri)
                .AppendLine("")
                .AppendLine($"host:{new Uri(_baseAddress).Host.ToLower()}")
                .AppendLine($"x-amz-date:{iso8601Date}")
                .AppendLine($"x-amz-content-sha256:{contentHash}")
                .AppendLine($"x-amz-security-token:{_userToken}")
                .AppendLine("")
                .AppendLine("host;x-amz-date;x-amz-content-sha256;x-amz-security-token")
                .AppendLine(contentHash)
                .ToString();

            return canonicalRequest;
        }

        private string CreateStringToSign(string iso8601Date, string canonicalRequest)
        {
            var hashedCanonicalRequest = ComputeSha256Hash(canonicalRequest);
            var stringToSign = new StringBuilder()
                .AppendLine("AWS4-HMAC-SHA256")
                .AppendLine(iso8601Date)
                .AppendLine($"{DateTime.UtcNow.ToString("yyyyMMdd")}/s3/aws4_request")
                .AppendLine(hashedCanonicalRequest)
                .ToString();

            return stringToSign;
        }

        private static string ComputeSha256Hash(string data)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
                return BitConverter.ToString(bytes).Replace("-", "").ToLower();
            }
        }

        private static string GetContentHash(HttpContent content)
        {
            if (content == null)
                return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // Empty hash

            using (var sha256 = SHA256.Create())
            {
                using (var stream = content.ReadAsStreamAsync().Result)
                {
                    var hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLower();
                }
            }
        }
    }

    // Helper class for signature calculation
    internal static class SignatureHelper
    {
        public static string CalculateSignature(string stringToSign, string secretKey, string dateStamp)
        {
            var signingKey = GetSignatureKey(secretKey, dateStamp);
            return HmacSha256(signingKey, stringToSign);
        }

        private static byte[] GetSignatureKey(string key, string dateStamp)
        {
            var kDate = HmacSha256(Encoding.UTF8.GetBytes("AWS4" + key), dateStamp);
            var kService = HmacSha256(kDate, "s3");
            var kSigning = HmacSha256(kService, "aws4_request");
            return kSigning;
        }

        private static string HmacSha256(byte[] key, string data)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return BitConverter.ToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(data))).Replace("-", "").ToLower();
            }
        }
    }
}
