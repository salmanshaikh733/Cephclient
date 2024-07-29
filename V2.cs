using System;
using System.Globalization;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class S3Client
{
    private readonly HttpClient _httpClient;
    private readonly string _accessKey = "AKIAIOSFODNN7EXAMPLE";
    private readonly string _secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private readonly string _userAgent = "aws-sdk-dotnet-core/3.7.0"; // Replace with your SDK version

    public S3Client()
    {
        _httpClient = new HttpClient { BaseAddress = new Uri("http://192.168.2.20:80") };
    }

    public async Task<string> ListBucketsAsync()
    {
        var requestUri = "/";
        var request = new HttpRequestMessage(HttpMethod.Get, requestUri);

        // Set headers
        var dateTime = DateTime.UtcNow;
        var iso8601Date = dateTime.ToString("yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture);
        var dateStamp = dateTime.ToString("yyyyMMdd");
        var contentHash = "UNSIGNED-PAYLOAD"; // For GET requests, the payload is not signed
        var host = "192.168.2.20";
        var sdkInvocationId = Guid.NewGuid().ToString();
        var sdkRequest = Guid.NewGuid().ToString();

        // Clear existing headers if any
        request.Headers.Clear();
        request.Headers.Add("Host", host);
        request.Headers.Add("x-amz-date", iso8601Date);
        request.Headers.Add("x-amz-content-sha256", contentHash);
        request.Headers.Add("User-Agent", _userAgent);
        request.Headers.Add("x-amz-sdk-invocation-id", sdkInvocationId);
        request.Headers.Add("x-amz-sdk-request", sdkRequest);

        var authorizationHeader = GenerateAuthorizationHeader(HttpMethod.Get, requestUri, iso8601Date, dateStamp, contentHash, host);
        request.Headers.Add("Authorization", authorizationHeader);

        // Send the request
        var response = await _httpClient.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine("Error Response Content: " + errorContent);
            throw new Exception($"Request failed with status code {response.StatusCode}: {errorContent}");
        }

        return await response.Content.ReadAsStringAsync();
    }

    private string GenerateAuthorizationHeader(HttpMethod method, string requestUri, string iso8601Date, string dateStamp, string contentHash, string host)
    {
        var canonicalRequest = CreateCanonicalRequest(method, requestUri, iso8601Date, contentHash, host);
        var stringToSign = CreateStringToSign(iso8601Date, dateStamp, canonicalRequest);

        var signature = SignatureHelper.CalculateSignature(stringToSign, _secretKey, dateStamp);
        var authorizationHeader = $"AWS4-HMAC-SHA256 Credential={_accessKey}/{dateStamp}/s3/aws4_request, SignedHeaders=host;x-amz-date;x-amz-content-sha256, Signature={signature}";

        return authorizationHeader;
    }

    private string CreateCanonicalRequest(HttpMethod method, string requestUri, string iso8601Date, string contentHash, string host)
    {
        // Canonical request includes HTTP method, request URI, headers, and hashed payload
        var canonicalHeaders = $"host:{host}\nx-amz-date:{iso8601Date}\nx-amz-content-sha256:{contentHash}\n";
        var signedHeaders = "host;x-amz-date;x-amz-content-sha256";
        
        return $"{method}\n{requestUri}\n\n{canonicalHeaders}\n{signedHeaders}\n{contentHash}";
    }

    private string CreateStringToSign(string iso8601Date, string dateStamp, string canonicalRequest)
    {
        var credentialScope = $"{dateStamp}/s3/aws4_request";
        var hashedCanonicalRequest = ComputeSha256Hash(canonicalRequest);

        return $"AWS4-HMAC-SHA256\n{iso8601Date}\n{credentialScope}\n{hashedCanonicalRequest}";
    }

    private string ComputeSha256Hash(string input)
    {
        using (var sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }
}

public static class SignatureHelper
{
    public static string CalculateSignature(string stringToSign, string secretKey, string date)
    {
        var dateKey = HmacSha256("AWS4" + secretKey, date);
        var dateRegionServiceKey = HmacSha256(dateKey, "s3");
        var signingKey = HmacSha256(dateRegionServiceKey, "aws4_request");

        return HmacSha256(signingKey, stringToSign);
    }

    private static string HmacSha256(string key, string data)
    {
        using (var hmacsha256 = HMACSHA256.Create())
        {
            hmacsha256.Key = Encoding.UTF8.GetBytes(key);
            var hash = hmacsha256.ComputeHash(Encoding.UTF8.GetBytes(data));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }
}
