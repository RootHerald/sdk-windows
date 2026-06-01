/**
 * HTTP transport using WinHTTP — Full implementation.
 */

#include "http_winhttp.h"

#include <windows.h>
#include <winhttp.h>

#include <sstream>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace RootHerald {

static HttpResponse DoRequest(const std::string& url, const std::string& verb,
                               const std::string& body,
                               const wchar_t* contentTypeHeader = L"Content-Type: application/json")
{
    HttpResponse response;

    // Convert URL to wide string
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wideUrl(wideLen);
    MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, wideUrl.data(), wideLen);

    // Crack the URL
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t hostName[256] = {};
    wchar_t urlPath[2048] = {};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = _countof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = _countof(urlPath);

    if (!WinHttpCrackUrl(wideUrl.data(), 0, 0, &urlComp)) {
        response.body = R"({"error":"Failed to parse URL"})";
        return response;
    }

    bool isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    // Open session
    HINTERNET hSession = WinHttpOpen(
        L"RootHerald/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        response.body = R"({"error":"WinHttpOpen failed"})";
        return response;
    }

    // Connect
    HINTERNET hConnect = WinHttpConnect(
        hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        response.body = R"({"error":"WinHttpConnect failed"})";
        return response;
    }

    // Convert verb to wide
    int verbWideLen = MultiByteToWideChar(CP_UTF8, 0, verb.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wideVerb(verbWideLen);
    MultiByteToWideChar(CP_UTF8, 0, verb.c_str(), -1, wideVerb.data(), verbWideLen);

    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, wideVerb.data(), urlPath,
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        response.body = R"({"error":"WinHttpOpenRequest failed"})";
        return response;
    }

    // Set Content-Type header
    WinHttpAddRequestHeaders(hRequest, contentTypeHeader, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    // Send
    BOOL result;
    if (!body.empty()) {
        result = WinHttpSendRequest(
            hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)body.c_str(), (DWORD)body.size(),
            (DWORD)body.size(), 0);
    } else {
        result = WinHttpSendRequest(
            hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    }

    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        response.body = R"({"error":"WinHttpSendRequest failed"})";
        return response;
    }

    // Receive response
    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        response.body = R"({"error":"WinHttpReceiveResponse failed"})";
        return response;
    }

    // Read status code
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
        WINHTTP_NO_HEADER_INDEX);
    response.statusCode = (int)statusCode;

    // Read body
    std::ostringstream bodyStream;
    DWORD bytesAvailable = 0;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<char> buf(bytesAvailable);
        DWORD bytesRead = 0;
        WinHttpReadData(hRequest, buf.data(), bytesAvailable, &bytesRead);
        bodyStream.write(buf.data(), bytesRead);
    }
    response.body = bodyStream.str();

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

HttpResponse HttpPost(const std::string& url, const std::string& jsonBody)
{
    return DoRequest(url, "POST", jsonBody);
}

HttpResponse HttpPostForm(const std::string& url, const std::string& formBody)
{
    return DoRequest(url, "POST", formBody, L"Content-Type: application/x-www-form-urlencoded");
}

HttpResponse HttpGet(const std::string& url)
{
    return DoRequest(url, "GET", "");
}

} // namespace RootHerald
