#include "http_winhttp.h"

#include <windows.h>
#include <winhttp.h>
#include <sal.h>

#include <sstream>
#include <vector>

#include "unique_handle.h"

#pragma comment(lib, "winhttp.lib")

namespace RootHerald {

namespace {

/* statusCode stays 0 on every pre-response failure; the body then carries a
 * short JSON diagnostic rather than server content. */
HttpResponse DoRequest(const std::string& url, const std::string& verb,
                       const std::string& body,
                       _In_z_ const wchar_t* contentTypeHeader)
{
    HttpResponse response;

    int wideLen = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wideUrl(wideLen);
    MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, wideUrl.data(), wideLen);

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

    UniqueInternet session(WinHttpOpen(
        L"RootHerald/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) {
        response.body = R"({"error":"WinHttpOpen failed"})";
        return response;
    }

    UniqueInternet connection(WinHttpConnect(session.Get(), hostName, urlComp.nPort, 0));
    if (!connection) {
        response.body = R"({"error":"WinHttpConnect failed"})";
        return response;
    }

    int verbWideLen = MultiByteToWideChar(CP_UTF8, 0, verb.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wideVerb(verbWideLen);
    MultiByteToWideChar(CP_UTF8, 0, verb.c_str(), -1, wideVerb.data(), verbWideLen);

    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    UniqueInternet request(WinHttpOpenRequest(
        connection.Get(), wideVerb.data(), urlPath,
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
    if (!request) {
        response.body = R"({"error":"WinHttpOpenRequest failed"})";
        return response;
    }

    WinHttpAddRequestHeaders(request.Get(), contentTypeHeader, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL sent;
    if (!body.empty()) {
        sent = WinHttpSendRequest(
            request.Get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (PVOID)body.c_str(), (DWORD)body.size(),
            (DWORD)body.size(), 0);
    } else {
        sent = WinHttpSendRequest(
            request.Get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    }

    if (!sent) {
        response.body = R"({"error":"WinHttpSendRequest failed"})";
        return response;
    }

    if (!WinHttpReceiveResponse(request.Get(), nullptr)) {
        response.body = R"({"error":"WinHttpReceiveResponse failed"})";
        return response;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(request.Get(),
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
        WINHTTP_NO_HEADER_INDEX);
    response.statusCode = (int)statusCode;

    std::ostringstream bodyStream;
    DWORD bytesAvailable = 0;
    while (WinHttpQueryDataAvailable(request.Get(), &bytesAvailable) && bytesAvailable > 0) {
        std::vector<char> buf(bytesAvailable);
        DWORD bytesRead = 0;
        WinHttpReadData(request.Get(), buf.data(), bytesAvailable, &bytesRead);
        bodyStream.write(buf.data(), bytesRead);
    }
    response.body = bodyStream.str();

    return response;
}

} // namespace

HttpResponse HttpGet(const std::string& url)
{
    return DoRequest(url, "GET", "", L"Content-Type: application/json");
}

} // namespace RootHerald
