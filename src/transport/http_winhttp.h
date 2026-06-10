/**
 * HTTP transport using WinHTTP.
 */

#ifndef ROOTHERALD_HTTP_WINHTTP_H
#define ROOTHERALD_HTTP_WINHTTP_H

#include <string>

namespace RootHerald {

struct HttpResponse {
    int statusCode = 0;
    std::string body;
};

HttpResponse HttpPost(const std::string& url, const std::string& jsonBody);
HttpResponse HttpPostForm(const std::string& url, const std::string& formBody);
HttpResponse HttpGet(const std::string& url);

/**
 * INTERNAL — not part of the public ABI in common/rootherald.h.
 *
 * Set the tenant's publishable key to attach as the
 * `X-RootHerald-Site-Key` request header on subsequent JSON POSTs
 * (the enroll / activate / attest calls). Empty string clears it (no
 * header sent — the default, which is what legacy global-API consumers
 * get). Set by the public-ABI facade under its handle lock for the
 * duration of a call; process-global like the legacy link-token state.
 */
void SetSiteKeyForRequests(const std::string& siteKey);

} // namespace RootHerald

#endif /* ROOTHERALD_HTTP_WINHTTP_H */
