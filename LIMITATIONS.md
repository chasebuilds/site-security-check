# Limitations

What site-security-check does not do, or does imperfectly. Read this before trusting a grade.

## Scope

- It is a checkup of what the site shows to any visitor. It is not a penetration test or a full audit.
- It reads the homepage and at most a few same-site pages. Headers are judged on the homepage only. Other pages can be configured differently.
- Nothing behind a login is checked. Application bugs (injection, broken access control) are out of scope on purpose.
- A good grade does not mean the site is safe. A poor grade is a to-do list.

## Accuracy

- **Exposed files** use one `HEAD` request each and count only a 200 or 206 as reachable. A server that blocks `HEAD` but serves `GET` would be missed. A site that returns 200 for everything is reported as inconclusive.
- **CMS versions** are compared against a short hand-written table (WordPress 6.0, Joomla 4, Drupal 10 as the oldest accepted lines). The table ages and is not a vulnerability database. Many sites hide the generator tag, so "no tag" proves nothing.
- **CSP** grading is a simple read of the policy text. It flags the common weak patterns, it does not prove a policy blocks real attacks.
- **Cookies** are judged from `Set-Cookie` headers on the pages fetched. Cookies set later by JavaScript are not seen. Cookies that are not login cookies are held to the same rule.
- **Mixed content** is found by reading HTML tags. Resources added by JavaScript are not seen, and pages are not rendered in a browser.
- **SPF and DMARC** are read for the site host with a leading `www.` removed. There is no public-suffix list, so for hosts such as `shop.example.co.uk` pass `--email-domain`. Sites that send no email may not need either record. SPF `include:` chains are not followed or counted.
- **TLS** checks the certificate the server presents and its expiry. It does not test cipher suites, protocol downgrade, or the whole certificate chain beyond what Python's default trust store verifies.
- **HTTPS redirect** looks at port 80 only. If nothing answers there, it is reported as a note, not a failure.
- **robots.txt** is applied to the pages read. The short fixed list of exposed-file and security.txt requests does not consult it.

## Practical

- Sites behind a bot-protection layer may block the request or serve a challenge page. The report then describes the challenge, not the site.
- A site that redirects to a different host from the one you gave is analysed as the redirect response; use the final address instead.
- Scores and weights are my judgement, not an industry standard. They are in one file so you can change them.
- Tested only against local servers. Behaviour on unusual real-world servers has not been measured.
