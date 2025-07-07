## Flagdoor

### Basic lookaround
At first, I tested for ssti as username was reflected, then tried for sqli in login, but nothing. The only option left was enumerating user ids and viewing the content. 

Rate Limit was implemented with a separate cookie, and not inside flask session token, so we could just skip sending the cookie to prevent being rate limited.

This seemed inteded to allow bypass of rate limit, so I fuzzed from 0 to 70k user IDs. Nothing. Found lots of other user accounts, but none with a valid flag.

Next, tried, -1 as user id. It gave internal server error. This got me wondering what the server was doing that caused the error. Cuz flask routes should support negative int, and even int(-1) wouldn't throw error. sql should also have no problem with -1. So I thought of fuzzing negative ids. Got -3 as a successful hit. Opened it up, and it had the flag.