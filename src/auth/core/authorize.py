from yarl import URL

import auth.data as data
from auth.core.error import AuthError
from auth.core.validate import auth_request_validate
from auth.core.response import Redirect
from auth.data.error import NoDataError
from auth.define import Define
from store.store import Store


async def oauth_start(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    nonce: str,
    define: Define,
    store: Store,
) -> Redirect:
    """This request 'prepares' the authorization request. The client provides the initially required information and
    in this case the endpoint redirects the user-agent to the credentials_url, which will handle the authentication.
    This means that this particular endpoint is not directly in the OAuth 2.1 spec, it is a choice for how to
    authenticate. We already validate the redirect_uri and whether there is a code challenge.

    Any unspecific error in this method should be caught and lead to a server_error redirect.
    """

    auth_request = auth_request_validate(
        define,
        response_type,
        client_id,
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
        nonce,
    )

    # The retrieval query is any information necessary to get all parameters necessary for the actual request
    retrieval_query = await data.requests.store_auth_request(store, auth_request)

    url = URL(define.credentials_url)
    persist_key = define.persist_key

    redirect = str(url.update_query({persist_key: retrieval_query}))

    return Redirect(code=303, url=redirect)


async def oauth_callback(retrieval_query: str, code: str, store: Store):
    try:
        auth_request = await data.requests.get_auth_request(store, retrieval_query)
    except NoDataError:
        raise AuthError(
            "invalid_request",
            "Expired or missing auth request",
            "missing_oauth_flow_id",
        )

    params = {"code": code, "state": auth_request.state}
    redirect = str(URL(auth_request.redirect_uri).update_query(params))

    return Redirect(code=303, url=redirect)
