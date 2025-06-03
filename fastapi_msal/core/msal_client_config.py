from __future__ import annotations

from enum import Enum
from typing import ClassVar

from pydantic_settings import BaseSettings

from .utils import OptStr


class MSALPolicies(str, Enum):
    """
    This Enum is a representation of the different types of **Athuroties**.
    https://learn.microsoft.com/en-us/entra/identity-platform/msal-client-application-configuration#authority

    Name will need to be change in the future to reflect the correct purpose of the Enum
    """

    # Sign in users of a specific organization only.
    AAD_SINGLE = "AAD_SINGLE"
    # Sign in users with work and school accounts or personal Microsoft accounts.
    AAD_MULTI = "AAD_MULTI"

    # Sign in users of a specific organization only, with B2C policies.
    EXTERNAL_ID = "EXTERNAL_ID"
    # B2C or EXTERNAL ID?
    # https://learn.microsoft.com/en-us/answers/questions/1556632/confusion-around-azure-ad-b2c-vs-microsoft-entra-e

    # The below are predefined B2C policies,
    # if you are using a custom policy, set the b2c_policy in the config
    B2C_LOGIN = "B2C_1_LOGIN"
    B2C_PROFILE = "B2C_1_PROFILE"
    B2C_CUSTOM = "B2C_1A_LOGIN"


class MSALClientConfig(BaseSettings):
    # The following params must be set according to the app registration data recieved from AAD
    # https://docs.microsoft.com/azure/active-directory/develop/quickstart-v2-register-an-app
    client_id: OptStr = None
    client_credential: OptStr = None
    tenant: OptStr = None

    # Optional to set, default is single AAD (B2B)
    policy: MSALPolicies = MSALPolicies.AAD_SINGLE

    # EXTERNAL_ID policy specific params
    external_id_response_type: list[str] = ["id_token", "token"]
    external_id_prompt: OptStr = "login"

    # added to resolve issue with B2C custom policies [issue #32]
    b2c_policy: OptStr = None

    # Optional to set - If you are unsure don't set - it will be filled by MSAL as required
    scopes: ClassVar[list[str]] = []
    # Not in use - for future support
    session_type: str = "filesystem"

    # Set the following params if you wish to change the default MSAL Router endpoints
    path_prefix: str = ""
    login_path: str = "/_login_route"
    token_path: str = "/token"  # noqa: S105
    logout_path: str = "/_logout_route"
    show_in_docs: bool = False

    # Optional uri for redirect (token path) in cases where the app is behind a reverse proxy (PR #35)
    redirect_uri: OptStr = None

    # Optional Params for Logging and Telemetry with AAD
    app_name: OptStr = None
    app_version: OptStr = None

    @property
    def authority(self) -> str:
        if not self.policy:
            msg = "Policy must be specificly set before use"
            raise ValueError(msg)

        # set authority for single tenant authority
        if MSALPolicies.AAD_SINGLE == self.policy:
            authority_url = f"https://login.microsoftonline.com/{self.tenant}"
            return authority_url

        if MSALPolicies.AAD_MULTI == self.policy:
            authority_url = "https://login.microsoftonline.com/common/"
            return authority_url
        
        if MSALPolicies.EXTERNAL_ID == self.policy:
            if not self.external_user_flow_endpoint:
                msg = "External user flow endpoint must be set for EXTERNAL_ID policy"
                raise ValueError(msg)
            scopes = "%20".join(self.scopes) if self.scopes else "openid"
            response_type = "%20".join(self.external_id_response_type)
            authority_url = f"https://{self.tenant}.ciamlogin.com/{self.tenant}.onmicrosoft.com/oauth2/v2.0/authorize?client_id={self.client_id}&response_type={response_type}&scope={scopes}&prompt={self.external_id_prompt}"
            return authority_url

        # Assume B2C policy, specific policy need to be set by user (predefined added B2C_LOGIN, B2C_PROFILE, B2C_CUSTOM)
        policy = self.b2c_policy or self.policy.value
        authority_url = f"https://{self.tenant}.b2clogin.com/{self.tenant}.onmicrosoft.com/{policy}"

        return authority_url

    @property
    def login_full_path(self) -> str:
        return f"{self.path_prefix}{self.login_path}"
