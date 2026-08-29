"""SAML 2.0 SP — AuthnRequest (redirect binding) + signed Response verification.

Signature verification is done with `signxml` (pure Python: lxml + cryptography),
so there is no libxmlsec system dependency.
"""

from __future__ import annotations

import base64
import secrets
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlencode

from lxml import etree
from signxml import XMLVerifier

from ..models import SsoConnection

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}
_EMAIL_ATTRS = {
    "email",
    "mail",
    "emailaddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
}
_NAME_ATTRS = {
    "name",
    "displayname",
    "cn",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "urn:oid:2.16.840.1.113730.3.1.241",
}


class SamlError(Exception):
    pass


@dataclass(frozen=True)
class SamlProfile:
    subject: str
    email: str | None
    name: str | None
    attributes: dict[str, list[str]] = field(default_factory=dict)


def sp_entity_id(base_url: str, connection_id: str) -> str:
    return f"{base_url.rstrip('/')}/v1/auth/sso/{connection_id}/metadata"


def acs_url(base_url: str, connection_id: str) -> str:
    return f"{base_url.rstrip('/')}/v1/auth/sso/{connection_id}/acs"


def _cert_pem(cert: str) -> str:
    cert = cert.strip()
    if cert.startswith("-----BEGIN"):
        return cert
    body = "\n".join(cert[i : i + 64] for i in range(0, len(cert), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def sp_metadata(conn: SsoConnection, base_url: str) -> str:
    eid = sp_entity_id(base_url, str(conn.id))
    acs = acs_url(base_url, str(conn.id))
    return (
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{eid}">'
        f'<SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        f"<AssertionConsumerService "
        f'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{acs}" index="0" isDefault="true"/>'
        f"</SPSSODescriptor></EntityDescriptor>"
    )


def build_redirect(conn: SsoConnection, *, base_url: str, relay_state: str) -> str:
    cfg = conn.config or {}
    sso_url = cfg.get("idp_sso_url")
    if not sso_url:
        raise SamlError("connection is missing idp_sso_url")
    req_id = "_" + secrets.token_hex(16)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    authn = (
        f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" '
        f'ID="{req_id}" Version="2.0" IssueInstant="{now}" '
        f'Destination="{sso_url}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'AssertionConsumerServiceURL="{acs_url(base_url, str(conn.id))}">'
        f"<saml:Issuer>{sp_entity_id(base_url, str(conn.id))}</saml:Issuer>"
        f"</samlp:AuthnRequest>"
    )
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = compressor.compress(authn.encode()) + compressor.flush()
    query = urlencode(
        {"SAMLRequest": base64.b64encode(deflated).decode(), "RelayState": relay_state}
    )
    sep = "&" if "?" in sso_url else "?"
    return f"{sso_url}{sep}{query}"


def parse_response(conn: SsoConnection, saml_response_b64: str, *, base_url: str) -> SamlProfile:
    cfg = conn.config or {}
    cert = cfg.get("idp_x509_cert")
    if not cert:
        raise SamlError("connection is missing idp_x509_cert")
    try:
        xml = base64.b64decode(saml_response_b64)
    except Exception as exc:
        raise SamlError("SAMLResponse is not valid base64") from exc

    try:
        result = XMLVerifier().verify(xml, x509_cert=_cert_pem(cert))
    except Exception as exc:
        raise SamlError(f"signature verification failed: {exc}") from exc

    signed = result.signed_xml
    if etree.QName(signed).localname == "Assertion":
        assertion = signed
    else:
        assertion = signed.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    if assertion is None:
        raise SamlError("no signed Assertion in response")

    now = datetime.now(UTC)
    conditions = assertion.find("{*}Conditions")
    if conditions is not None:
        not_after = conditions.get("NotOnOrAfter")
        not_before = conditions.get("NotBefore")
        if not_after and _parse_ts(not_after) <= now:
            raise SamlError("assertion has expired")
        if not_before and _parse_ts(not_before) > now:
            raise SamlError("assertion not yet valid")
        expected_aud = sp_entity_id(base_url, str(conn.id))
        auds = [a.text for a in conditions.findall(".//{*}Audience")]
        if auds and expected_aud not in auds:
            raise SamlError(f"audience mismatch: {auds}")

    nameid_el = assertion.find("{*}Subject/{*}NameID")
    if nameid_el is None or not (nameid_el.text or "").strip():
        raise SamlError("assertion has no Subject/NameID")
    nameid = nameid_el.text.strip()

    attrs: dict[str, list[str]] = {}
    for attr in assertion.findall(".//{*}AttributeStatement/{*}Attribute"):
        key = (attr.get("Name") or "").strip()
        values = [v.text.strip() for v in attr.findall("{*}AttributeValue") if v.text]
        if key:
            attrs[key] = values

    email = _pick(attrs, _EMAIL_ATTRS) or (nameid if "@" in nameid else None)
    return SamlProfile(
        subject=nameid,
        email=email.lower() if email else None,
        name=_pick(attrs, _NAME_ATTRS),
        attributes=attrs,
    )


def _pick(attrs: dict[str, list[str]], keys: set[str]) -> str | None:
    for k, vals in attrs.items():
        if k.lower() in keys and vals:
            return vals[0]
    return None


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
