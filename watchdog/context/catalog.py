from __future__ import annotations

from watchdog.context.identifiers import catalog_sha256
from watchdog.domain.context import (
    CatalogMetadata,
    ConfigurationRule,
    ContextRuleCatalog,
    EndpointRule,
    MemberRule,
    ObservationKind,
    PackageMappingRule,
)

# This catalog is code-native and is never populated from settings, advisory prose,
# or repository content. References document the public package contracts reviewed
# for the exact syntactic mapping; they are not fetched during analysis.
DEFAULT_CONTEXT_CATALOG = ContextRuleCatalog(
    version="1",
    package_mappings=(
        PackageMappingRule(
            id="pypi-beautifulsoup4-bs4",
            ecosystem="PyPI",
            package_name="beautifulsoup4",
            import_roots=("bs4",),
            review_reference="https://pypi.org/project/beautifulsoup4/",
        ),
        PackageMappingRule(
            id="pypi-pillow-pil",
            ecosystem="PyPI",
            package_name="pillow",
            import_roots=("PIL",),
            review_reference="https://pillow.readthedocs.io/en/stable/handbook/tutorial.html",
        ),
        PackageMappingRule(
            id="pypi-pyyaml-yaml",
            ecosystem="PyPI",
            package_name="pyyaml",
            import_roots=("yaml",),
            review_reference="https://pyyaml.org/wiki/PyYAMLDocumentation",
        ),
    ),
    member_rules=(
        MemberRule(
            id="pypi-pyyaml-load",
            ecosystem="PyPI",
            package_name="pyyaml",
            member_path=("load",),
            observation_kind=ObservationKind.EXPLICIT_CALL,
            review_reference="https://pyyaml.org/wiki/PyYAMLDocumentation",
        ),
    ),
    configuration_rules=(
        ConfigurationRule(
            id="npm-jsonwebtoken-algorithms",
            ecosystem="npm",
            package_name="jsonwebtoken",
            keys=("algorithms",),
            review_reference="https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback",
        ),
        ConfigurationRule(
            id="pypi-requests-verify",
            ecosystem="PyPI",
            package_name="requests",
            keys=("verify",),
            review_reference="https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification",
        ),
    ),
    endpoint_rules=(
        EndpointRule(
            id="go-net-http-handlers",
            ecosystem="Go",
            package_name="net/http",
            import_root="net/http",
            member_paths=(("Handle",), ("HandleFunc",)),
            review_reference="https://pkg.go.dev/net/http#Handle",
        ),
        EndpointRule(
            id="npm-express-routes",
            ecosystem="npm",
            package_name="express",
            import_root="express",
            member_paths=(
                ("delete",),
                ("get",),
                ("patch",),
                ("post",),
                ("put",),
                ("use",),
            ),
            review_reference="https://expressjs.com/en/4x/api.html#app.METHOD",
        ),
        EndpointRule(
            id="pypi-flask-route",
            ecosystem="PyPI",
            package_name="flask",
            import_root="flask",
            member_paths=(("route",),),
            review_reference="https://flask.palletsprojects.com/en/stable/api/#flask.Flask.route",
        ),
    ),
)


def default_catalog() -> ContextRuleCatalog:
    return DEFAULT_CONTEXT_CATALOG


def catalog_metadata(catalog: ContextRuleCatalog = DEFAULT_CONTEXT_CATALOG) -> CatalogMetadata:
    return CatalogMetadata(version=catalog.version, sha256=catalog_sha256(catalog))
