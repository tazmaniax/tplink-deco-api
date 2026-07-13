"""Composite FastAPI and FastMCP application over one Deco service instance."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated, Literal, cast

from fastapi import (
    APIRouter,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    Security,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.exceptions import HTTPException as StarletteHttpException

from ..capability_routing import get_capability_route
from ..exceptions import (
    ApiError,
    ConfirmationError,
    ControllerChangedError,
    DecoError,
    ExpiredPlanError,
    IdempotencyConflictError,
    IdempotencyInProgressError,
    MutationIneligibleError,
    TransportError,
    UnknownPlanError,
)
from ..mcp.server import create_server
from ..responses import (
    CapabilitiesResponse,
    CapabilityResponse,
    ClientsResponse,
    CloudResponse,
    ConfigurationResponse,
    LogTypesResponse,
    MeshResponse,
    MutationExecutionResponse,
    MutationPlanCreatedResponse,
    MutationPlanStatusResponse,
    MutationPreflightResponse,
    MutationResponse,
    MutationsResponse,
    NetworkStatusResponse,
    ServiceStatusResponse,
    SystemLogPageResponse,
    TrafficResponse,
    WlanResponse,
)
from ..server import ServerConfig, StaticBearerAuthenticator
from ..service import DecoService
from ._in_memory_idempotency_store import _InMemoryIdempotencyStore
from .http_transport_security_middleware import HttpTransportSecurityMiddleware
from .mutation_execution_request import (  # noqa: TC001 - FastAPI resolves this annotation.
    MutationExecutionRequest,
)
from .mutation_request import MutationRequest  # noqa: TC001 - FastAPI resolves this annotation.
from .problem_detail import ProblemDetail
from .request_capacity_middleware import RequestCapacityMiddleware
from .request_id_middleware import RequestIdMiddleware
from .rest_cache_control_middleware import RestCacheControlMiddleware

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from .._json import JsonValue

_bearer_scheme = HTTPBearer(auto_error=False, scheme_name="BearerAuth")
_ERROR_RESPONSES: dict[type[Exception], tuple[int, str, str]] = {
    UnknownPlanError: (404, "unknown_plan", "Mutation plan not found"),
    ExpiredPlanError: (410, "plan_expired", "Mutation plan expired"),
    ConfirmationError: (403, "request_forbidden", "Request forbidden"),
    ControllerChangedError: (409, "controller_changed", "Controller identity changed"),
    IdempotencyConflictError: (409, "idempotency_conflict", "Idempotency key conflict"),
    IdempotencyInProgressError: (
        409,
        "idempotency_in_progress",
        "Idempotent request is in progress",
    ),
    MutationIneligibleError: (
        409,
        "mutation_ineligible",
        "Mutation is not execution-eligible",
    ),
    PermissionError: (403, "request_forbidden", "Request forbidden"),
    ValueError: (422, "invalid_request", "Request validation failed"),
    TimeoutError: (504, "router_timeout", "Router request timed out"),
    OSError: (503, "router_unavailable", "Router unavailable"),
    ApiError: (502, "router_error", "Router API failed"),
    TransportError: (502, "router_error", "Router API failed"),
    DecoError: (502, "router_error", "Router API failed"),
}


def create_http_application(config: ServerConfig | None = None) -> FastAPI:
    """Create one secured HTTP application exposing REST and Streamable HTTP MCP."""
    effective_config = config or ServerConfig.from_env()
    if effective_config.transport != "streamable-http":
        raise ValueError("Failed to configure server: DECO_MCP_TRANSPORT must be streamable-http")
    effective_config.validate_server()
    service = DecoService(effective_config)
    authenticator = StaticBearerAuthenticator(effective_config.bearer_token)
    idempotency_store = _InMemoryIdempotencyStore()
    mcp_server = create_server(
        effective_config,
        service,
        include_health_route=False,
        streamable_http_path="/",
    )
    mcp_application = mcp_server.streamable_http_app()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            async with mcp_application.router.lifespan_context(mcp_application):
                yield
        finally:
            service.close()

    application = FastAPI(
        title="TP-Link Deco API",
        version="1.0.0",
        description=(
            "Protocol-neutral access to a TP-Link Deco mesh. Real state-changing semantic "
            "mutations are not currently execution-eligible."
        ),
        openapi_version="3.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.deco_service = service
    application.state.bearer_authenticator = authenticator
    application.add_middleware(
        RestCacheControlMiddleware,
        protected_prefixes=(
            effective_config.rest_prefix,
            "/openapi.json",
            "/docs",
            "/redoc",
        ),
    )
    application.add_middleware(
        RequestCapacityMiddleware,
        max_in_flight=effective_config.max_in_flight_requests,
        protected_prefixes=(effective_config.rest_prefix, effective_config.mcp_path),
    )
    application.add_middleware(
        HttpTransportSecurityMiddleware,
        allowed_hosts=effective_config.allowed_hosts,
        allowed_origins=effective_config.allowed_origins,
        protected_prefixes=(effective_config.rest_prefix, "/openapi.json", "/docs", "/redoc"),
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(effective_config.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
        expose_headers=["Location", "Retry-After", "X-Request-ID"],
    )
    application.add_middleware(RequestIdMiddleware)
    _register_exception_handlers(application)

    @application.get("/healthz", include_in_schema=False)
    def health() -> PlainTextResponse:
        """Return process liveness without contacting the router."""
        return PlainTextResponse("ok")

    @application.get("/readyz", include_in_schema=False)
    def readiness() -> PlainTextResponse:
        """Return whether the process can accept work without probing the router."""
        return PlainTextResponse("ready")

    if effective_config.rest_enabled:
        application.include_router(
            _create_rest_router(effective_config, service, idempotency_store)
        )

        @application.get("/openapi.json", include_in_schema=False)
        def openapi_schema(_: None = Security(_require_bearer)) -> JSONResponse:
            """Return the OpenAPI document to authenticated callers."""
            return JSONResponse(application.openapi())

        if effective_config.rest_expose_docs:

            @application.get("/docs", include_in_schema=False)
            def swagger_ui(_: None = Security(_require_bearer)) -> HTMLResponse:
                """Return authenticated Swagger UI documentation."""
                return get_swagger_ui_html(
                    openapi_url="/openapi.json",
                    title=f"{application.title} - Swagger UI",
                )

            @application.get("/redoc", include_in_schema=False)
            def redoc_ui(_: None = Security(_require_bearer)) -> HTMLResponse:
                """Return authenticated ReDoc documentation."""
                return get_redoc_html(
                    openapi_url="/openapi.json",
                    title=f"{application.title} - ReDoc",
                )

    application.mount(effective_config.mcp_path, mcp_application)
    return application


def _create_rest_router(
    config: ServerConfig,
    service: DecoService,
    idempotency_store: _InMemoryIdempotencyStore,
) -> APIRouter:
    router = APIRouter(
        prefix=config.rest_prefix,
        dependencies=[Security(_require_bearer)],
        responses={
            401: {"model": ProblemDetail, "description": "Bearer authentication failed"},
            403: {"model": ProblemDetail, "description": "A safety gate rejected the request"},
            404: {"model": ProblemDetail, "description": "The requested resource was not found"},
            409: {
                "model": ProblemDetail,
                "description": "The request conflicts with current state",
            },
            410: {"model": ProblemDetail, "description": "The mutation plan has expired"},
            422: {"model": ProblemDetail, "description": "The request contract is invalid"},
            429: {"model": ProblemDetail, "description": "Server request capacity is exhausted"},
            502: {"model": ProblemDetail, "description": "The router API failed"},
            503: {"model": ProblemDetail, "description": "The router is unavailable"},
            504: {"model": ProblemDetail, "description": "The router request timed out"},
        },
    )

    @router.get(
        "/service",
        response_model=ServiceStatusResponse,
        operation_id="getServiceStatus",
    )
    def service_status() -> dict[str, JsonValue]:
        """Return sanitized server configuration and connection state."""
        return service.public_status()

    @router.get(
        "/status",
        response_model=NetworkStatusResponse,
        operation_id="getNetworkStatus",
    )
    def network_status() -> dict[str, JsonValue]:
        """Return current normalized Deco network health."""
        return service.network_status_resource()

    @router.get(
        "/configuration",
        response_model=ConfigurationResponse,
        response_model_exclude_unset=True,
        operation_id="getConfiguration",
    )
    def configuration() -> dict[str, JsonValue]:
        """Return a sanitized live configuration overview."""
        return service.configuration_resource()

    @router.get("/mesh", response_model=MeshResponse, operation_id="getMesh")
    def mesh(refresh: Annotated[bool, Query()] = False) -> dict[str, JsonValue]:
        """Return the controller and mesh-node inventory."""
        return service.device_inventory(refresh=refresh)

    @router.get("/clients", response_model=ClientsResponse, operation_id="getClients")
    def clients(
        view: Annotated[
            Literal["all", "active", "inactive", "blocked"],
            Query(),
        ] = "all",
    ) -> dict[str, JsonValue]:
        """Return one normalized client-device view."""
        return service.client_devices_resource(view)

    @router.get("/traffic", response_model=TrafficResponse, operation_id="getTraffic")
    def traffic() -> dict[str, JsonValue]:
        """Return normalized device and aggregate traffic rates."""
        return service.traffic_resource()

    @router.get(
        "/address-reservations",
        response_model=CapabilityResponse,
        operation_id="getAddressReservations",
    )
    def address_reservations() -> dict[str, JsonValue]:
        """Return the live address-reservation table."""
        return service.address_reservations_resource()

    @router.get("/log-types", response_model=LogTypesResponse, operation_id="getLogTypes")
    def log_types() -> dict[str, JsonValue]:
        """Return available log categories without reading log contents."""
        return service.logs_resource()

    @router.get(
        "/logs/{index}",
        response_model=SystemLogPageResponse,
        operation_id="getSystemLogPage",
    )
    def system_log_page(
        index: int,
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
    ) -> dict[str, JsonValue]:
        """Return one gated page of secret system-log content."""
        return service.system_log_page_resource(index, limit)

    @router.get(
        "/capabilities",
        response_model=CapabilitiesResponse,
        operation_id="getCapabilities",
    )
    def capabilities() -> dict[str, JsonValue]:
        """Return semantic read capabilities for the connected controller."""
        return service.capabilities()

    @router.get(
        "/capabilities/{name}",
        response_model=CapabilityResponse,
        operation_id="getCapability",
    )
    def capability(name: str) -> dict[str, JsonValue]:
        """Read one semantic capability with protocol-routing provenance."""
        try:
            get_capability_route(name)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Unknown semantic capability") from exc
        return service.read_capability(name)

    @router.get("/wlan", response_model=WlanResponse, operation_id="getWlan")
    def wlan(
        include_passwords: Annotated[bool, Query()] = False,
    ) -> dict[str, JsonValue]:
        """Return gated WLAN state with passwords omitted by default."""
        return service.wlan_state(include_passwords=include_passwords)

    @router.get("/cloud", response_model=CloudResponse, operation_id="getCloud")
    def cloud() -> dict[str, JsonValue]:
        """Return opted-in DDNS and cloud-manager state."""
        return service.cloud_state()

    @router.get("/mutations", response_model=MutationsResponse, operation_id="getMutations")
    def mutations() -> dict[str, JsonValue]:
        """Return semantic mutation candidates and eligibility."""
        return service.semantic_mutations()

    @router.get(
        "/mutations/{name}",
        response_model=MutationResponse,
        operation_id="getMutation",
    )
    def mutation(name: str) -> dict[str, JsonValue]:
        """Return one semantic mutation candidate by stable name."""
        try:
            return service.semantic_mutation(name)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="Unknown semantic mutation") from exc

    @router.post(
        "/mutation-preflights",
        response_model=MutationPreflightResponse,
        operation_id="preflightMutation",
    )
    def preflight_mutation(request: MutationRequest) -> dict[str, JsonValue]:
        """Assess a semantic mutation without registering a plan."""
        return service.preflight_semantic_mutation(
            request.name,
            request.changes,
            mode=request.mode,
        )

    @router.post(
        "/mutation-plans",
        response_model=MutationPlanCreatedResponse,
        status_code=status.HTTP_201_CREATED,
        operation_id="createMutationPlan",
        responses={
            status.HTTP_201_CREATED: {
                "description": "Mutation plan created",
                "headers": {
                    "Location": {
                        "description": "Path of the new mutation-plan status resource",
                        "schema": {"type": "string"},
                    }
                },
            }
        },
    )
    def create_mutation_plan(
        request: MutationRequest,
        response: Response,
    ) -> dict[str, JsonValue]:
        """Create a short-lived plan only when semantic execution is eligible."""
        result = service.plan_semantic_mutation(
            request.name,
            request.changes,
            mode=request.mode,
        )
        plan_id = result.get("plan_id")
        if not isinstance(plan_id, str):
            raise MutationIneligibleError(_string_tuple(result.get("blockers")))
        response.headers["Location"] = f"{config.rest_prefix}/mutation-plans/{plan_id}"
        return result

    @router.get(
        "/mutation-plans/{plan_id}",
        response_model=MutationPlanStatusResponse,
        operation_id="getMutationPlan",
    )
    def mutation_plan(plan_id: str) -> dict[str, JsonValue]:
        """Return the current state of one pending mutation plan."""
        return service.semantic_mutation_plan(plan_id)

    @router.post(
        "/mutation-plans/{plan_id}/executions",
        response_model=MutationExecutionResponse,
        response_model_exclude_unset=True,
        operation_id="executeMutationPlan",
    )
    def execute_mutation_plan(
        plan_id: str,
        request: MutationExecutionRequest,
        idempotency_key: Annotated[
            str,
            Header(alias="Idempotency-Key", min_length=8, max_length=200),
        ],
    ) -> dict[str, JsonValue]:
        """Consume one plan synchronously with process-local idempotent replay."""
        fingerprint = hashlib.sha256(f"{plan_id}\0{request.confirmation}".encode()).hexdigest()
        result, replayed = idempotency_store.execute(
            idempotency_key,
            fingerprint,
            lambda: service.execute_semantic_mutation(plan_id, request.confirmation),
        )
        result["idempotency_replayed"] = replayed
        return result

    return router


async def _require_bearer(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(_bearer_scheme),
    ] = None,
) -> None:
    authenticator = cast("StaticBearerAuthenticator", request.app.state.bearer_authenticator)
    if credentials is None or not authenticator.accepts(credentials.credentials):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer authentication is required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _register_exception_handlers(application: FastAPI) -> None:
    application.add_exception_handler(StarletteHttpException, _http_exception_handler)
    application.add_exception_handler(RequestValidationError, _validation_exception_handler)
    for exception_type in _root_error_types():
        application.add_exception_handler(exception_type, _exception_handler)


async def _exception_handler(request: Request, error: Exception) -> JSONResponse:
    status_code, code, title = _error_status(error)
    blockers = error.blockers if isinstance(error, MutationIneligibleError) else None
    headers = {"Retry-After": "1"} if isinstance(error, IdempotencyInProgressError) else None
    return _problem_response(
        request,
        status_code=status_code,
        code=code,
        title=title,
        detail=str(error),
        blockers=blockers,
        headers=headers,
    )


async def _http_exception_handler(
    request: Request,
    error: Exception,
) -> JSONResponse:
    if not isinstance(error, StarletteHttpException):
        raise TypeError("Failed to handle HTTP exception: unexpected exception type")
    titles = {
        401: ("authentication_failed", "Authentication failed"),
        403: ("request_forbidden", "Request forbidden"),
        404: ("resource_not_found", "Resource not found"),
    }
    code, title = titles.get(error.status_code, ("http_error", "HTTP request failed"))
    detail = error.detail if isinstance(error.detail, str) else title
    return _problem_response(
        request,
        status_code=error.status_code,
        code=code,
        title=title,
        detail=detail,
        headers=error.headers,
    )


async def _validation_exception_handler(
    request: Request,
    error: Exception,
) -> JSONResponse:
    if not isinstance(error, RequestValidationError):
        raise TypeError("Failed to handle validation exception: unexpected exception type")
    return _problem_response(
        request,
        status_code=422,
        code="invalid_request",
        title="Request validation failed",
        detail="The request did not match the documented API contract.",
    )


def _problem_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    title: str,
    detail: str,
    blockers: tuple[str, ...] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    problem = ProblemDetail(
        type=f"https://tplink-deco-api.invalid/problems/{code}",
        title=title,
        status=status_code,
        detail=detail,
        instance=request.url.path,
        code=code,
        request_id=getattr(request.state, "request_id", ""),
        blockers=list(blockers) if blockers is not None else None,
    )
    return JSONResponse(
        status_code=status_code,
        content=problem.to_dict(),
        media_type="application/problem+json",
        headers=headers,
    )


def _error_status(error: Exception) -> tuple[int, str, str]:
    for error_type, response in _ERROR_RESPONSES.items():
        if isinstance(error, error_type):
            return response
    return 500, "internal_error", "Internal server error"


def _root_error_types() -> tuple[type[Exception], ...]:
    return tuple(
        error_type
        for error_type in _ERROR_RESPONSES
        if not any(
            error_type is not candidate and issubclass(error_type, candidate)
            for candidate in _ERROR_RESPONSES
        )
    )


def _string_tuple(value: JsonValue | None) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(item for item in value if isinstance(item, str))
