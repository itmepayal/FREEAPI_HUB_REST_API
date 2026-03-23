from drf_spectacular.utils import OpenApiExample, OpenApiResponse, extend_schema

# =============================================================
# Health Swagger
# =============================================================

# ----------------------------
# Request Example
# ----------------------------
health_check_example = OpenApiExample(
    name="Health Check Response",
    summary="Example response for the health check endpoint",
    value={
        "status": "ok",
        "message": "API is running"
    },
    response_only=True,
)

# ----------------------------
# Response Example
# ----------------------------
health_check_schema = extend_schema(
    request=None,
    responses={
        200: OpenApiResponse(
            response=dict,
            description="API is healthy and running properly",
            examples=[health_check_example],
        )
    },
    description="Simple endpoint to verify if the API server is healthy and running.",
)
