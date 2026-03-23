from drf_spectacular.utils import (
    OpenApiExample,
    extend_schema,
    OpenApiResponse,
)
from todo.serializers import TodoCreateSerializer, TodoSerializer

# =============================================================
# Todo Create Swagger
# =============================================================
# ----------------------------
# Request Example
# ----------------------------
todo_create_request_example = OpenApiExample(
    name="Todo Create Request",
    summary="Example payload for creating a new Todo",
    value={
        "title": "Learn DRF",
        "description": "Build a Todo API",
        "completed": False,
        "due_date": None,
        "priority": "Medium"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
todo_create_success_example = OpenApiExample(
    name="Todo Create Success Response",
    summary="Example response after successfully creating a Todo",
    value={
        "success": True,
        "message": "Todo created successfully",
        "data": {
            "id": "2fe31e3f-2ca0-4395-a8ef-6b670b0ac923",
            "title": "Learn DRF",
            "description": "Build a Todo API",
            "completed": False,
            "due_date": None,
            "priority": "Medium",
            "status": "Pending",
            "created_at": "2025-11-08T09:51:49.140962Z",
            "updated_at": "2025-11-08T09:51:49.141010Z"
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Create Todo API
# ----------------------------
todo_create_schema = extend_schema(
    request=TodoCreateSerializer,
    examples=[todo_create_request_example],
    responses={
        201: OpenApiResponse(
            response=TodoSerializer,
            description="Todo created successfully",
            examples=[todo_create_success_example]
        )
    },
    description=(
        "Create a new Todo item. The authenticated user becomes the owner. "
        "Returns a standardized response containing the created Todo details."
    )
)

# =============================================================
# Todo List Swagger
# =============================================================

# ----------------------------
# Response Example
# ----------------------------
todo_list_success_example = OpenApiExample(
    name="Todo List Success Response",
    summary="Example response when retrieving a list of Todos",
    value={
        "count": 1,
        "next": None,
        "previous": None,
        "results": [
            {
                "id": "2fe31e3f-2ca0-4395-a8ef-6b670b0ac923",
                "title": "Learn DRF",
                "description": "Build a Todo API",
                "completed": False,
                "due_date": None,
                "priority": "Medium",
                "status": "Pending",
                "created_at": "2025-11-08T09:51:49.140962Z",
                "updated_at": "2025-11-08T09:51:49.141010Z"
            }
        ]
    },
    response_only=True
)

# ----------------------------
# Extend Schema for List Todos API
# ----------------------------
todo_list_schema = extend_schema(
    request=None,
    responses={
        200: OpenApiResponse(
            response=TodoSerializer(many=True),
            description="List of all Todos",
            examples=[todo_list_success_example],
        )
    },
    description=(
        "Retrieve a paginated list of all Todo items. "
        "Supports filters, ordering, and pagination as per Django REST framework settings."
    ),
)   

# =============================================================
# Todo Retrieve Swagger
# =============================================================

todo_retrieve_example = OpenApiExample(
    name="Todo Retrieve Example",
    summary="Example response when retrieving a single Todo",
    value={
        "success": True,
        "message": "Todo retrieved successfully",
        "data": {
            "id": "2fe31e3f-2ca0-4395-a8ef-6b670b0ac923",
            "title": "Learn DRF",
            "description": "Build a Todo API",
            "completed": False,
            "due_date": None,
            "priority": "Medium",
            "status": "Pending",
            "created_at": "2025-11-08T09:51:49.140962Z",
            "updated_at": "2025-11-08T09:51:49.141010Z"
        },
    },
    response_only=True
)

todo_retrieve_schema = extend_schema(
    request=None,
    responses={
        200: OpenApiResponse(
            response=TodoSerializer,
            description="Retrieve a single Todo successfully.",
            examples=[todo_retrieve_example],
        )
    },
    description="Retrieve details of a single Todo item by its ID.",
)

# =============================================================
# Todo Update Swagger
# =============================================================

# ----------------------------
# Request Example
# ----------------------------
todo_update_request_example = OpenApiExample(
    name="Todo Update Request",
    summary="Example payload for updating an existing Todo",
    value={
        "title": "Working Django project",
        "description": "Build API for Todo app",
        "priority": "High",
        "due_date": "2025-09-20T10:00:00Z"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
todo_update_success_example = OpenApiExample(
    name="Todo Update Success Response",
    summary="Example response after successfully updating a Todo",
    value={
        "success": True,
        "message": "Todo updated successfully",
        "data": {
            "id": "2fe31e3f-2ca0-4395-a8ef-6b670b0ac923",
            "title": "Working Django project",
            "description": "Build API for Todo app",
            "completed": False,
            "due_date": "2025-09-20T10:00:00Z",
            "priority": "High",
            "status": "Pending",
            "created_at": "2025-11-08T09:51:49.140962Z",
            "updated_at": "2025-11-08T10:07:56.097491Z"
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Update Todo API
# ----------------------------
todo_update_schema = extend_schema(
    request=TodoCreateSerializer, 
    examples=[todo_update_request_example],
    responses={
        200: OpenApiResponse(
            response=TodoSerializer,
            description="Todo updated successfully.",
            examples=[todo_update_success_example],
        )
    },
    description=(
        "Update an existing Todo item by its ID. "
        "Supports partial updates. Returns the updated Todo details."
    ),
)

# =============================================================
# Todo Toggle Status Swagger
# =============================================================

# ----------------------------
# Response Example
# ----------------------------
todo_toggle_status_success_example = OpenApiExample(
    name="Todo Toggle Status Success Response",
    summary="Example response after toggling the completed status of a Todo",
    value={
        "success": True,
        "message": "Todo status toggled successfully",
        "data": {
            "id": "2fe31e3f-2ca0-4395-a8ef-6b670b0ac923",
            "completed": True
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Toggle Status API
# ----------------------------
todo_toggle_status_schema = extend_schema(
    request=None,  
    responses={
        200: OpenApiResponse(
            response=dict,
            description="Todo status toggled successfully.",
            examples=[todo_toggle_status_success_example],
        )
    },
    description=(
        "Toggle the completion status (`completed`) of a Todo item by its ID. "
        "If it's marked as incomplete, it will be set to complete, and vice versa."
    ),
)

# =============================================================
# Todo Delete Swagger
# =============================================================

# ----------------------------
# Response Example
# ----------------------------
todo_delete_success_example = OpenApiExample(
    name="Todo Delete Success Response",
    summary="Example response after successfully deleting a Todo",
    value={
        "success": True,
        "message": "Todo deleted successfully",
        "data": {
            "id": "2fe31e3f-2ca0-4395-a8ef-6b670b0ac923",
            "message": "Todo deleted successfully"
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Delete Todo API
# ----------------------------
todo_delete_schema = extend_schema(
    request=None, 
    responses={
        200: OpenApiResponse(
            response=dict,
            description="Todo deleted successfully.",
            examples=[todo_delete_success_example],
        )
    },
    description=(
        "Delete a Todo item by its ID. "
        "Returns the ID of the deleted Todo and a success message."
    ),
)

# =============================================================
# Todo Restore Swagger
# =============================================================

# ----------------------------
# Response Example
# ----------------------------
todo_restore_success_example = OpenApiExample(
    name="Todo Restore Success Response",
    summary="Example response after successfully restoring a deleted Todo",
    value={
        "success": True,
        "message": "Todo restored successfully",
        "data": {
            "id": "2fe31e3f-2ca0-4395-a8ef-6b670b0ac923",
            "message": "Todo restored successfully"
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Restore Todo API
# ----------------------------
todo_restore_schema = extend_schema(
    request=None,  
    responses={
        200: OpenApiResponse(
            response=dict,
            description="Todo restored successfully.",
            examples=[todo_restore_success_example],
        )
    },
    description=(
        "Restore a previously deleted Todo item by its ID. "
        "Returns the ID of the restored Todo and a success message."
    ),
)