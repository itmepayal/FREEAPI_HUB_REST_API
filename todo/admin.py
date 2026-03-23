from django.contrib import admin
from todo.models import Todo

# ----------------------
# Todo Admin
# ----------------------
@admin.register(Todo)
class TodoAdmin(admin.ModelAdmin):
    list_display = ("title", "priority", "completed", "due_date", "expire_at", "created_at")
    list_filter = ("priority", "completed", "due_date")
    search_fields = ("title", "description")
    readonly_fields = ("expire_at", "created_at", "updated_at", "deleted_at")
    ordering = ("-created_at",)
    date_hierarchy = "due_date"
    
    def has_delete_permission(self, request, obj=None):
        return False
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.filter(deleted_at__isnull=True)
