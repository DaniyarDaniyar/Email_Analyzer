# Django modules
from django.contrib import admin
from django.utils.html import format_html

# Project modules
from .models import DetectorResult


@admin.register(DetectorResult)
class DetectorResultAdmin(admin.ModelAdmin):
    """Admin interface for DetectorResult model."""
    list_display = (
        'id', 'user', 'input_type', 'input_preview', 'score', 'is_safe', 'created_at'
    )
    list_filter = ('is_safe', 'input_type', 'created_at')
    search_fields = ('user__username', 'user__email')
    ordering = ('-created_at',)

    def input_preview(self, obj):
        text = obj.input_data or ''
        preview = text if len(text) <= 120 else text[:120] + '...'
        full_id = f"det-input-{obj.id}"
        return format_html(
            '<div>{} <a href="#" onclick="var e=document.getElementById(\'{}\'); '
            'e.style.display = e.style.display === \'none\' ? \'block\' : \'none\'; return false;">[показать]</a>'
            '<div id="{}" style="display:none; white-space:pre-wrap; margin-top:6px;">{}</div></div>',
            preview, full_id, full_id, text,
        )

    input_preview.short_description = 'Input (preview)'
