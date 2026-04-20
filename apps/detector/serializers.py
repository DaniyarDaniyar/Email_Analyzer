# Rest Framework modules
from rest_framework import serializers

# Project modules
from apps.detector.models import DetectorResult


class ScanRequestSerializer(serializers.Serializer):
    """Serializer for scan request (text, URL, or file upload)."""

    INPUT_CHOICES = (("text", "Email/text"), ("url", "URL"), ("file", "PDF/TXT/EML file"))
    
    input_type = serializers.ChoiceField(choices=INPUT_CHOICES)
    input_data = serializers.CharField(max_length=5000, min_length=1, required=False, allow_blank=True)
    file = serializers.FileField(required=False)

    def validate(self, data):
        """Validate that input_type matches the provided data."""
        input_type = data.get("input_type")
        input_data = data.get("input_data", "").strip()
        file_obj = data.get("file")

        if input_type == "file":
            if not file_obj:
                raise serializers.ValidationError("File is required when input_type is 'file'")
            # Validate file extension
            allowed_extensions = (".pdf", ".txt", ".eml")
            if not any(str(file_obj.name).lower().endswith(ext) for ext in allowed_extensions):
                raise serializers.ValidationError("Only PDF, TXT and EML files are allowed")
            if file_obj.size > 10 * 1024 * 1024:  # 10MB limit
                raise serializers.ValidationError("File size must not exceed 10MB")
        else:
            if not input_data:
                raise serializers.ValidationError("input_data is required when input_type is 'text' or 'url'")
        
        return data

    def validate_input_data(self, value):
        """Trim whitespace."""
        return value.strip() if value else value


class DetectorResultSerializer(serializers.ModelSerializer):
    """Full serializer for DetectorResult with all fields."""

    class Meta:
        model = DetectorResult
        fields = (
            "id",
            "user",
            "input_type",
            "input_data",
            "score",
            "explanation",
            "is_safe",
            "report_file",
            "status",
            "started_at",
            "finished_at",
            "error_message",
            "score_details",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "user",
            "created_at",
            "updated_at",
            "status",
            "started_at",
            "finished_at",
            "error_message",
            "score_details",
        )


class DetectorResultListSerializer(serializers.ModelSerializer):
    """List serializer for DetectorResult (lighter version)."""

    class Meta:
        model = DetectorResult
        fields = (
            "id",
            "input_type",
            "score",
            "is_safe",
            "status",
            "created_at",
        )
        read_only_fields = fields


class HTTP405MethodNotAllowedSerializer(serializers.Serializer):
    """Serializer for 405 Method Not Allowed response."""

    detail = serializers.CharField(read_only=True, default="Method Not Allowed")    

    class Meta:
        """Serializer for 405 Method Not Allowed response."""
        fields = ("detail",)